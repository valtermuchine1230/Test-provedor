"""
SMTP Diagnostic Engine — v2

Para cada domínio: resolve MX, detecta o próprio IP de saída (e seu PTR/
FCrDNS), conecta ao MX, percorre o handshake completo (banner -> EHLO ->
STARTTLS -> EHLO -> MAIL FROM -> RCPT TO), guarda o transcript inteiro e
classifica cada resposta por evidência textual, não só pelo código SMTP.

Nunca envia DATA. Nunca usa caixas de terceiros. Serve só para descobrir
COMO cada provedor reage à combinação (nosso domínio, nosso IP/PTR, nosso
envelope) — não para entregar nada.
"""
import csv
import json
import os
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import dns.resolver
import dns.reversename
import requests

from providers import PROVIDERS, PRIORITY

MAIL_FROM = os.environ.get("MAIL_FROM", "ptrtest@veriscop.dedyn.io")
RCPT_PROBE = "ptr-probe-test@{domain}"
EHLO_NAME = os.environ.get("EHLO_NAME", "veriscop.dedyn.io")
TEST_LANE = os.environ.get("TEST_LANE", "unknown")  # ex: direct / route64 / tunnelbroker
TIMEOUT = 12
MAX_WORKERS = 20
SMTP_PORT = 25

# ---------------------------------------------------------------------------
# Classificador de evidências: cada entrada é (regex, classificação,
# confiança 0-1). A ordem importa — a primeira que bater vence.
# ---------------------------------------------------------------------------
EVIDENCE_RULES = [
    (r"reverse\s*dns|rdns|ptr record|cannot find your hostname|"
     r"does not resolve|no ptr|fcrdns|forward.?confirmed",
     "PTR_OR_HOSTNAME_POLICY", 0.9),

    (r"dynamic|residential|dial.?up|dsl|broadband|"
     r"generic (rdns|hostname)|dynamic pool",
     "DYNAMIC_IP_POLICY", 0.75),

    (r"spamhaus|barracuda|sorbs|rbl|blacklist|black.?list|"
     r"listed (in|at)|reputation|denied access|not allowed to connect|"
     r"has been blocked|banned",
     "IP_REPUTATION_OR_BLACKLIST", 0.85),

    (r"tunnel|proxy|vpn|hosting (provider|network)|datacenter|data center|"
     r"cloud provider not accepted",
     "TUNNEL_OR_HOSTING_POLICY", 0.7),

    (r"spf|not authorized to send|domain does not exist|"
     r"sender (address |domain )?(rejected|not accepted)|"
     r"envelope.{0,15}rejected",
     "SENDER_OR_SPF_POLICY", 0.65),

    (r"rate limit|too many (connections|messages)|throttl|slow down",
     "RATE_LIMIT", 0.8),

    (r"greylist|try again later|temporarily deferred|please try later",
     "GREYLIST_OR_TEMPORARY", 0.8),

    (r"relay (access )?denied|relaying denied|not (a |our )?local",
     "RELAY_DENIED", 0.6),

    (r"user unknown|no such user|mailbox (not found|unavailable)|"
     r"recipient (address )?rejected|does not exist",
     "RECIPIENT_UNKNOWN_EXPECTED", 0.5),  # esperado, já que o RCPT é fictício
]


def classify_text(text):
    """Procura evidência textual na resposta SMTP. Retorna (classe, confiança, trecho)."""
    lowered = text.lower()
    for pattern, label, confidence in EVIDENCE_RULES:
        m = re.search(pattern, lowered)
        if m:
            snippet = text.strip().splitlines()[-1][:200]
            return label, confidence, snippet
    return None, 0.0, None


# ---------------------------------------------------------------------------
# Descoberta do IP de saída + PTR + FCrDNS (feito uma vez por execução,
# não por domínio — é o mesmo IP de saída para todos os testes desta run)
# ---------------------------------------------------------------------------
def discover_source_ip(family):
    """Descobre o IP público de saída via serviço externo (ipify)."""
    url = "https://api64.ipify.org?format=json" if family == socket.AF_INET6 \
        else "https://api.ipify.org?format=json"
    try:
        r = requests.get(url, timeout=8)
        r.raise_for_status()
        return r.json().get("ip")
    except Exception as e:
        print(f"[AVISO] Não consegui detectar IP de saída ({family}): {e}", file=sys.stderr)
        return None


def ptr_lookup(ip):
    if not ip:
        return None
    try:
        rev = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev, "PTR", lifetime=8)
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


def fcrdns_check(ip, ptr_hostname):
    """Confirma se o PTR resolve de volta para o mesmo IP (forward-confirmed rDNS)."""
    if not ip or not ptr_hostname:
        return False
    rtype = "AAAA" if ":" in ip else "A"
    try:
        answers = dns.resolver.resolve(ptr_hostname, rtype, lifetime=8)
        return any(str(a) == ip for a in answers)
    except Exception:
        return False


def asn_org_lookup(ip):
    """Best-effort: dono/ASN do IP. Não bloqueia o teste se falhar/limitar."""
    if not ip:
        return None
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=6)
        if r.status_code == 200:
            data = r.json()
            return {"asn": data.get("asn"), "org": data.get("org"),
                    "country": data.get("country_name")}
    except Exception:
        pass
    return None


def gather_source_info():
    info = {"test_lane": TEST_LANE}
    for family, key in ((socket.AF_INET, "ipv4"), (socket.AF_INET6, "ipv6")):
        ip = discover_source_ip(family)
        ptr = ptr_lookup(ip)
        fcrdns = fcrdns_check(ip, ptr)
        info[key] = {
            "ip": ip,
            "ptr": ptr,
            "fcrdns": fcrdns,
            "asn_org": asn_org_lookup(ip),
        }
    return info


# ---------------------------------------------------------------------------
# Handshake SMTP fase a fase, com transcript completo
# ---------------------------------------------------------------------------
def read_response(sock, transcript):
    data = b""
    sock.settimeout(TIMEOUT)
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        lines = data.split(b"\r\n")
        last = lines[-2] if lines[-1] == b"" else lines[-1]
        if len(last) >= 4 and last[3:4] == b" ":
            break
    text = data.decode(errors="replace")
    for line in text.strip().splitlines():
        transcript.append({"dir": "recv", "line": line})
    code = int(text[:3]) if text[:3].isdigit() else 0
    return code, text


def send_line(sock, transcript, line):
    transcript.append({"dir": "send", "line": line})
    sock.sendall((line + "\r\n").encode())


def new_phase(name):
    return {"phase": name, "status": "SKIPPED", "code": None,
            "text": None, "classification": None, "confidence": 0.0,
            "evidence": None}


def probe_domain(domain, source_info):
    result = {
        "domain": domain,
        "priority": domain in PRIORITY,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "test_lane": TEST_LANE,
        "source_ip_used": None,
        "mx": None,
        "phases": {
            "connect": new_phase("connect"),
            "banner": new_phase("banner"),
            "ehlo": new_phase("ehlo"),
            "starttls": new_phase("starttls"),
            "ehlo_tls": new_phase("ehlo_tls"),
            "mail_from": new_phase("mail_from"),
            "rcpt_to": new_phase("rcpt_to"),
        },
        "final_classification": "UNKNOWN",
        "final_confidence": 0.0,
        "notes": [],
        "transcript": [],
    }
    phases = result["phases"]
    transcript = result["transcript"]

    # --- resolução MX ---
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8)
        mx_hosts = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
        if not mx_hosts:
            raise Exception("sem registros MX")
        result["mx"] = mx_hosts[0][1]
    except Exception as e:
        result["final_classification"] = "NO_MX"
        result["notes"].append(str(e))
        return result

    mx_host = result["mx"]

    # --- resolução do IP do MX (prefere IPv6, cai para IPv4) ---
    family_used = None
    try:
        addr_info = socket.getaddrinfo(mx_host, SMTP_PORT, socket.AF_INET6)
        family_used = "ipv6"
    except Exception:
        try:
            addr_info = socket.getaddrinfo(mx_host, SMTP_PORT, socket.AF_INET)
            family_used = "ipv4"
        except Exception as e:
            result["final_classification"] = "MX_UNRESOLVABLE"
            result["notes"].append(str(e))
            return result

    result["source_ip_used"] = source_info.get(family_used, {}).get("ip")

    # --- CONNECT ---
    try:
        sock = socket.socket(addr_info[0][0], socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect(addr_info[0][4])
        phases["connect"]["status"] = "OK"
    except socket.timeout:
        phases["connect"].update(status="TIMEOUT")
        result["final_classification"] = "CONNECTIVITY_TIMEOUT"
        return result
    except ConnectionRefusedError:
        phases["connect"].update(status="REFUSED")
        result["final_classification"] = "CONNECTIVITY_REFUSED"
        return result
    except Exception as e:
        phases["connect"].update(status="ERROR")
        result["notes"].append(str(e))
        result["final_classification"] = "CONNECTIVITY_ERROR"
        return result

    try:
        # --- BANNER ---
        code, text = read_response(sock, transcript)
        cls, conf, ev = classify_text(text)
        phases["banner"].update(status="OK" if code < 400 else "REJECTED",
                                 code=code, text=text.strip(),
                                 classification=cls, confidence=conf, evidence=ev)
        if code >= 400:
            sock.close()
            return finalize(result)

        # --- EHLO ---
        send_line(sock, transcript, f"EHLO {EHLO_NAME}")
        code, text = read_response(sock, transcript)
        cls, conf, ev = classify_text(text)
        phases["ehlo"].update(status="OK" if code < 400 else "REJECTED",
                               code=code, text=text.strip(),
                               classification=cls, confidence=conf, evidence=ev)
        if code >= 400:
            sock.close()
            return finalize(result)

        # --- STARTTLS (se oferecido) ---
        if "STARTTLS" in text.upper():
            send_line(sock, transcript, "STARTTLS")
            code, text = read_response(sock, transcript)
            phases["starttls"].update(status="OK" if code < 400 else "REJECTED",
                                       code=code, text=text.strip())
            if code < 400:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=mx_host)
                send_line(sock, transcript, f"EHLO {EHLO_NAME}")
                code, text = read_response(sock, transcript)
                cls, conf, ev = classify_text(text)
                phases["ehlo_tls"].update(status="OK" if code < 400 else "REJECTED",
                                           code=code, text=text.strip(),
                                           classification=cls, confidence=conf, evidence=ev)
        else:
            phases["starttls"]["status"] = "NOT_OFFERED"

        # --- MAIL FROM ---
        send_line(sock, transcript, f"MAIL FROM:<{MAIL_FROM}>")
        code, text = read_response(sock, transcript)
        cls, conf, ev = classify_text(text)
        phases["mail_from"].update(status="OK" if code < 400 else
                                    ("TEMP" if code < 500 else "REJECTED"),
                                    code=code, text=text.strip(),
                                    classification=cls, confidence=conf, evidence=ev)
        if code >= 400:
            send_line(sock, transcript, "QUIT")
            sock.close()
            return finalize(result)

        # --- RCPT TO ---
        rcpt = RCPT_PROBE.format(domain=domain)
        send_line(sock, transcript, f"RCPT TO:<{rcpt}>")
        code, text = read_response(sock, transcript)
        cls, conf, ev = classify_text(text)
        phases["rcpt_to"].update(status="OK" if code < 400 else
                                  ("TEMP" if code < 500 else "REJECTED"),
                                  code=code, text=text.strip(),
                                  classification=cls, confidence=conf, evidence=ev)

        send_line(sock, transcript, "QUIT")
        try:
            read_response(sock, transcript)
        except Exception:
            pass
        sock.close()

    except socket.timeout:
        result["notes"].append("timeout no meio do handshake")
    except Exception as e:
        result["notes"].append(f"erro no handshake: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return finalize(result)


def finalize(result):
    """Decide a classificação final olhando a fase mais avançada com evidência,
    dando prioridade a fases posteriores (mais informativas) e a evidência
    textual sobre o código puro."""
    phases = result["phases"]
    order = ["rcpt_to", "mail_from", "ehlo_tls", "starttls", "ehlo", "banner"]

    for phase_name in order:
        p = phases[phase_name]
        if p["status"] in ("REJECTED", "TEMP") and p.get("classification"):
            result["final_classification"] = p["classification"]
            result["final_confidence"] = p["confidence"]
            return result

    # sem evidência textual — cai para o resultado bruto do RCPT
    rcpt = phases["rcpt_to"]
    if rcpt["status"] == "OK":
        result["final_classification"] = "ACCEPTED_TO_RCPT_STAGE"
        result["final_confidence"] = 0.3  # RCPT é fictício, então "aceito" != confirmado
    elif rcpt["status"] == "TEMP":
        result["final_classification"] = "TEMPORARY_NO_EVIDENCE"
        result["final_confidence"] = 0.4
    elif rcpt["status"] == "REJECTED":
        result["final_classification"] = "REJECTED_NO_EVIDENCE"
        result["final_confidence"] = 0.3
    elif phases["mail_from"]["status"] == "REJECTED":
        result["final_classification"] = "REJECTED_AT_MAILFROM_NO_EVIDENCE"
        result["final_confidence"] = 0.3
    else:
        result["final_classification"] = "INCONCLUSIVE"
        result["final_confidence"] = 0.0

    return result


def main():
    print(f"[INFO] Descobrindo IP/PTR/FCrDNS de saída (lane={TEST_LANE})...")
    source_info = gather_source_info()
    print(json.dumps(source_info, indent=2, ensure_ascii=False))

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(probe_domain, d, source_info): d for d in PROVIDERS}
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            results.append(r)
            print(f"[{i}/{len(PROVIDERS)}] {r['domain']:30s} -> "
                  f"{r['final_classification']} ({r['final_confidence']:.2f})")

    results.sort(key=lambda r: (not r["priority"], r["domain"]))

    report = {
        "meta": {
            "run": datetime.now(timezone.utc).isoformat(),
            "test_lane": TEST_LANE,
            "total_tested": len(results),
            "source_info": source_info,
        },
        "results": results,
    }

    with open("report.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open("report.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "priority", "mx", "test_lane", "source_ip_used",
                    "final_classification", "final_confidence",
                    "banner_code", "ehlo_code", "starttls_status",
                    "mail_from_code", "rcpt_code", "rcpt_evidence"])
        for r in results:
            p = r["phases"]
            w.writerow([
                r["domain"], r["priority"], r["mx"], r["test_lane"], r["source_ip_used"],
                r["final_classification"], f"{r['final_confidence']:.2f}",
                p["banner"]["code"], p["ehlo"]["code"], p["starttls"]["status"],
                p["mail_from"]["code"], p["rcpt_to"]["code"], p["rcpt_to"]["evidence"],
            ])

    with open("report.md", "w") as f:
        f.write("# SMTP Diagnostic Engine — Relatório\n\n")
        f.write(f"Run: {report['meta']['run']}  \n")
        f.write(f"Lane: **{TEST_LANE}**  \n")
        f.write(f"Total testado: {len(results)}\n\n")

        f.write("## IP de saída usado nesta execução\n\n")
        for fam in ("ipv4", "ipv6"):
            si = source_info.get(fam, {})
            f.write(f"- **{fam}**: `{si.get('ip')}` — PTR: `{si.get('ptr')}` — "
                    f"FCrDNS: {'PASS' if si.get('fcrdns') else 'FAIL'}\n")
        f.write("\n")

        summary = {}
        for r in results:
            summary[r["final_classification"]] = summary.get(r["final_classification"], 0) + 1
        f.write("## Resumo por classificação (com evidência)\n\n")
        for k, v in sorted(summary.items(), key=lambda x: -x[1]):
            f.write(f"- **{k}**: {v}\n")

        f.write("\n## Prioritários — detalhe completo\n\n")
        for r in results:
            if not r["priority"]:
                continue
            f.write(f"### {r['domain']} (MX: {r['mx']})\n\n")
            f.write(f"Classificação final: **{r['final_classification']}** "
                    f"(confiança {r['final_confidence']:.2f})\n\n")
            for name, p in r["phases"].items():
                if p["status"] == "SKIPPED":
                    continue
                f.write(f"- `{name}`: {p['status']} — code={p['code']} "
                        f"— evidência: {p.get('evidence') or '-'}\n")
            f.write("\n")

    print("\nRelatório salvo em report.json / report.csv / report.md")


if __name__ == "__main__":
    main()
