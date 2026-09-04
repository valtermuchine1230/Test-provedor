"""
SMTP Diagnostic Engine — v3 (corrigido)

Corrige o bug crítico da v2: a detecção de IP de saída e a conexão ao MX
não forçavam de verdade a família IPv6, então quando o túnel Route64 não
estava roteando, o script caía silenciosamente para IPv4 e reportava isso
como se fosse IPv6 (ipv4 == ipv6 no relatório anterior). Agora:
  - a descoberta de IP usa socket+TLS manual, forçando a família pedida;
  - existe uma checagem explícita de roteabilidade IPv6 antes de tudo;
  - a conexão ao MX tenta endereços reais (não só DNS) e registra qual
    família de fato conectou.

Nunca envia DATA. Nunca usa caixas de terceiros.
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

from providers import PROVIDERS, PRIORITY

MAIL_FROM = os.environ.get("MAIL_FROM", "ptrtest@veriscop.dedyn.io")
RCPT_PROBE = "ptr-probe-test@{domain}"
EHLO_NAME = os.environ.get("EHLO_NAME", "veriscop.dedyn.io")
TEST_LANE = os.environ.get("TEST_LANE", "unknown")  # ex: direct / route64 / tunnelbroker
TIMEOUT = 12
MAX_WORKERS = 20
SMTP_PORT = 25

# Host IPv6 estável e conhecido, usado só para confirmar que existe rota
# IPv6 utilizável (ex: através do túnel Route64) antes de testar qualquer MX.
ROUTE64_CHECK_HOST = os.environ.get("ROUTE64_CHECK_HOST", "2001:4860:4860::8888")
ROUTE64_CHECK_PORT = 53  # DNS do Google — quase sempre aceita conexão TCP

# ---------------------------------------------------------------------------
# Classificador de evidências (igual à v2 — não é aqui que estava o bug)
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
     "RECIPIENT_UNKNOWN_EXPECTED", 0.5),
]


def classify_text(text):
    lowered = text.lower()
    for pattern, label, confidence in EVIDENCE_RULES:
        m = re.search(pattern, lowered)
        if m:
            snippet = text.strip().splitlines()[-1][:200]
            return label, confidence, snippet
    return None, 0.0, None


# ---------------------------------------------------------------------------
# CORREÇÃO 1: descoberta de IP de saída forçando de verdade a família
# ---------------------------------------------------------------------------
def http_get_forced_family(host, path, family, port=443, timeout=8):
    """Faz um GET HTTPS manual, forçando a família de socket (AF_INET ou
    AF_INET6) de verdade. Ao contrário de `requests`, NÃO faz fallback
    automático entre famílias — se a conexão na família pedida falhar,
    a exceção sobe (é isso que faltava na v2)."""
    infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    last_exc = None
    for fam, socktype, proto, canonname, sockaddr in infos:
        raw = None
        try:
            raw = socket.socket(fam, socktype, proto)
            raw.settimeout(timeout)
            raw.connect(sockaddr)
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(raw, server_hostname=host)
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: smtp-diagnostic-engine/3\r\n"
                f"Connection: close\r\n\r\n"
            )
            tls.sendall(request.encode())
            data = b""
            tls.settimeout(timeout)
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            tls.close()
            body = data.split(b"\r\n\r\n", 1)[-1]
            return body.decode(errors="replace")
        except Exception as e:
            last_exc = e
            if raw is not None:
                try:
                    raw.close()
                except Exception:
                    pass
            continue
    raise last_exc or Exception("nenhum endereço resolvido")


def discover_source_ip(family):
    """Descobre o IP público de saída, forçando a família pedida de verdade.
    Retorna None (não um IP da família errada) se a família não for
    roteável — esse é o fix do bug onde ipv4 e ipv6 saíam iguais."""
    fam_name = "ipv6" if family == socket.AF_INET6 else "ipv4"
    host = "api64.ipify.org" if family == socket.AF_INET6 else "api.ipify.org"
    try:
        body = http_get_forced_family(host, "/?format=json", family)
        data = json.loads(body)
        ip = data.get("ip")
        # proteção extra: se por algum motivo vier um IP da família errada,
        # trata como falha em vez de aceitar silenciosamente
        is_v6_format = ip and ":" in ip
        if family == socket.AF_INET6 and not is_v6_format:
            raise Exception(f"esperava IPv6 mas recebi '{ip}' — família não foi respeitada")
        if family == socket.AF_INET and is_v6_format:
            raise Exception(f"esperava IPv4 mas recebi '{ip}'")
        return ip
    except Exception as e:
        print(f"[AVISO] Falha ao descobrir IP {fam_name} de saída (rota indisponível?): {e}",
              file=sys.stderr)
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
    if not ip or not ptr_hostname:
        return False
    rtype = "AAAA" if ":" in ip else "A"
    try:
        answers = dns.resolver.resolve(ptr_hostname, rtype, lifetime=8)
        return any(str(a) == ip for a in answers)
    except Exception:
        return False


def asn_org_lookup(ip):
    """Best-effort via socket puro (evita depender de requests aqui também)."""
    if not ip:
        return None
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        body = http_get_forced_family("ipapi.co", f"/{ip}/json/", family, timeout=6)
        data = json.loads(body)
        return {"asn": data.get("asn"), "org": data.get("org"),
                "country": data.get("country_name")}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CORREÇÃO 2: checagem explícita de roteabilidade IPv6/Route64
# ---------------------------------------------------------------------------
def check_route64_reachability(host=ROUTE64_CHECK_HOST, port=ROUTE64_CHECK_PORT, timeout=6):
    """Confirma que existe rota IPv6 USÁVEL (ex: via túnel Route64) abrindo
    uma conexão TCP real — não apenas checando se a interface está 'up'."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception as e:
        print(f"[AVISO] IPv6 NÃO está roteável neste runner (Route64 down?): {e}",
              file=sys.stderr)
        return False


def gather_source_info():
    route64_ok = check_route64_reachability()
    info = {"test_lane": TEST_LANE, "route64_ok": route64_ok}

    for family, key in ((socket.AF_INET, "ipv4"), (socket.AF_INET6, "ipv6")):
        if key == "ipv6" and not route64_ok:
            # não tenta nem descobrir IPv6 se já sabemos que não roteia —
            # evita reintroduzir a confusão da v2
            info[key] = {"ip": None, "ptr": None, "fcrdns": False, "asn_org": None}
            continue
        ip = discover_source_ip(family)
        ptr = ptr_lookup(ip)
        fcrdns = fcrdns_check(ip, ptr)
        info[key] = {
            "ip": ip,
            "ptr": ptr,
            "fcrdns": fcrdns,
            "asn_org": asn_org_lookup(ip),
        }

    if info["ipv4"]["ip"] and info["ipv6"]["ip"] and info["ipv4"]["ip"] == info["ipv6"]["ip"]:
        # não deveria mais acontecer, mas mantém a checagem como cinto de segurança
        print("[ERRO] ipv4 e ipv6 retornaram o mesmo endereço — algo ainda está "
              "caindo para IPv4 silenciosamente. Marcando ipv6 como inválido.",
              file=sys.stderr)
        info["ipv6"] = {"ip": None, "ptr": None, "fcrdns": False, "asn_org": None}
        info["route64_ok"] = False

    return info


# ---------------------------------------------------------------------------
# Handshake SMTP (igual à v2)
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


# ---------------------------------------------------------------------------
# CORREÇÃO 3: conexão ao MX com tentativa real por endereço, não só DNS
# ---------------------------------------------------------------------------
def resolve_mx_candidates(mx_host, allow_ipv6):
    """Retorna lista de (family_name, sockaddr_info) — IPv6 primeiro (só se
    permitido), depois IPv4. Isso é só resolução DNS; a confirmação real
    de que a rota funciona acontece na hora do connect(), não aqui."""
    candidates = []
    if allow_ipv6:
        try:
            for info in socket.getaddrinfo(mx_host, SMTP_PORT, socket.AF_INET6, socket.SOCK_STREAM):
                candidates.append(("ipv6", info))
        except Exception:
            pass
    try:
        for info in socket.getaddrinfo(mx_host, SMTP_PORT, socket.AF_INET, socket.SOCK_STREAM):
            candidates.append(("ipv4", info))
    except Exception:
        pass
    return candidates


def connect_to_mx(mx_host, source_info):
    """Tenta conectar de verdade em cada endereço candidato, na ordem.
    Retorna (sock, family_used, errors) — family_used reflete a conexão
    que REALMENTE funcionou, não a que só existia no DNS."""
    candidates = resolve_mx_candidates(mx_host, allow_ipv6=source_info.get("route64_ok", False))
    errors = []
    if not candidates:
        return None, None, ["sem endereços resolvidos"]

    for fam_name, (family, socktype, proto, canonname, sockaddr) in candidates:
        try:
            s = socket.socket(family, socktype, proto)
            s.settimeout(TIMEOUT)
            s.connect(sockaddr)
            return s, fam_name, errors
        except Exception as e:
            errors.append(f"{fam_name} {sockaddr}: {e}")
            continue

    return None, None, errors


def probe_domain(domain, source_info):
    result = {
        "domain": domain,
        "priority": domain in PRIORITY,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "test_lane": TEST_LANE,
        "route64_ok": source_info.get("route64_ok", False),
        "source_ip_used": None,
        "family_used": None,
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

    # --- CONNECT (agora com tentativa real por endereço) ---
    sock, family_used, connect_errors = connect_to_mx(mx_host, source_info)
    if sock is None:
        timed_out = any("timed out" in e or "timeout" in e.lower() for e in connect_errors)
        phases["connect"].update(status="TIMEOUT" if timed_out else "REFUSED")
        result["notes"].extend(connect_errors)
        result["final_classification"] = "CONNECTIVITY_TIMEOUT" if timed_out else "CONNECTIVITY_REFUSED"
        return result

    result["family_used"] = family_used
    result["source_ip_used"] = source_info.get(family_used, {}).get("ip")
    phases["connect"]["status"] = "OK"

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
    phases = result["phases"]
    order = ["rcpt_to", "mail_from", "ehlo_tls", "starttls", "ehlo", "banner"]

    for phase_name in order:
        p = phases[phase_name]
        if p["status"] in ("REJECTED", "TEMP") and p.get("classification"):
            result["final_classification"] = p["classification"]
            result["final_confidence"] = p["confidence"]
            return result

    rcpt = phases["rcpt_to"]
    if rcpt["status"] == "OK":
        result["final_classification"] = "ACCEPTED_TO_RCPT_STAGE"
        result["final_confidence"] = 0.3
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
    print(f"[INFO] Verificando roteabilidade IPv6 (Route64) e descobrindo IP/PTR de saída (lane={TEST_LANE})...")
    source_info = gather_source_info()
    print(json.dumps(source_info, indent=2, ensure_ascii=False))

    if not source_info["route64_ok"]:
        print("\n[ALERTA] Route64/IPv6 NÃO está roteável nesta execução. "
              "Todos os testes vão rodar só por IPv4 e isso ficará marcado "
              "em cada resultado (route64_ok=False). Corrija o túnel WireGuard "
              "antes de tirar qualquer conclusão sobre comportamento por IPv6.\n",
              file=sys.stderr)

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(probe_domain, d, source_info): d for d in PROVIDERS}
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            results.append(r)
            print(f"[{i}/{len(PROVIDERS)}] {r['domain']:30s} -> "
                  f"{r['final_classification']} ({r['final_confidence']:.2f}) "
                  f"[{r.get('family_used')}]")

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
        w.writerow(["domain", "priority", "mx", "test_lane", "route64_ok", "family_used",
                    "source_ip_used", "final_classification", "final_confidence",
                    "banner_code", "ehlo_code", "starttls_status",
                    "mail_from_code", "rcpt_code", "rcpt_evidence"])
        for r in results:
            p = r["phases"]
            w.writerow([
                r["domain"], r["priority"], r["mx"], r["test_lane"], r["route64_ok"],
                r["family_used"], r["source_ip_used"],
                r["final_classification"], f"{r['final_confidence']:.2f}",
                p["banner"]["code"], p["ehlo"]["code"], p["starttls"]["status"],
                p["mail_from"]["code"], p["rcpt_to"]["code"], p["rcpt_to"]["evidence"],
            ])

    with open("report.md", "w") as f:
        f.write("# SMTP Diagnostic Engine — Relatório (v3)\n\n")
        f.write(f"Run: {report['meta']['run']}  \n")
        f.write(f"Lane: **{TEST_LANE}**  \n")
        f.write(f"Route64/IPv6 roteável nesta execução: **{'SIM' if source_info['route64_ok'] else 'NÃO'}**  \n")
        f.write(f"Total testado: {len(results)}\n\n")

        f.write("## IP de saída usado nesta execução\n\n")
        for fam in ("ipv4", "ipv6"):
            si = source_info.get(fam, {})
            f.write(f"- **{fam}**: `{si.get('ip') or 'NONE'}` — PTR: `{si.get('ptr') or 'NONE'}` — "
                    f"FCrDNS: {'PASS' if si.get('fcrdns') else 'FAIL'}\n")
        f.write("\n")

        family_counts = {}
        for r in results:
            family_counts[r.get("family_used")] = family_counts.get(r.get("family_used"), 0) + 1
        f.write("## Família de IP realmente usada por domínio\n\n")
        for k, v in sorted(family_counts.items(), key=lambda x: str(x[0])):
            f.write(f"- **{k}**: {v}\n")
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
            f.write(f"### {r['domain']} (MX: {r['mx']}, família: {r.get('family_used')})\n\n")
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
