"""
Para cada domínio: resolve MX, conecta via IPv6 (saindo pelo túnel Route64),
faz EHLO/STARTTLS/MAIL FROM/RCPT TO com um endereço de prova, registra a
transação completa e classifica o resultado.
"""
import csv
import json
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import dns.resolver

from providers import PROVIDERS, PRIORITY

MAIL_FROM = "ptrtest@veriscop.dedyn.io"
RCPT_PROBE = "ptr-probe-test@{domain}"
TIMEOUT = 12
MAX_WORKERS = 25
SMTP_PORT = 25


def log_line(sock_log, direction, text):
    sock_log.append(f"{direction} {text.strip()}")


def read_response(sock, sock_log):
    data = b""
    sock.settimeout(TIMEOUT)
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        lines = data.split(b"\r\n")
        # resposta multi-linha termina quando o 4º char é espaço, não hífen
        last = lines[-2] if lines[-1] == b"" else lines[-1]
        if len(last) >= 4 and last[3:4] == b" ":
            break
    text = data.decode(errors="replace")
    for line in text.strip().splitlines():
        log_line(sock_log, "<", line)
    code = int(text[:3]) if text[:3].isdigit() else 0
    return code, text


def send_line(sock, sock_log, line):
    log_line(sock_log, ">", line)
    sock.sendall((line + "\r\n").encode())


def probe_domain(domain):
    result = {
        "domain": domain,
        "priority": domain in PRIORITY,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mx": None,
        "connect": "FAIL",
        "banner_code": None,
        "ehlo_code": None,
        "starttls": False,
        "mail_from_code": None,
        "rcpt_code": None,
        "classification": "UNKNOWN",
        "error": None,
        "log": [],
    }
    log = result["log"]

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8)
        mx_hosts = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers]
        )
        if not mx_hosts:
            raise Exception("sem registros MX")
        result["mx"] = mx_hosts[0][1]
    except Exception as e:
        result["error"] = f"MX lookup falhou: {e}"
        result["classification"] = "NO_MX"
        return result

    mx_host = result["mx"]

    try:
        addr_info = socket.getaddrinfo(mx_host, SMTP_PORT, socket.AF_INET6)
    except Exception:
        try:
            addr_info = socket.getaddrinfo(mx_host, SMTP_PORT)
        except Exception as e:
            result["error"] = f"Resolução do MX falhou: {e}"
            result["classification"] = "MX_UNRESOLVABLE"
            return result

    try:
        sock = socket.socket(addr_info[0][0], socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect(addr_info[0][4])
        result["connect"] = "OK"

        code, _ = read_response(sock, log)
        result["banner_code"] = code
        if code >= 500:
            result["classification"] = "REJECTED_AT_CONNECT"
            sock.close()
            return result

        send_line(sock, log, f"EHLO veriscop.dedyn.io")
        code, resp = read_response(sock, log)
        result["ehlo_code"] = code

        if code >= 500:
            result["classification"] = "REJECTED_AT_EHLO"
            sock.close()
            return result

        if "STARTTLS" in resp.upper():
            send_line(sock, log, "STARTTLS")
            code, _ = read_response(sock, log)
            if code < 400:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=mx_host)
                result["starttls"] = True
                send_line(sock, log, f"EHLO veriscop.dedyn.io")
                code, resp = read_response(sock, log)

        send_line(sock, log, f"MAIL FROM:<{MAIL_FROM}>")
        code, _ = read_response(sock, log)
        result["mail_from_code"] = code

        if code >= 500:
            result["classification"] = "REJECTED_AT_MAILFROM"
            send_line(sock, log, "QUIT")
            sock.close()
            return result

        rcpt = RCPT_PROBE.format(domain=domain)
        send_line(sock, log, f"RCPT TO:<{rcpt}>")
        code, _ = read_response(sock, log)
        result["rcpt_code"] = code

        send_line(sock, log, "QUIT")
        try:
            read_response(sock, log)
        except Exception:
            pass
        sock.close()

        if result["mail_from_code"] and result["mail_from_code"] < 300:
            if code < 300:
                result["classification"] = "ACCEPTED_UNKNOWN_RECIPIENT"
            elif code == 550 or code == 551:
                result["classification"] = "ACCEPTED_CONN_REJECTED_RCPT"
            else:
                result["classification"] = "ACCEPTED_CONN_AMBIGUOUS_RCPT"

    except socket.timeout:
        result["error"] = "timeout"
        result["classification"] = "TIMEOUT"
    except ConnectionRefusedError:
        result["error"] = "conexão recusada"
        result["classification"] = "CONNECTION_REFUSED"
    except Exception as e:
        result["error"] = str(e)
        result["classification"] = "ERROR"

    return result


def main():
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(probe_domain, d): d for d in PROVIDERS}
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            results.append(r)
            print(f"[{i}/{len(PROVIDERS)}] {r['domain']:30s} -> {r['classification']}")

    results.sort(key=lambda r: (not r["priority"], r["domain"]))

    with open("report.json", "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    with open("report.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain","priority","mx","connect","banner_code","ehlo_code",
                     "starttls","mail_from_code","rcpt_code","classification","error"])
        for r in results:
            w.writerow([r["domain"], r["priority"], r["mx"], r["connect"],
                        r["banner_code"], r["ehlo_code"], r["starttls"],
                        r["mail_from_code"], r["rcpt_code"], r["classification"],
                        r["error"]])

    with open("report.md", "w") as f:
        f.write(f"# PTR/SMTP Compatibility Test\n\n")
        f.write(f"Run: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write(f"Total testado: {len(results)}\n\n")

        summary = {}
        for r in results:
            summary[r["classification"]] = summary.get(r["classification"], 0) + 1
        f.write("## Resumo\n\n")
        for k, v in sorted(summary.items(), key=lambda x: -x[1]):
            f.write(f"- **{k}**: {v}\n")

        f.write("\n## Prioritários (🟡 do levantamento anterior)\n\n")
        f.write("| Domínio | MX | Classificação | Banner | EHLO | MAIL FROM | RCPT |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for r in results:
            if r["priority"]:
                f.write(f"| {r['domain']} | {r['mx']} | {r['classification']} | "
                        f"{r['banner_code']} | {r['ehlo_code']} | "
                        f"{r['mail_from_code']} | {r['rcpt_code']} |\n")

        f.write("\n## Todos os resultados\n\n")
        f.write("| Domínio | MX | Classificação |\n|---|---|---|\n")
        for r in results:
            f.write(f"| {r['domain']} | {r['mx']} | {r['classification']} |\n")

    print("\nRelatório salvo em report.json / report.csv / report.md")


if __name__ == "__main__":
    main()
