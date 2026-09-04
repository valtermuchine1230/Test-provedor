"""
Configura SPF (adiciona mecanismo ip6 do Route64, preservando o include
do ImprovMX), DKIM e DMARC no domínio veriscop.dedyn.io via API do deSEC.
Idempotente: pode rodar em toda execução sem duplicar registros.
"""
import os
import sys
import base64
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DESEC_TOKEN = os.environ["DESEC_TOKEN"]
DOMAIN = os.environ.get("TEST_DOMAIN", "veriscop.dedyn.io")
ROUTE64_IPV6_PREFIX = os.environ.get("ROUTE64_IPV6_PREFIX", "2a11:6c7:f35:e3::/64")
DKIM_SELECTOR = os.environ.get("DKIM_SELECTOR", "ptrtest")

API = "https://desec.io/api/v1"
HEADERS = {
    "Authorization": f"Token {DESEC_TOKEN}",
    "Content-Type": "application/json",
}


def get_rrset(subname, rtype):
    url_subname = "@" if subname == "" else subname
    r = requests.get(
        f"{API}/domains/{DOMAIN}/rrsets/{url_subname}/{rtype}/",
        headers=HEADERS,
    )
    if r.status_code == 200:
        return r.json()
    if r.status_code == 404:
        return None
    print(
        f"[ERRO] GET {rtype} {subname or '@'}: "
        f"{r.status_code} {r.text}",
        file=sys.stderr,
    )
    r.raise_for_status()


def put_rrset(subname, rtype, records, ttl=3600):
    url_subname = "@" if subname == "" else subname
    payload = {
        "subname": subname,
        "type": rtype,
        "ttl": ttl,
        "records": records,
    }
    r = requests.put(
        f"{API}/domains/{DOMAIN}/rrsets/{url_subname}/{rtype}/",
        headers=HEADERS,
        json=payload,
    )
    if r.status_code not in (200, 201):
        print(
            f"[ERRO] {rtype} {subname or '@'}: "
            f"{r.status_code} {r.text}",
            file=sys.stderr,
        )
        r.raise_for_status()
    print(f"[OK] {rtype} {subname or '@'} -> {records}")


def ensure_spf():
    current = get_rrset("", "TXT")
    spf_value = None
    other_txt = []
    if current:
        for rec in current["records"]:
            unquoted = rec.strip('"')
            if unquoted.startswith("v=spf1"):
                spf_value = unquoted
            else:
                other_txt.append(rec)

    if spf_value is None:
        spf_value = "v=spf1 ~all"

    if f"ip6:{ROUTE64_IPV6_PREFIX}" in spf_value:
        print("[SKIP] SPF já contém o prefixo do Route64.")
        return

    # insere o mecanismo ip6 antes do "~all" final
    parts = spf_value.split()
    tail = parts[-1] if parts[-1].endswith("all") else "~all"
    body = [p for p in parts if not p.endswith("all")]
    body.append(f"ip6:{ROUTE64_IPV6_PREFIX}")
    new_spf = "v=spf1 " + " ".join(p for p in body if p != "v=spf1") + f" {tail}"

    records = [f'"{new_spf}"'] + other_txt
    put_rrset("", "TXT", records)


def ensure_dkim():
    existing = get_rrset(f"{DKIM_SELECTOR}._domainkey", "TXT")
    if existing:
        print("[SKIP] DKIM selector já publicado.")
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode()

    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # Salva a chave privada como artifact local (NÃO commitar no repo).
    with open("dkim_private.pem", "w") as f:
        f.write(priv_pem)

    dkim_txt = f"v=DKIM1; k=rsa; p={pub_b64}"
    put_rrset(f"{DKIM_SELECTOR}._domainkey", "TXT", [f'"{dkim_txt}"'])
    print("[AVISO] Chave privada DKIM salva em dkim_private.pem "
          "— copie o conteúdo para o secret DKIM_PRIVATE_KEY e apague o arquivo.")


def ensure_dmarc():
    existing = get_rrset("_dmarc", "TXT")
    if existing:
        print("[SKIP] DMARC já publicado.")
        return
    dmarc = "v=DMARC1; p=none; rua=mailto:dmarc@" + DOMAIN
    put_rrset("_dmarc", "TXT", [f'"{dmarc}"'])


if __name__ == "__main__":
    ensure_spf()
    ensure_dkim()
    ensure_dmarc()
