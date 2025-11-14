import ssl
import socket
import OpenSSL
import json
from datetime import datetime
from urllib.parse import urlparse

def load_config(path="app/config.json"):
    with open(path) as f:
        return json.load(f)

def get_certificate(host, port):
    ctx = ssl.create_default_context()

    # NON verifichiamo il certificato → estraiamo sempre i dati
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    conn = ctx.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=host
    )
    conn.settimeout(5)
    conn.connect((host, port))

    # Estrae cert grezzo
    der_cert = conn.getpeercert(True)
    conn.close()

    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)

    # Controllo chain → se verify fallisce = chain incompleta
    chain_incomplete = False
    try:
        ssl.get_server_certificate((host, port))
    except Exception:
        chain_incomplete = True

    return x509, chain_incomplete


def parse_cert(x509):
    # Expiration
    expires_str = x509.get_notAfter().decode("utf-8")
    expires_dt = datetime.strptime(expires_str, "%Y%m%d%H%M%SZ")

    # Issuer
    issuer = ", ".join([f"{name.decode()}={value.decode()}" for name, value in x509.get_issuer().get_components()])

    # SAN
    san = []
    ext_count = x509.get_extension_count()
    for i in range(ext_count):
        ext = x509.get_extension(i)
        if ext.get_short_name() == b"subjectAltName":
            san = ext.__str__().split(", ")

    return expires_dt, issuer, san


def check_domains(config_path="app/config.json"):
    config = load_config(config_path)
    results = []

    for entry in config["domains"]:
        url = entry["url"]
        alert_days = entry.get("alert_days", 30)
        service = entry.get("service", None)

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)

        try:
            cert, chain_incomplete = get_certificate(host, port)
            expires, issuer, san = parse_cert(cert)

            days_left = (expires - datetime.utcnow()).days
            alert = days_left <= alert_days

            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "expires": expires.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "issuer": issuer,
                "san": san,
                "alert": alert,
                "chain_incomplete": chain_incomplete
            })

        except Exception as e:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "error": str(e)
            })

    return results
