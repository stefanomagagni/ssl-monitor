import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


def fetch_certificate(host, port):
    """
    Fetch certificate WITHOUT validation.
    Uses SECLEVEL=0 to allow legacy servers (Actalis, vecchi Java, TLS1.0/1.1).
    """
    try:
        conn = socket.create_connection((host, port), timeout=7)

        # Context permissivo per server legacy
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Supporto per ciphers legacy (fondamentale)
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except Exception:
            pass

        sock = context.wrap_socket(conn, server_hostname=host)
        der_cert = sock.getpeercert(True)
        sock.close()

        # Converte DER → X509
        return crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

    except ssl.SSLError as e:
        return f"SSL error: {e}"
    except Exception as e:
        return f"Connection error: {e}"


def parse_certificate(cert):
    """Extract data even if certificate chain is incomplete."""
    try:
        # Expiration date
        expires = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_left = (expires - datetime.utcnow()).days

        # Issuer
        issuer_parts = dict(cert.get_issuer().get_components())
        issuer = ", ".join([
            issuer_parts.get(b"O", b"").decode(),
            issuer_parts.get(b"CN", b"").decode()
        ]).strip(", ")

        # SAN
        san_list = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                san_list = [entry.strip() for entry in str(ext).split(",")]
                break

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer if issuer else "Unknown",
            "san": san_list,
            "chain": "⚠️ Incomplete or not provided by server",
            "chain_incomplete": True
        }

    except Exception as e:
        return {
            "error": f"Parsing error: {e}",
            "chain_incomplete": True
        }


def check_domains(config_path="app/config.json"):
    import json

    with open(config_path) as f:
        config = json.load(f)

    results = []

    for entry in config["domains"]:
        host = entry.get("url")
        port = entry.get("port", 443)
        service = entry.get("service_name")
        alert_days = entry.get("alert_days", config.get("notify_before_days", 15))

        cert = fetch_certificate(host, port)

        # ERROR CASE
        if isinstance(cert, str):
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "error": cert,
                "chain_incomplete": True
            })
            continue

        parsed = parse_certificate(cert)

        # PARSE ERROR CASE
        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "error": parsed["error"],
                "chain_incomplete": True
            })
            continue

        # SUCCESS CASE
        results.append({
            "service": service,
            "domain": host,
            "port": port,
            "expires": parsed["expires"],
            "days_left": parsed["days_left"],
            "issuer": parsed["issuer"],
            "san": parsed["san"],
            "chain": parsed["chain"],
            "chain_incomplete": parsed["chain_incomplete"],
            "alert": parsed["days_left"] <= alert_days
        })

    # SORT BY EXPIRY DATE (errori in fondo)
    def sort_key(item):
        if "error" in item:
            return (99999, item["service"])
        return (item["days_left"], item["service"])

    results.sort(key=sort_key)

    return results
