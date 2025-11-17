import ssl
import socket
from datetime import datetime
from OpenSSL import crypto

def fetch_certificate_and_protocol(host, port):
    """
    Apre una connessione TLS non validata, ritorna certificato DER e protocollo negoziato.
    """
    try:
        # Connessione TCP
        conn = socket.create_connection((host, port), timeout=5)

        # Contesto senza validazione (accetta anche chain non completa)
        context = ssl._create_unverified_context()

        # Wrap TLS, con SNI
        sock = context.wrap_socket(conn, server_hostname=host)

        # Ottenimento certificato in formato DER
        der_cert = sock.getpeercert(True)

        # Recupero versione protocollo negoziato
        negotiated_protocol = sock.version() or "unknown"

        sock.close()

        # Conversione a oggetto X509
        cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

        return cert_obj, negotiated_protocol

    except ssl.SSLError as e:
        return f"SSL error: {e}", None
    except Exception as e:
        return f"Connection error: {e}", None


def parse_certificate(cert):
    """Estrarre informazioni certificate, assume chain incompleta."""
    try:
        expires = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_left = (expires - datetime.utcnow()).days

        issuer_parts = dict(cert.get_issuer().get_components())
        issuer = ", ".join([
            issuer_parts.get(b"O", b"").decode(),
            issuer_parts.get(b"CN", b"").decode()
        ]).strip(", ")

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
        return {"error": f"Parsing error: {e}", "chain_incomplete": True}


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

        cert, proto = fetch_certificate_and_protocol(host, port)

        # Error check
        if isinstance(cert, str):
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": proto or "unknown",
                "error": cert,
                "chain_incomplete": True
            })
            continue

        parsed = parse_certificate(cert)

        # Parsing error
        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": proto or "unknown",
                "error": parsed["error"],
                "chain_incomplete": True
            })
            continue

        # Success
        results.append({
            "service": service,
            "domain": host,
            "port": port,
            "protocol": proto,
            "expires": parsed["expires"],
            "days_left": parsed["days_left"],
            "issuer": parsed["issuer"],
            "san": parsed["san"],
            "chain": parsed["chain"],
            "chain_incomplete": parsed["chain_incomplete"],
            "alert": parsed["days_left"] <= alert_days
        })

    return results
