import ssl
import socket
from datetime import datetime
from OpenSSL import crypto

# Lista protocolli da testare in ordine
SSL_PROTOCOLS = [
    ("tls_modern", ssl.PROTOCOL_TLS_CLIENT),  # Supporta auto TLS1.2/1.3
    ("tls_legacy", ssl.PROTOCOL_TLSv1),       # TLS 1.0
    ("tls_legacy", ssl.PROTOCOL_TLSv1_1),     # TLS 1.1
]


def try_handshake(host, port, label, protocol):
    """Tenta handshake TLS e ritorna certificato + etichetta se riesce."""
    try:
        context = ssl.SSLContext(protocol)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        conn = socket.create_connection((host, port), timeout=4)
        sock = context.wrap_socket(conn, server_hostname=host)

        der = sock.getpeercert(binary_form=True)
        sock.close()

        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
        return cert, label

    except Exception:
        return None, None


def detect_protocol_and_fetch(host, port):
    """Verifica porta + handshake + certificato con fallback multi-protocollo."""

    # 1️⃣ Test TCP reachability
    try:
        socket.create_connection((host, port), timeout=4).close()
    except TimeoutError:
        return None, "timeout"
    except Exception:
        return None, "port_closed"

    # 2️⃣ Se la porta è aperta, proviamo TLS
    for label, proto in SSL_PROTOCOLS:
        cert, proto_label = try_handshake(host, port, label, proto)
        if cert:
            return cert, proto_label

    # 3️⃣ Porta risponde ma NON parla TLS → servizio non SSL
    return None, "no_tls"


def parse_certificate(cert):
    """Estrae metadati certificato anche se la chain è incompleta."""
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
            "chain": "⚠ missing intermediate (not validated)",
            "chain_incomplete": True,
        }

    except Exception as e:
        return {"error": f"Certificate parsing failed: {e}"}


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

        cert, protocol = detect_protocol_and_fetch(host, port)

        # Stato icone
        protocol_icon_map = {
            "tls_modern": "🟢",
            "tls_legacy": "🟠",
            "ssl_obsolete": "🔴",
            "no_tls": "⚫",
            "port_closed": "🚫",
            "timeout": "🕓",
        }
        icon = protocol_icon_map.get(protocol, "❔")

        # Porta aperta ma NESSUN certificato TLS
        if cert is None:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": icon,
                "expires": "N/A",
                "days_left": 999999,
                "issuer": "N/A",
                "san": [],
                "chain": "N/A",
                "chain_incomplete": True,
                "alert": False,
                "error": "No TLS certificate available" if protocol == "no_tls" else "Connection or handshake failed",
            })
            continue

        # parsing OK
        parsed = parse_certificate(cert)

        results.append({
            "service": service,
            "domain": host,
            "port": port,
            "protocol": icon,
            "expires": parsed["expires"],
            "days_left": parsed["days_left"],
            "issuer": parsed["issuer"],
            "san": parsed["san"],
            "chain": parsed["chain"],
            "chain_incomplete": parsed["chain_incomplete"],
            "alert": parsed["days_left"] <= alert_days,
        })

    # sorting: certificati validi prima, poi errori
    results.sort(key=lambda x: x["days_left"])
    return results
