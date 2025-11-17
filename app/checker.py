import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


def detect_protocol(sock):
    version = sock.version()  # Example: 'TLSv1.3', 'TLSv1.2', 'SSLv3', None

    if not version:
        return "no_ssl"

    version = version.lower()

    if "tlsv1.3" in version or "tlsv1.2" in version:
        return "tls_modern"
    elif "tlsv1.1" in version or version == "tlsv1":
        return "tls_legacy"
    elif "ssl" in version:
        return "ssl_obsolete"
    return "unknown"


def try_handshake(host, port, tls_versions):
    """Attempts handshake using provided TLS context versions list."""
    for ver_name, tls_ctx in tls_versions:
        try:
            conn = socket.create_connection((host, port), timeout=8)
            sock = tls_ctx.wrap_socket(conn, server_hostname=host)

            protocol = detect_protocol(sock)

            try:
                der = sock.getpeercert(True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
                sock.close()
                return {"cert": cert, "protocol": protocol}
            except:
                sock.close()
                return {"error": "Peer connected but no certificate sent", "protocol": protocol}

        except Exception:
            continue

    return {"error": "Handshake failed on all supported protocols", "protocol": "no_ssl"}


def fetch_certificate(host, port):
    """Attempts handshake with fallback for TLS/SSL variations."""
    # Modern and legacy fallback order
    tls_attempts = [
        ("TLS_auto", ssl._create_unverified_context()),
        ("TLSv1", ssl.SSLContext(ssl.PROTOCOL_TLSv1)),
        ("TLSv1.1", ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)),
        ("TLSv1.2", ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)),
    ]

    # Optional SSLv3 fallback if available
    try:
        tls_attempts.append(("SSLv3", ssl.SSLContext(ssl.PROTOCOL_SSLv3)))
    except Exception:
        pass

    return try_handshake(host, port, tls_attempts)


def parse_certificate(cert):
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
                san_list = [s.strip() for s in str(ext).split(",")]
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

        data = fetch_certificate(host, port)
        protocol = data.get("protocol", "unknown")

        if "error" in data:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": protocol,
                "error": data["error"],
                "chain_incomplete": True
            })
            continue

        parsed = parse_certificate(data["cert"])

        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": protocol,
                "error": parsed["error"],
                "chain_incomplete": True
            })
            continue

        results.append({
            "service": service,
            "domain": host,
            "port": port,
            "protocol": protocol,
            "expires": parsed["expires"],
            "days_left": parsed["days_left"],
            "issuer": parsed["issuer"],
            "san": parsed["san"],
            "chain": parsed["chain"],
            "chain_incomplete": parsed["chain_incomplete"],
            "alert": parsed["days_left"] <= alert_days
        })

    results.sort(key=lambda x: (99999 if "error" in x else x["days_left"], x["service"]))
    return results
