import ssl
import socket
from datetime import datetime
from OpenSSL import crypto

# Protocol test order
SSL_PROTOCOLS = [
    ("tls_modern", ssl.PROTOCOL_TLS_CLIENT),  # auto TLS1.2/1.3
    ("tls_legacy", ssl.PROTOCOL_TLSv1),       # TLS 1.0
    ("tls_legacy", ssl.PROTOCOL_TLSv1_1),     # TLS 1.1
    ("ssl_obsolete", ssl.PROTOCOL_TLSv1),     # fallback used when SSLv3 unsupported
]


def try_handshake(host, port, label, protocol):
    try:
        ctx = ssl.SSLContext(protocol)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        conn = socket.create_connection((host, port), timeout=4)
        sock = ctx.wrap_socket(conn, server_hostname=host)

        der = sock.getpeercert(binary_form=True)
        sock.close()

        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
        return cert, label

    except ssl.SSLError:
        return "not_tls", label
    except Exception:
        return None, None


def detect_state_and_fetch_cert(host, port):
    """Return: cert, protocol_label, state_icon"""

    # Step 1 — TCP connection test
    try:
        test_socket = socket.create_connection((host, port), timeout=4)
        tcp_open = True
        test_socket.close()
    except ConnectionRefusedError:
        return None, "closed", "❌"
    except socket.timeout:
        return None, "timeout", "🕓"
    except Exception:
        return None, "timeout", "🕓"

    # Step 2 — TLS/SSL handshake attempts
    for label, proto in SSL_PROTOCOLS:
        cert, result = try_handshake(host, port, label, proto)

        if cert == "not_tls":
            return None, "not_tls", "⚪"
        if cert:
            icon = "🟢" if label == "tls_modern" else "🟠" if label == "tls_legacy" else "🔴"
            return cert, label, icon

    return None, "not_tls", "⚪"


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
                san_list = [entry.strip() for entry in str(ext).split(",")]
                break

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer if issuer else "Unknown",
            "san": san_list,
            "chain": "⚠️ missing intermediate",
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

        cert, proto_label, state_icon = detect_state_and_fetch_cert(host, port)

        if cert is None:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol_icon": state_icon,
                "protocol": proto_label,
                "error": (
                    "Port closed" if state_icon == "❌" else
                    "Timeout" if state_icon == "🕓" else
                    "No TLS certificate available"
                ),
                "chain_incomplete": True
            })
            continue

        parsed = parse_certificate(cert)

        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol_icon": state_icon,
                "protocol": proto_label,
                "error": parsed["error"],
            })
            continue

        results.append({
            "service": service,
            "domain": host,
            "port": port,
            "protocol_icon": state_icon,
            "protocol": proto_label,
            "expires": parsed["expires"],
            "days_left": parsed["days_left"],
            "issuer": parsed["issuer"],
            "san": parsed["san"],
            "chain": parsed["chain"],
            "chain_incomplete": parsed["chain_incomplete"],
            "alert": parsed["days_left"] <= alert_days,
        })

    results.sort(key=lambda x: (99999 if "days_left" not in x else x["days_left"]))
    return results
