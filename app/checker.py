import ssl
import socket
from datetime import datetime
from OpenSSL import crypto

# Order of protocol fallback
PROTO_FALLBACK = [
    ("TLS 1.3", ssl.PROTOCOL_TLS_CLIENT),
    ("TLS 1.2", ssl.PROTOCOL_TLSv1_2),
    ("TLS 1.1", ssl.PROTOCOL_TLSv1_1),
    ("TLS 1.0", ssl.PROTOCOL_TLSv1),
    ("SSL 3.0", ssl.PROTOCOL_SSLv3) if hasattr(ssl, "PROTOCOL_SSLv3") else None,
]

# Remove Nones if SSLv3 is not available
PROTO_FALLBACK = [p for p in PROTO_FALLBACK if p is not None]


def try_handshake(host, port):
    """Attempt connection using fallback protocols, returning protocol used + certificate"""
    for label, proto in PROTO_FALLBACK:
        try:
            context = ssl.SSLContext(proto)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as conn:
                with context.wrap_socket(conn, server_hostname=host) as sock:
                    der = sock.getpeercert(True)
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
                    return cert, label  # SUCCESS!

        except Exception:
            continue

    return None, None  # NO PROTOCOL WORKED


def parse_certificate(cert, protocol_label):
    try:
        expires = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_left = (expires - datetime.utcnow()).days

        issuer_parts = dict(cert.get_issuer().get_components())
        issuer = ", ".join(filter(None, [
            issuer_parts.get(b"O", b"").decode(),
            issuer_parts.get(b"CN", b"").decode()
        ]))

        # Parse SAN
        san_list = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                san_list = [entry.strip() for entry in str(ext).split(",")]
                break

        chain_status = "⚠️ Incomplete or not provided by server"

        # risk level based on protocol
        risk_map = {
            "TLS 1.3": "low",
            "TLS 1.2": "low",
            "TLS 1.1": "medium",
            "TLS 1.0": "medium",
            "SSL 3.0": "high"
        }

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer if issuer else "Unknown",
            "san": san_list,
            "chain": chain_status,
            "chain_incomplete": True,
            "protocol": protocol_label,
            "risk_level": risk_map.get(protocol_label, "unknown")
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

        cert, protocol_label = try_handshake(host, port)

        if cert is None:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "error": "Handshake failed on all protocols",
                "chain_incomplete": True
            })
            continue

        parsed = parse_certificate(cert, protocol_label)

        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "error": parsed["error"],
                "chain_incomplete": True
            })
            continue

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
            "alert": parsed["days_left"] <= alert_days,
            "protocol": parsed["protocol"],
            "risk_level": parsed["risk_level"]
        })

    # Sort by expiry date
    def sort_key(item):
        if "error" in item:
            return (99999, item["service"])
        return (item["days_left"], item["service"])

    results.sort(key=sort_key)
    return results

