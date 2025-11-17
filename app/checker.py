import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


def classify_protocol(proto):
    """Return protocol classification: modern / legacy / obsolete."""
    if proto in ("TLSv1.3", "TLSv1.2"):
        return "modern"
    if proto == "TLSv1.1":
        return "legacy"
    return "obsolete"  # TLS1.0, SSLv3, SSLv2, unknown, None


def fetch_certificate(host, port):
    """Fetch certificate WITHOUT strict validation and capture protocol."""
    try:
        conn = socket.create_connection((host, port), timeout=6)
        context = ssl._create_unverified_context()
        sock = context.wrap_socket(conn, server_hostname=host)

        # detect protocol used
        proto = sock.version()  # example: TLSv1.2, TLSv1.3, TLSv1.1, TLSv1, None

        der_cert = sock.getpeercert(True)
        sock.close()

        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
        return cert, proto

    except ssl.SSLError as e:
        return f"SSL error: {e}", None
    except Exception as e:
        return f"Connection error: {e}", None


def parse_certificate(cert, proto):
    """Extract information even if chain is incomplete."""
    try:
        expires = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_left = (expires - datetime.utcnow()).days

        issuer_parts = dict(cert.get_issuer().get_components())
        issuer = ", ".join([
            issuer_parts.get(b"O", b"").decode(),
            issuer_parts.get(b"CN", b"").decode()
        ]).strip(", ")

        # SAN extraction
        san_list = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                san_list = [entry.strip() for entry in str(ext).split(",")]
                break

        protocol_level = classify_protocol(proto)

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer if issuer else "Unknown",
            "san": san_list,
            "chain": "⚠️ Incomplete or not provided by server",
            "chain_incomplete": True,
            "protocol": proto,
            "protocol_level": protocol_level,
        }

    except Exception as e:
        return {
            "error": f"Parsing error: {e}",
            "chain_incomplete": True,
            "protocol": proto,
            "protocol_level": classify_protocol(proto)
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

        cert, proto = fetch_certificate(host, port)

        # Error case (no certificate)
        if isinstance(cert, str):
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "error": cert,
                "chain_incomplete": True,
                "protocol": proto,
                "protocol_level": classify_protocol(proto),
            })
            continue

        parsed = parse_certificate(cert, proto)

        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "error": parsed["error"],
                "chain_incomplete": True,
                "protocol": parsed.get("protocol"),
                "protocol_level": parsed.get("protocol_level"),
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
            "protocol": parsed["protocol"],
            "protocol_level": parsed["protocol_level"],
            "alert": parsed["days_left"] <= alert_days
        })

    # Sort by expiration
    def sort_key(item):
        if "days_left" not in item:
            return (999999, item["service"])
        return (item["days_left"], item["service"])

    results.sort(key=sort_key)
    return results
