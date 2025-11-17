import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


def detect_protocol(sock):
    """Restituisce categoria protocollo in base alla versione negoziata."""
    version = sock.version()  # es: 'TLSv1.2', 'TLSv1.3', 'SSLv3', None

    if version is None:
        return "no_ssl"

    version = version.lower()

    if "tlsv1.3" in version or "tlsv1.2" in version:
        return "tls_modern"
    elif "tlsv1.1" in version or "tlsv1" in version:
        return "tls_legacy"
    elif "ssl" in version:
        return "ssl_obsolete"
    else:
        return "unknown"


def fetch_certificate(host, port):
    """Fetch certificate WITHOUT validation, and detect protocol."""
    try:
        conn = socket.create_connection((host, port), timeout=5)
        context = ssl._create_unverified_context()
        sock = context.wrap_socket(conn, server_hostname=host)

        protocol = detect_protocol(sock)

        try:
            der_cert = sock.getpeercert(True)
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)
        except Exception:
            sock.close()
            return {"error": "No peer certificate provided", "protocol": protocol}

        sock.close()

        return {"cert": cert, "protocol": protocol}

    except ssl.SSLError as e:
        return {"error": f"SSL error: {e}", "protocol": "ssl_obsolete"}
    except Exception as e:
        return {"error": f"Connection error: {e}", "protocol": "no_ssl"}


def parse_certificate(cert):
    """Extract fields even if chain is incomplete."""
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

        chain_status = "⚠️ Incomplete or not provided by server"

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer if issuer else "Unknown",
            "san": san_list,
            "chain": chain_status,
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

    # sort by expiration
    def sort_key(item):
        if "error" in item:
            return (99999, item["service"])
        return (item["days_left"], item["service"])

    results.sort(key=sort_key)

    return results
