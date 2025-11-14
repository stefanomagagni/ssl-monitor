import ssl
import socket
import json
from datetime import datetime

def get_cert_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Expiry date
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days

        # Issuer (CA)
        issuer_data = cert.get("issuer", [])
        issuer = " ".join(x[0][1] for x in issuer_data if isinstance(x, tuple))

        # SAN (Subject Alternative Names)
        san_list = []
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                san_list.append(val)

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer or "Unknown",
            "san": san_list
        }

    except Exception as e:
        return {"error": str(e)}


def check_domains(config_path="app/config.json"):
    with open(config_path) as f:
        conf = json.load(f)

    results = []

    for d in conf["domains"]:
        url = d["url"].replace("https://", "").replace("http://", "").strip("/")
        alert_days = d.get("alert_days", conf.get("notify_before_days", 15))

        cert = get_cert_info(url)

        if "error" in cert:
            results.append({
                "domain": url,
                "error": cert["error"]
            })
            continue

        alert = cert["days_left"] <= alert_days

        results.append({
            "domain": url,
            "expires": cert["expires"],
            "days_left": cert["days_left"],
            "issuer": cert["issuer"],
            "san": cert["san"],
            "alert": alert
        })

    return results
