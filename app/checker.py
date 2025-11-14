import ssl
import socket
from datetime import datetime
import json

def get_cert_info(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(5.0)
    conn.connect((hostname, 443))
    cert = conn.getpeercert()
    conn.close()

    # Estraggo i dati principali
    issuer = dict(x[0] for x in cert['issuer'])
    issued_by = issuer.get('organizationName', issuer.get('commonName', 'Sconosciuto'))

    return {
        "expires": datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z"),
        "issuer": issued_by
    }

def check_domains(config_path="app/config.json"):
    with open(config_path) as f:
        conf = json.load(f)

    results = []
    for d in conf["domains"]:
        url = d["url"].replace("https://", "").replace("http://", "").split("/")[0]
        alert_days = d.get("alert_days", conf.get("notify_before_days", 15))
        try:
            info = get_cert_info(url)
            expires = info["expires"]
            issuer = info["issuer"]
            days_left = (expires - datetime.utcnow()).days
            results.append({
                "domain": url,
                "expires": expires.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "issuer": issuer,
                "alert": days_left <= alert_days
            })
        except Exception as e:
            results.append({
                "domain": url,
                "error": str(e)
            })

    return results
