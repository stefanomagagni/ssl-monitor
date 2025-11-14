import ssl, socket, json
from datetime import datetime

def get_cert_expiry(host, port=443):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()

    expires = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    issuer = " ".join(v[0][1] for v in cert['issuer'])
    san = [x[1] for x in cert.get('subjectAltName', [])]

    return expires.date(), issuer, san


def check_domains(config_path="app/config.json"):
    with open(config_path) as f:
        conf = json.load(f)

    results = []

    for d in conf["domains"]:
        url = d["url"]
        port = d.get("port", 443)
        service = d.get("service_name", "-")
        alert_days = d.get("alert_days", 15)

        try:
            expires, issuer, san = get_cert_expiry(url, port)
            days_left = (expires - datetime.now().date()).days
            alert = days_left < alert_days

            results.append({
                "domain": url,
                "port": port,
                "service": service,
                "expires": str(expires),
                "days_left": days_left,
                "issuer": issuer,
                "san": san,
                "alert": alert
            })

        except Exception as e:
            results.append({
                "domain": url,
                "port": port,
                "service": service,
                "error": str(e)
            })

    return results
