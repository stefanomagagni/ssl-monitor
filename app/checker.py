import ssl
import socket
import datetime
import json

def get_cert_info(domain):
    """Recupera informazioni complete sul certificato SSL."""
    try:
        hostname = domain.replace("https://", "").replace("http://", "").split("/")[0]

        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Data di scadenza
        expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

        # CA / Issuer
        issuer = ", ".join(x[0][1] for x in cert["issuer"])

        # SAN
        san = []
        for ext in cert.get("subjectAltName", []):
            san.append(ext[1])

        return {
            "expires": expiry.strftime("%Y-%m-%d"),
            "days_left": (expiry - datetime.datetime.utcnow()).days,
            "issuer": issuer,
            "san": san
        }

    except Exception as e:
        return {"error": str(e)}


def check_domains(config_path="app/config.json"):
    """Legge i domini dal config e costruisce il risultato completo."""
    with open(config_path) as f:
        conf = json.load(f)

    results = []

    for d in conf["domains"]:
        url = d["url"]
        alert_days = d.get("alert_days", conf.get("notify_before_days", 15))

        cert = get_cert_info(url)

        if "error" in cert:
            results.append({
                "domain": url,
                "error": cert["error"]
            })
            continue

        results.append({
            "domain": url,
            "expires": cert["expires"],
            "days_left": cert["days_left"],
            "issuer": cert["issuer"],
            "san": cert["san"],
            "alert": cert["days_left"] <= alert_days
        })

    return results
