import ssl, socket, datetime, json

def get_cert_expiry(domain):
    hostname = domain.replace("https://", "").replace("http://", "").split("/")[0]
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
    exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    return exp

def check_domains(config_path="app/config.json"):
    with open(config_path) as f:
        conf = json.load(f)
    results = []
    now = datetime.datetime.utcnow()
    for d in conf["domains"]:
        try:
            expiry = get_cert_expiry(d["url"])
            days_left = (expiry - now).days
            results.append({
                "domain": d["url"],
                "expires": expiry.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "alert": days_left < d["alert_days"]
            })
        except Exception as e:
            results.append({
                "domain": d["url"],
                "error": str(e)
            })
    return results
