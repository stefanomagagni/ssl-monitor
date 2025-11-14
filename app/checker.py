import socket
import ssl
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import idna


def get_certificate(hostname, port):
    try:
        hostname_idna = idna.encode(hostname).decode()
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname_idna) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                chain = ssock.get_verified_chain() if hasattr(ssock, "get_verified_chain") else None

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        return cert, chain

    except Exception as e:
        return None, str(e)


def parse_certificate(cert, chain):
    issuer = ", ".join([f"{name.oid._name}: {name.value}" for name in cert.issuer])
    san_list = []

    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = ext.value.get_values_for_type(x509.DNSName)
    except:
        pass

    expires = cert.not_valid_after
    days_left = (expires - datetime.utcnow()).days

    chain_info = []
    if chain:
        for c in chain:
            chain_info.append(c.subject.rfc4514_string())

    return issuer, san_list, expires.strftime("%Y-%m-%d"), days_left, chain_info


def check_domains(config_path="app/config.json"):
    import json
    with open(config_path) as f:
        conf = json.load(f)

    results = []

    for item in conf["domains"]:
        url = item["url"]
        port = item.get("port", None)
        service_name = item.get("service_name", "")
        alert_days = item.get("alert_days", conf.get("notify_before_days", 15))

        if not port:
            results.append({
                "service": service_name,
                "domain": url,
                "port": None,
                "error": "Porta mancante, devi specificarla nel config.json"
            })
            continue

        cert, error = get_certificate(url, port)

        if error:
            results.append({
                "service": service_name,
                "domain": url,
                "port": port,
                "error": error
            })
            continue

        issuer, san, expires, days_left, chain = parse_certificate(cert, error)

        results.append({
            "service": service_name,
            "domain": url,
            "port": port,
            "issuer": issuer,
            "san": san,
            "expires": expires,
            "days_left": days_left,
            "chain": chain,
            "alert": days_left <= alert_days
        })

    return results
