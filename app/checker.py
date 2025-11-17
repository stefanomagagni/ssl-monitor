import ssl
import socket
from datetime import datetime
from OpenSSL import crypto

# Tentativi compatibili e più aggressivi per sistemi legacy
PROTOCOL_MATRIX = [
    ("tls_modern", ssl.PROTOCOL_TLS),          # TLS 1.2 / 1.3 auto
    ("tls_legacy", ssl.PROTOCOL_TLSv1_1),      # TLS 1.1
    ("tls_legacy", ssl.PROTOCOL_TLSv1),        # TLS 1.0
    ("ssl_obsolete", ssl.PROTOCOL_SSLv23),     # handshake permissivo (NON SSLv2/v3 reali)
]


def try_handshake(host, port, label, protocol, use_sni=True, allow_weak=False):
    try:
        ctx = ssl.SSLContext(protocol)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if allow_weak:
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except Exception:
                pass

        conn = socket.create_connection((host, port), timeout=5)

        if use_sni:
            sock = ctx.wrap_socket(conn, server_hostname=host)
        else:
            sock = ctx.wrap_socket(conn)

        der = sock.getpeercert(binary_form=True)
        sock.close()

        return crypto.load_certificate(crypto.FILETYPE_ASN1, der), label

    except Exception:
        return None, None


def detect_protocol(host, port):

    for label, proto in PROTOCOL_MATRIX:

        # 1️⃣ con SNI
        cert, lbl = try_handshake(host, port, label, proto, use_sni=True)
        if cert:
            return cert, lbl

        # 2️⃣ senza SNI (apparati legacy)
        cert, lbl = try_handshake(host, port, label, proto, use_sni=False)
        if cert:
            return cert, lbl

        # 3️⃣ con cipher weak e senza SNI (ultima spiaggia controllata)
        cert, lbl = try_handshake(host, port, label, proto, use_sni=False, allow_weak=True)
        if cert:
            return cert, lbl

    return None, "no_tls"


def parse_certificate(cert):

    try:
        expires = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_left = (expires - datetime.utcnow()).days

        issuer_data = dict(cert.get_issuer().get_components())
        issuer = ", ".join([
            issuer_data.get(b"O", b"").decode(),
            issuer_data.get(b"CN", b"").decode()
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
            "issuer": issuer or "Unknown",
            "san": san_list,
            "chain": "⚠ not validated",
            "chain_incomplete": True
        }

    except Exception as e:
        return {"error": f"Cannot parse certificate: {e}"}


def check_domains(config_path="app/config.json"):
    import json
    with open(config_path) as f:
        config = json.load(f)

    results = []

    for entry in config["domains"]:
        host = entry["url"]
        port = entry.get("port", 443)
        service = entry.get("service_name")
        alert_days = entry.get("alert_days", config.get("notify_before_days", 15))

        cert, protocol = detect_protocol(host, port)

        if cert is None:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": protocol,
                "error": "No TLS certificate available",
                "chain_incomplete": True
            })
            continue

        parsed = parse_certificate(cert)
        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": protocol,
                "error": parsed["error"]
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

    results.sort(key=lambda x: (99999 if "error" in x else x["days_left"]))
    return results
