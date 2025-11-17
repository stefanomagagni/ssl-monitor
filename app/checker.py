import ssl
import socket
from datetime import datetime
from OpenSSL import crypto

# Lista protocolli in ordine dal migliore al peggiore
PROTOCOL_FALLBACKS = [
    ("tls_modern", ssl.PROTOCOL_TLS_CLIENT),  # auto TLS1.2/1.3
]

# Aggiungiamo protocolli legacy garantendo compatibilità
for p in ["PROTOCOL_TLSv1_2", "PROTOCOL_TLSv1_1", "PROTOCOL_TLSv1"]:
    if hasattr(ssl, p):
        PROTOCOL_FALLBACKS.append(("tls_legacy", getattr(ssl, p)))

# SSLv3 se disponibile → per server molto vecchi
if hasattr(ssl, "PROTOCOL_SSLv3"):
    PROTOCOL_FALLBACKS.append(("ssl_obsolete", ssl.PROTOCOL_SSLv3))
else:
    # ultima spiaggia
    PROTOCOL_FALLBACKS.append(("ssl_obsolete", ssl.PROTOCOL_TLSv1))


def try_handshake(host, port, label, protocol, timeout=5):
    """Prova handshake con protocollo specifico."""
    try:
        ctx = ssl.SSLContext(protocol)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        conn = socket.create_connection((host, port), timeout=timeout)
        sock = ctx.wrap_socket(conn, server_hostname=host)

        der = sock.getpeercert(binary_form=True)
        sock.close()

        if not der:
            return None

        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
        return cert
    except:
        return None


def fetch_tls_info(host, port):
    """
    Prova multipli handshake:
    - ritorna CERT + LABEL se trovato
    - ritorna stato errore coerente se nessuno funziona
    """

    # Prova *tutti* i protocolli prima di considerarlo errore
    for label, proto in PROTOCOL_FALLBACKS:
        cert = try_handshake(host, port, label, proto)
        if cert:
            return {"cert": cert, "protocol": label}, None, None

    # Se non abbiamo certificato, dobbiamo capire il perché
    # — distingui timeout / refused / no TLS
    try:
        conn = socket.create_connection((host, port), timeout=4)
        conn.close()
        return None, "no_tls", "Nessun certificato TLS disponibile"
    except socket.timeout:
        return None, "timeout", "Timeout di connessione"
    except ConnectionRefusedError:
        return None, "refused", "Connessione rifiutata"
    except Exception as e:
        return None, "unknown", f"Errore connessione: {e}"


def parse_certificate(cert):
    """Estrae dati dal certificato (anche incompleto)."""
    try:
        expires = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_left = (expires - datetime.utcnow()).days

        issuer_parts = dict(cert.get_issuer().get_components())
        issuer = ", ".join([
            issuer_parts.get(b"O", b"").decode(),
            issuer_parts.get(b"CN", b"").decode()
        ]).strip(", ")

        san = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                san = [x.strip() for x in str(ext).split(",")]
                break

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer if issuer else "Unknown",
            "san": san,
            "chain": "⚠ chain non validata",
            "chain_incomplete": True,
        }
    except Exception as e:
        return {"error": f"Errore parsing certificato: {e}"}


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

        data, proto_state, err_msg = fetch_tls_info(host, port)

        if err_msg:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": proto_state,
                "error": err_msg,
                "chain_incomplete": True
            })
            continue

        cert = data["cert"]
        proto = data["protocol"]

        parsed = parse_certificate(cert)

        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": proto,
                "error": parsed["error"],
                "chain_incomplete": True,
            })
            continue

        results.append({
            "service": service,
            "domain": host,
            "port": port,
            "protocol": proto,
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
