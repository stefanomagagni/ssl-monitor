import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


def fetch_tls_info(host, port, timeout=5):
    """
    Prova a connettersi e fare handshake TLS.

    Ritorna:
      - (data_dict, None, None)  se il certificato è stato ottenuto
      - (None, protocol_state, error_message) se qualcosa va storto

    protocol_state può essere:
      - "tls_modern", "tls_legacy", "ssl_obsolete"
      - "no_tls", "timeout", "refused", "unknown"
    """
    try:
        conn = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        return None, "timeout", "Timeout di connessione"
    except ConnectionRefusedError:
        return None, "refused", "Connessione rifiutata"
    except OSError as e:
        return None, "refused", f"Errore di connessione: {e}"

    try:
        # Contesto TLS molto permissivo, ma senza validazione
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = ctx.wrap_socket(conn, server_hostname=host)
        version = sock.version() or ""  # es: "TLSv1.2"

        try:
            der = sock.getpeercert(binary_form=True)
        except Exception:
            sock.close()
            return None, "no_tls", "Nessun certificato TLS disponibile"

        if not der:
            sock.close()
            return None, "no_tls", "Nessun certificato TLS disponibile"

        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
        sock.close()

        # Classificazione protocollo
        version_low = version.lower()
        if "tlsv1.3" in version_low or "tlsv1.2" in version_low:
            proto_label = "tls_modern"
        elif "tlsv1.1" in version_low or version_low == "tlsv1":
            proto_label = "tls_legacy"
        elif version_low.startswith("ssl"):
            proto_label = "ssl_obsolete"
        else:
            proto_label = "unknown"

        return {"cert": cert, "protocol": proto_label}, None, None

    except ssl.SSLError as e:
        msg = str(e).lower()
        # Porta aperta ma non parla TLS
        if "wrong version number" in msg or "unknown protocol" in msg:
            return None, "no_tls", "Servizio non TLS sulla porta specificata"
        return None, "no_tls", f"Errore SSL/TLS: {e}"

    except socket.timeout:
        return None, "timeout", "Timeout durante handshake"
    except Exception as e:
        return None, "refused", f"Errore durante handshake: {e}"


def parse_certificate(cert):
    """Estrae dati dal certificato (anche se la chain è incompleta)."""
    try:
        # Expiry
        expires = datetime.strptime(
            cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ"
        )
        days_left = (expires - datetime.utcnow()).days

        # Issuer
        issuer_parts = dict(cert.get_issuer().get_components())
        issuer = ", ".join([
            issuer_parts.get(b"O", b"").decode(),
            issuer_parts.get(b"CN", b"").decode()
        ]).strip(", ")

        # SAN
        san_list = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                san_list = [entry.strip() for entry in str(ext).split(",")]
                break

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer if issuer else "Unknown",
            "san": san_list,
            # Non validiamo la chain → la segniamo sempre "non completa"
            "chain": "⚠ chain non validata (possibili CA intermedie mancanti)",
            "chain_incomplete": True,
        }

    except Exception as e:
        return {"error": f"Errore lettura certificato: {e}"}


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

        data, proto_state, err_msg = fetch_tls_info(host, port)

        # Caso ERRORE / nessun certificato / timeout / rifiutata
        if err_msg is not None:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": proto_state,
                "error": err_msg,
                "chain_incomplete": True,
            })
            continue

        cert = data["cert"]
        proto_label = data["protocol"]

        parsed = parse_certificate(cert)

        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": proto_label,
                "error": parsed["error"],
                "chain_incomplete": True,
            })
            continue

        results.append({
            "service": service,
            "domain": host,
            "port": port,
            "protocol": proto_label,
            "expires": parsed["expires"],
            "days_left": parsed["days_left"],
            "issuer": parsed["issuer"],
            "san": parsed["san"],
            "chain": parsed["chain"],
            "chain_incomplete": parsed["chain_incomplete"],
            "alert": parsed["days_left"] <= alert_days,
        })

    # Ordina: prima quelli OK, poi errori
    def sort_key(r):
        if "error" in r:
            return (1, 999999)
        return (0, r.get("days_left", 999999))

    results.sort(key=sort_key)
    return results
