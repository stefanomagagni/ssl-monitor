import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


# ================================================================
#  CONFIGURAZIONE FALLBACK HANDSHAKE
# ================================================================

HANDSHAKE_ATTEMPTS = [
    ("tls_auto", None),                    # Automatico (TLS1.2/1.3 in genere)
    ("tls_legacy", ssl.PROTOCOL_TLSv1),    # TLS 1.0
    ("tls_legacy", ssl.PROTOCOL_TLSv1_1),  # TLS 1.1
]

# Tentativo SSLv3 SOLO SE supportato dall'interprete
if hasattr(ssl, "PROTOCOL_SSLv3"):
    HANDSHAKE_ATTEMPTS.append(("ssl_obsolete", ssl.PROTOCOL_SSLv3))


# ================================================================
#  FUNZIONE BASE DI CONNESSIONE
# ================================================================

def attempt_handshake(host, port, protocol_name, protocol_version, timeout=6, use_sni=True):
    try:
        conn = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        return None, "timeout", "Timeout di connessione"
    except ConnectionRefusedError:
        return None, "refused", "Connessione rifiutata"
    except OSError as e:
        return None, "refused", f"Errore socket: {e}"

    try:
        if protocol_version is None:
            ctx = ssl._create_unverified_context()
        else:
            ctx = ssl.SSLContext(protocol_version)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        if use_sni:
            sock = ctx.wrap_socket(conn, server_hostname=host)
        else:
            sock = ctx.wrap_socket(conn)

        protocol_used = sock.version() or ""

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

        # Classificazione protocollo reale
        pl = protocol_used.lower()
        if "tlsv1.3" in pl or "tlsv1.2" in pl:
            proto_label = "tls_modern"
        elif "tlsv1.1" in pl or "tlsv1" == pl:
            proto_label = "tls_legacy"
        elif pl.startswith("ssl"):
            proto_label = "ssl_obsolete"
        else:
            proto_label = "unknown"

        return {"cert": cert, "protocol": proto_label}, None, None

    except ssl.SSLError as e:
        msg = str(e).lower()
        if "wrong version" in msg or "unknown protocol" in msg:
            return None, "tcp_open_not_tls", "Porta aperta ma non parla TLS"
        return None, "no_tls", f"Errore SSL/TLS: {e}"

    except socket.timeout:
        return None, "timeout", "Timeout durante handshake"
    except Exception as e:
        return None, "refused", f"Errore handshake: {e}"


# ================================================================
#  FALLBACK MANAGER
# ================================================================

def fetch_tls_info(host, port):
    # 1️⃣ Tentativi standard (SNI)
    for proto_name, proto_ver in HANDSHAKE_ATTEMPTS:
        data, proto_state, err = attempt_handshake(host, port, proto_name, proto_ver)
        if data:
            return data, None, None
        if proto_state not in (None, "no_tls"):
            last_state, last_err = proto_state, err

    # 2️⃣ Tentativo SENZA SNI
    data, proto_state, err = attempt_handshake(host, port, "no_sni", None, use_sni=False)
    if data:
        data["protocol"] = "tls_legacy"  # Di norma senza SNI = legacy
        return data, None, None

    return None, proto_state or "no_tls", err or "Impossibile stabilire connessione TLS"


# ================================================================
#  PARSING CERTIFICATO
# ================================================================

def parse_certificate(cert):
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

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer or "Unknown",
            "san": san_list,
            "chain": "⚠ chain non validata (possibili intermediate CA mancanti)",
            "chain_incomplete": True,
        }

    except Exception as e:
        return {"error": f"Errore parsing certificato: {e}"}


# ================================================================
#  MAIN CHECK FUNCTION
# ================================================================

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

        data, proto_state, err = fetch_tls_info(host, port)

        if err:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": proto_state,
                "error": err,
                "chain_incomplete": True,
            })
            continue

        cert = data["cert"]
        parsed = parse_certificate(cert)

        if "error" in parsed:
            results.append({
                "service": service,
                "domain": host,
                "port": port,
                "protocol": data["protocol"],
                "error": parsed["error"],
                "chain_incomplete": True,
            })
            continue

        results.append({
            "service": service,
            "domain": host,
            "port": port,
            "protocol": data["protocol"],
            "expires": parsed["expires"],
            "days_left": parsed["days_left"],
            "issuer": parsed["issuer"],
            "san": parsed["san"],
            "chain": parsed["chain"],
            "chain_incomplete": parsed["chain_incomplete"],
            "alert": parsed["days_left"] <= alert_days,
        })

    # Ordina come richiesto
    def sort_key(r):
        if "error" in r:
            return (1, 999999)
        return (0, r.get("days_left", 999999))

    results.sort(key=sort_key)
    return results
