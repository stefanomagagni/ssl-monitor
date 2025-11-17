import ssl
import socket
from datetime import datetime
from OpenSSL import crypto

# ===========================================================
#  HELPERS
# ===========================================================

def _connect_and_get_cert(host, port, ctx, timeout=5, use_sni=True):
    """
    Effettua connessione TLS (con o senza SNI) e ritorna (certificate, version)
    """
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = ctx.wrap_socket(raw, server_hostname=host if use_sni else None)
    version = sock.version() or ""
    der = sock.getpeercert(binary_form=True)
    if not der:
        sock.close()
        raise ssl.SSLError("No certificate returned")
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
    sock.close()
    return cert, version


def _classify_version(version):
    v = (version or "").lower()
    if "tlsv1.3" in v or "tlsv1.2" in v:
        return "tls_modern"
    if "tlsv1.1" in v or v == "tlsv1":
        return "tls_legacy"
    if v.startswith("ssl"):
        return "ssl_obsolete"
    return "unknown"


# ===========================================================
#  MAIN TLS FUNCTION
# ===========================================================

def fetch_tls_info(host, port, timeout=5):
    """
    Restituisce:
      successo: ({ "cert": x, "protocol": proto }, None, None)
      errore: (None, protocol_state, error_message)

    protocol_state può essere:
      tls_modern, tls_legacy, ssl_obsolete, tcp_open_not_tls, timeout, refused, no_tls, unknown
    """
    # 1) TCP connection
    try:
        conn = socket.create_connection((host, port), timeout=timeout)
    except socket.timeout:
        return None, "timeout", "Timeout di connessione"
    except ConnectionRefusedError:
        return None, "refused", "Connessione rifiutata"
    except OSError as e:
        return None, "refused", f"Errore di connessione: {e}"

    # ---- TENTATIVO TLS MODERNO (TLS1.3/1.2) ----
    try:
        ctx_modern = ssl._create_unverified_context()
        ctx_modern.check_hostname = False
        ctx_modern.verify_mode = ssl.CERT_NONE

        cert, version = _connect_and_get_cert(host, port, ctx_modern, timeout=timeout, use_sni=True)
        proto_label = _classify_version(version)
        return {"cert": cert, "protocol": proto_label}, None, None

    except ssl.SSLError as e_modern:
        msg = str(e_modern).lower()

        # trigger fallback TLS1.0
        fallback_triggers = [
            "handshake", "no protocols available", "protocol version",
            "unsupported protocol", "illegal parameter", "sslv3", "alert"
        ]

        if any(k in msg for k in fallback_triggers):
            pass  # eseguiamo fallback sotto
        else:
            if "wrong version number" in msg or "unknown protocol" in msg:
                return None, "tcp_open_not_tls", "Porta aperta ma non parla SSL/TLS"
            return None, "no_tls", f"Errore SSL/TLS: {e_modern}"

    except socket.timeout:
        return None, "timeout", "Timeout durante handshake"
    except Exception as e:
        return None, "refused", f"Errore handshake: {e}"

    # ---- FALLBACK TLS 1.0 ----
    try:
        ctx_legacy = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx_legacy.check_hostname = False
        ctx_legacy.verify_mode = ssl.CERT_NONE

        # 1️⃣ TLS1 con SNI
        try:
            cert, version = _connect_and_get_cert(host, port, ctx_legacy, timeout=timeout, use_sni=True)
            proto_label = _classify_version(version)
            return {"cert": cert, "protocol": proto_label, "fallback": "sni"}, None, None
        except ssl.SSLError:
            pass

        # 2️⃣ TLS1 senza SNI → NS2
        try:
            cert, version = _connect_and_get_cert(host, port, ctx_legacy, timeout=timeout, use_sni=False)
            proto_label = _classify_version(version)
            return {"cert": cert, "protocol": proto_label, "fallback": "no_sni"}, None, None
        except Exception:
            return None, "no_tls", f"Errore TLS1.0 final fallback: impossibile ottenere certificato"

    except Exception as e_fallback:
        return None, "no_tls", f"Errore TLS1.0 fallback: {e_fallback}"


# ===========================================================
#  PARSE CERTIFICATE
# ===========================================================

def parse_certificate(cert):
    try:
        expires = datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        days_left = (expires - datetime.utcnow()).days

        # Issuer
        issuer_dict = dict(cert.get_issuer().get_components())
        issuer = ", ".join([
            issuer_dict.get(b"O", b"").decode(),
            issuer_dict.get(b"CN", b"").decode()
        ]).strip(", ")

        # SAN
        san = []
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                san = [item.strip() for item in str(ext).split(",")]
                break

        return {
            "expires": expires.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "issuer": issuer or "Unknown",
            "san": san,
            "chain": "⚠ chain non validata (possibili CA intermedie mancanti)",
            "chain_incomplete": True
        }

    except Exception as e:
        return {"error": f"Errore lettura certificato: {e}"}


# ===========================================================
#  MAIN CHECKER
# ===========================================================

def check_domains(config_path="app/config.json"):
    import json

    with open(config_path) as f:
        cfg = json.load(f)

    results = []

    for entry in cfg["domains"]:
        host = entry.get("url")
        port = entry.get("port", 443)
        svc  = entry.get("service_name")
        alert_days = entry.get("alert_days", cfg.get("notify_before_days", 15))

        data, proto, err = fetch_tls_info(host, port)

        if err:
            results.append({
                "service": svc,
                "domain": host,
                "port": port,
                "protocol": proto,
                "error": err,
                "chain_incomplete": True
            })
            continue

        parsed = parse_certificate(data["cert"])
        if "error" in parsed:
            results.append({
                "service": svc,
                "domain": host,
                "port": port,
                "protocol": data["protocol"],
                "error": parsed["error"],
                "chain_incomplete": True
            })
            continue

        results.append({
            "service": svc,
            "domain": host,
            "port": port,
            "protocol": data["protocol"],
            "expires": parsed["expires"],
            "days_left": parsed["days_left"],
            "issuer": parsed["issuer"],
            "san": parsed["san"],
            "chain": parsed["chain"],
            "chain_incomplete": True,
            "alert": parsed["days_left"] <= alert_days
        })

    # Sort final
    return sorted(results, key=lambda r: (1 if "error" in r else 0, r.get("days_left", 999999)))
