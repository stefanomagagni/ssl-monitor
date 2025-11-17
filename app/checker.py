import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


def _connect_and_get_cert(host, port, ctx, timeout=5, use_sni=True):
    """
    Apre una connessione TCP, fa l'handshake TLS con il contesto dato
    e restituisce (certificato OpenSSL, versione TLS negoziata come stringa).

    Può sollevare:
      - socket.timeout
      - ConnectionRefusedError / OSError
      - ssl.SSLError
      - RuntimeError("no_cert") se non viene fornito alcun certificato
    """
    conn = socket.create_connection((host, port), timeout=timeout)
    try:
        server_hostname = host if use_sni else None
        sock = ctx.wrap_socket(conn, server_hostname=server_hostname)
        try:
            version = sock.version() or ""
            der = sock.getpeercert(binary_form=True)
        finally:
            sock.close()
    finally:
        conn.close()

    if not der:
        raise RuntimeError("no_cert")

    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
    return cert, version


def fetch_tls_info(host, port, timeout=5):
    """
    Prova a recuperare il certificato e classificare il protocollo.

    Ritorna SEMPRE una delle due forme:

    1) Certificato OK:
       ({ "cert": cert, "protocol": proto_label, "via_no_sni": bool }, None, None)

    2) Errore:
       (None, protocol_state, error_message)

       dove protocol_state ∈ {
         "tls_modern", "tls_legacy", "ssl_obsolete",
         "tcp_open_not_tls", "timeout", "refused", "no_tls", "unknown"
       }
    """
    # -------------------------------------------------------------
    # 1) PRIMO TENTATIVO: contesto moderno (TLS1.2/1.3)
    # -------------------------------------------------------------
    try:
        ctx_modern = ssl._create_unverified_context()
        ctx_modern.check_hostname = False
        ctx_modern.verify_mode = ssl.CERT_NONE

        cert, version = _connect_and_get_cert(host, port, ctx_modern, timeout=timeout, use_sni=True)

        version_low = (version or "").lower()
        if "tlsv1.3" in version_low or "tlsv1.2" in version_low:
            proto_label = "tls_modern"
        elif "tlsv1.1" in version_low or version_low == "tlsv1":
            proto_label = "tls_legacy"
        elif version_low.startswith("ssl"):
            proto_label = "ssl_obsolete"
        else:
            proto_label = "unknown"

        return {"cert": cert, "protocol": proto_label, "via_no_sni": False}, None, None

    except socket.timeout:
        # Timeout già a livello di handshake moderno
        return None, "timeout", "Timeout durante handshake"
    except ConnectionRefusedError:
        return None, "refused", "Connessione rifiutata"
    except OSError as e:
        # errore di rete / routing ecc.
        return None, "refused", f"Errore di connessione: {e}"
    except RuntimeError as e:
        if str(e) == "no_cert":
            return None, "no_tls", "Nessun certificato TLS disponibile"
        return None, "no_tls", f"Errore TLS: {e}"
    except ssl.SSLError as e_modern:
        # Qui può essere:
        #  - handshake_failure perché il server vuole solo TLS1.0 (es. AMCO)
        #  - oppure un vero problema TLS
        msg_modern = str(e_modern).lower()

        # ---------------------------------------------------------
        # 2) SE IL MODERNO FALLISCE → FALLBACK TLS1.0 (legacy)
        # ---------------------------------------------------------
        try:
            ctx_legacy = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            ctx_legacy.check_hostname = False
            ctx_legacy.verify_mode = ssl.CERT_NONE

            # 2a) prima prova con SNI
            try:
                cert, version = _connect_and_get_cert(host, port, ctx_legacy, timeout=timeout, use_sni=True)
                version_low = (version or "").lower()
                if version_low.startswith("ssl"):
                    proto_label = "ssl_obsolete"
                else:
                    # in pratica sarà TLSv1
                    proto_label = "tls_legacy"

                return {"cert": cert, "protocol": proto_label, "via_no_sni": False}, None, None

            except ssl.SSLError:
                # 2b) seconda prova SENZA SNI (NS2)
                try:
                    cert, version = _connect_and_get_cert(host, port, ctx_legacy, timeout=timeout, use_sni=False)
                    version_low = (version or "").lower()
                    if version_low.startswith("ssl"):
                        proto_label = "ssl_obsolete"
                    else:
                        proto_label = "tls_legacy"

                    # via_no_sni=True → lo useremo per aggiungere una nota in "chain"
                    return {"cert": cert, "protocol": proto_label, "via_no_sni": True}, None, None

                except ssl.SSLError as e_fallback:
                    msg_fallback = str(e_fallback).lower()
                    if "wrong version number" in msg_fallback or "unknown protocol" in msg_fallback:
                        return None, "tcp_open_not_tls", "Servizio non TLS sulla porta specificata"
                    return None, "no_tls", f"Errore TLS1.0: {e_fallback}"
                except socket.timeout:
                    return None, "timeout", "Timeout durante handshake (TLS1.0)"
                except ConnectionRefusedError:
                    return None, "refused", "Connessione rifiutata (TLS1.0)"
                except OSError as e_conn2:
                    return None, "refused", f"Errore di connessione (TLS1.0): {e_conn2}"
                except RuntimeError as e_no_cert2:
                    if str(e_no_cert2) == "no_cert":
                        return None, "no_tls", "Nessun certificato TLS disponibile (TLS1.0 senza SNI)"
                    return None, "no_tls", f"Errore TLS1.0 (no SNI): {e_no_cert2}"

        except Exception as e_legacy_setup:
            # Se addirittura non riusciamo a creare il contesto legacy
            # o qualcosa va molto storto: torniamo l'errore originale moderno.
            if "wrong version number" in msg_modern or "unknown protocol" in msg_modern:
                return None, "tcp_open_not_tls", "Servizio non TLS sulla porta specificata"
            return None, "no_tls", f"Errore SSL/TLS: {e_modern}"


def parse_certificate(cert):
    """Estrae dati dal certificato (anche se la chain è incompleta)."""
    try:
        expires = datetime.strptime(
            cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ"
        )
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

        # --- CASI DI ERRORE / NESSUN CERTIFICATO / TIMEOUT / NO TLS ---
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
        via_no_sni = data.get("via_no_sni", False)

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

        # Nota extra se siamo riusciti a collegarci SOLO senza SNI (NS2)
        chain_text = parsed["chain"]
        if via_no_sni:
            chain_text += " [handshake riuscito solo senza SNI]"

        results.append({
            "service": service,
            "domain": host,
            "port": port,
            "protocol": proto_label,
            "expires": parsed["expires"],
            "days_left": parsed["days_left"],
            "issuer": parsed["issuer"],
            "san": parsed["san"],
            "chain": chain_text,
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

    results.sort(key=sort_key)
    return results
