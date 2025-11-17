import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


def _handshake_once(host, port, min_ver, max_ver, timeout=5, use_sni=True):
    """
    Esegue UNA prova di handshake TLS con:
      - range di versioni (min_ver / max_ver)
      - con o senza SNI.

    Ritorna:
      (cert, version_string) in caso di successo
      solleva eccezioni in caso di errore.
    """
    conn = None
    sock = None
    try:
        conn = socket.create_connection((host, port), timeout=timeout)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver

        server_name = host if use_sni else None
        sock = ctx.wrap_socket(conn, server_hostname=server_name)

        version = sock.version() or ""

        der = sock.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError("no_cert")

        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
        return cert, version

    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
        try:
            if conn:
                conn.close()
        except Exception:
            pass


def fetch_tls_info(host, port, timeout=5):
    """
    Prova handshake in questo ordine (opzione A: fallback SOLO se serve):

      1) TLS moderno -> min TLS1.2, max TLS1.3
      2) Se fallisce:
           2a) legacy TLS1.0 con SNI
           2b) legacy TLS1.0 senza SNI

    Ritorna:
      - ({"cert": cert, "protocol": label}, None, None) se OK
      - (None, protocol_state, error_msg) se errore

    protocol_state per gli errori:
      "no_tls", "timeout", "refused", "unknown"
    """
    # --- Definizione versioni ---
    # TLS moderno: 1.2 - max supportata
    min_modern = getattr(ssl.TLSVersion, "TLSv1_2", ssl.TLSVersion.MINIMUM_SUPPORTED)
    max_modern = getattr(ssl.TLSVersion, "TLSv1_3", ssl.TLSVersion.MAXIMUM_SUPPORTED)

    # TLS legacy: solo TLS1.0
    min_legacy = getattr(ssl.TLSVersion, "TLSv1", ssl.TLSVersion.MINIMUM_SUPPORTED)
    max_legacy = getattr(ssl.TLSVersion, "TLSv1", ssl.TLSVersion.MINIMUM_SUPPORTED)

    # ---------------------------
    # 1) TENTATIVO MODERNO
    # ---------------------------
    try:
        cert, version = _handshake_once(host, port, min_modern, max_modern, timeout=timeout, use_sni=True)

        # Classificazione versione
        v = (version or "").lower()
        if "tlsv1.3" in v or "tlsv1.2" in v:
            proto_label = "tls_modern"
        elif "tlsv1.1" in v or v == "tlsv1":
            proto_label = "tls_legacy"
        elif v.startswith("ssl"):
            proto_label = "ssl_obsolete"
        else:
            proto_label = "unknown"

        return {"cert": cert, "protocol": proto_label}, None, None

    except socket.timeout:
        return None, "timeout", "Timeout durante handshake"
    except ConnectionRefusedError:
        return None, "refused", "Connessione rifiutata"
    except ssl.SSLError as e:
        # NON torniamo errore subito: facciamo fallback legacy
        last_err_msg = str(e)
    except OSError as e:
        # errore generico di connessione → niente fallback TLS ha senso
        return None, "refused", f"Errore di connessione: {e}"
    except Exception as e:
        # generico: lo ricordiamo, ma proviamo comunque legacy
        last_err_msg = str(e)

    # ---------------------------
    # 2) FALLBACK LEGACY (TLS1.0)
    #    2a) con SNI, 2b) senza SNI
    # ---------------------------
    last_state = "no_tls"
    last_msg = f"Errore SSL/TLS: {last_err_msg}" if "last_err_msg" in locals() else "Errore SSL/TLS"

    for use_sni in (True, False):
        try:
            cert, version = _handshake_once(
                host, port, min_legacy, max_legacy, timeout=timeout, use_sni=use_sni
            )

            v = (version or "").lower()
            if "tlsv1.3" in v or "tlsv1.2" in v:
                proto_label = "tls_modern"
            elif "tlsv1.1" in v or v == "tlsv1":
                proto_label = "tls_legacy"
            elif v.startswith("ssl"):
                proto_label = "ssl_obsolete"
            else:
                proto_label = "unknown"

            return {"cert": cert, "protocol": proto_label}, None, None

        except socket.timeout:
            last_state = "timeout"
            last_msg = "Timeout durante handshake legacy"
        except ConnectionRefusedError:
            last_state = "refused"
            last_msg = "Connessione rifiutata (legacy)"
        except ssl.SSLError as e:
            msg = str(e).lower()
            # Porta aperta ma non parla TLS
            if "wrong version number" in msg or "unknown protocol" in msg:
                last_state = "no_tls"
                last_msg = "Servizio non TLS sulla porta specificata"
            else:
                last_state = "no_tls"
                last_msg = f"Errore SSL/TLS legacy: {e}"
        except RuntimeError as e:
            if "no_cert" in str(e).lower():
                last_state = "no_tls"
                last_msg = "Nessun certificato TLS disponibile"
            else:
                last_state = "unknown"
                last_msg = f"Errore legacy: {e}"
        except Exception as e:
            last_state = "unknown"
            last_msg = f"Errore durante handshake legacy: {e}"

    # Nessun tentativo ha avuto successo
    return None, last_state, last_msg


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
                "protocol": proto_state,   # es: no_tls / timeout / refused / unknown
                "error": err_msg,
                "chain_incomplete": True,
            })
            continue

        cert = data["cert"]
        proto_label = data["protocol"]  # tls_modern / tls_legacy / ssl_obsolete / unknown

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
