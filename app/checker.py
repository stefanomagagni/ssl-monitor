import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


def _handshake(host, port, context, timeout=5, use_sni=True):
    """
    Esegue una connessione TCP e un handshake TLS con il contesto passato.
    Ritorna (certificato, versione_tls) oppure solleva eccezioni.
    """
    conn = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_sni:
            sock = context.wrap_socket(conn, server_hostname=host)
        else:
            sock = context.wrap_socket(conn)

        version = sock.version() or ""  # Es: 'TLSv1.2'

        der = sock.getpeercert(binary_form=True)
        sock.close()

        if not der:
            raise ValueError("no_cert")

        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
        return cert, version

    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def fetch_tls_info(host, port, timeout=5):
    """
    Prova a connettersi e fare handshake TLS.

    Ritorna:
      - ({"cert": cert, "protocol": label}, None, None) se il certificato è stato ottenuto
      - (None, protocol_state, error_message) se qualcosa va storto

    protocol_state può essere:
      - "tls_modern", "tls_legacy", "ssl_obsolete"
      - "no_tls", "timeout", "refused", "unknown"
    """

    # 1️⃣ Verifica porta raggiungibile (TCP)
    try:
        conn = socket.create_connection((host, port), timeout=timeout)
        conn.close()
    except socket.timeout:
        return None, "timeout", "Timeout di connessione"
    except ConnectionRefusedError:
        return None, "refused", "Connessione rifiutata"
    except OSError as e:
        return None, "refused", f"Errore di connessione: {e}"

    # 2️⃣ Primo tentativo: TLS moderno (1.2/1.3 auto)
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        cert, version = _handshake(host, port, ctx, timeout=timeout, use_sni=True)

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

    except ssl.SSLError as e1:
        msg = str(e1).lower()

        # Tipico caso di porta non TLS
        if "wrong version number" in msg or "unknown protocol" in msg:
            return None, "no_tls", "Servizio non TLS sulla porta specificata"

        # 3️⃣ Fallback: TLS1.0 “vecchio” con ciphers deboli consentiti
        try:
            legacy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            legacy_ctx.check_hostname = False
            legacy_ctx.verify_mode = ssl.CERT_NONE

            # 👉 QUI LA DIFFERENZA IMPORTANTE:
            # abbassiamo il livello di sicurezza per permettere i cifrari legacy,
            # come fa `openssl s_client -tls1`
            try:
                legacy_ctx.set_ciphers("ALL:@SECLEVEL=0")
            except Exception:
                # Se l’OpenSSL sotto non capisce @SECLEVEL, ignora senza rompere
                pass

            cert, version = _handshake(
                host, port, legacy_ctx, timeout=timeout, use_sni=False
            )

            # Se arrivo qui HO il certificato: è TLS legacy
            return {"cert": cert, "protocol": "tls_legacy"}, None, None

        except ssl.SSLError as e2:
            msg2 = str(e2)
            # Porta parla qualcosa tipo SSL/TLS ma non riusciamo a completare
            return None, "no_tls", f"Errore SSL/TLS: {msg2}"

        except socket.timeout:
            return None, "timeout", "Timeout durante handshake"
        except Exception as e2:
            return None, "refused", f"Errore handshake legacy TLS1.0: {e2}"

    except socket.timeout:
        return None, "timeout", "Timeout durante handshake"
    except Exception as e:
        return None, "refused", f"Errore handshake: {e}"


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

        # ❌ Errore / timeout / no TLS / refused
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

        # ✅ OK
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

    def sort_key(r):
        if "error" in r:
            return (1, 999999)
        return (0, r.get("days_left", 999999))

    results.sort(key=sort_key)
    return results
