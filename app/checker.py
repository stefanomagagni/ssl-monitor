import ssl
import socket
from datetime import datetime
from OpenSSL import crypto


def try_tls(host, port, protocol, timeout=5, use_sni=True):
    """
    Esegue handshake con protocollo specifico.
    protocol può essere:
      - ssl.PROTOCOL_TLS_CLIENT → moderno
      - ssl.PROTOCOL_TLSv1      → TLS 1.0 legacy
    """
    conn = None
    sock = None
    try:
        conn = socket.create_connection((host, port), timeout=timeout)

        ctx = ssl.SSLContext(protocol)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # ⚠️ Per TLS 1.0 abbassiamo il security level,
        # altrimenti molti vecchi server rispondono con "internal error"
        if protocol == ssl.PROTOCOL_TLSv1:
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except Exception:
                # Se per qualche motivo fallisce, andiamo comunque avanti
                pass

        # SNI solo se richiesto
        server_name = host if use_sni else None
        sock = ctx.wrap_socket(conn, server_hostname=server_name)

        version = sock.version() or ""  # es: "TLSv1", "TLSv1.2"
        der = sock.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError("no_cert")

        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der)
        return cert, version

    finally:
        try:
            if sock:
                sock.close()
        except:
            pass
        try:
            if conn:
                conn.close()
        except:
            pass


def fetch_tls_info(host, port, timeout=5):
    """
    1️⃣ Prova TLS moderno (TLS1.2/1.3) con PROTOCOL_TLS_CLIENT
    2️⃣ Se fallisce, prova TLS1.0 legacy (con SNI e poi senza), con SECLEVEL=0
    """
    # ----------------
    # 1) TENTATIVO MODERNO
    # ----------------
    try:
        cert, version = try_tls(
            host,
            port,
            ssl.PROTOCOL_TLS_CLIENT,
            timeout=timeout,
            use_sni=True
        )

        v = version.lower()
        if "tlsv1.3" in v or "tlsv1.2" in v:
            proto = "tls_modern"
        elif "tlsv1.1" in v or v == "tlsv1":
            proto = "tls_legacy"
        elif v.startswith("ssl"):
            proto = "ssl_obsolete"
        else:
            proto = "unknown"

        return {"cert": cert, "protocol": proto}, None, None

    except socket.timeout:
        return None, "timeout", "Timeout durante handshake"
    except ConnectionRefusedError:
        return None, "refused", "Connessione rifiutata"
    except Exception as modern_err:
        last_state = "no_tls"
        last_err = f"Errore TLS moderno: {modern_err}"

    # ----------------
    # 2) FALLBACK TLS1.0 LEGACY (con e senza SNI)
    # ----------------
    for use_sni in (True, False):
        try:
            cert, version = try_tls(
                host,
                port,
                ssl.PROTOCOL_TLSv1,
                timeout=timeout,
                use_sni=use_sni
            )

            v = version.lower()
            if "tlsv1" in v:
                proto = "tls_legacy"
            elif v.startswith("ssl"):
                proto = "ssl_obsolete"
            else:
                proto = "unknown"

            return {"cert": cert, "protocol": proto}, None, None

        except socket.timeout:
            last_state = "timeout"
            last_err = "Timeout durante handshake legacy"
        except ConnectionRefusedError:
            last_state = "refused"
            last_err = "Connessione rifiutata (legacy)"
        except RuntimeError:
            last_state = "no_tls"
            last_err = "Nessun certificato TLS disponibile"
        except ssl.SSLError as e:
            last_state = "no_tls"
            last_err = f"Errore TLS1.0: {e}"
        except Exception as e:
            last_state = "no_tls"
            last_err = f"Errore TLS1.0: {e}"

    # Se siamo qui, tutti i tentativi legacy sono falliti
    return None, last_state, last_err


def parse_certificate(cert):
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
            "chain": "⚠ chain non validata",
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

        # Errore / nessun certificato / timeout / rifiutata
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

        parsed = parse_certificate(data["cert"])

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

    # Ordina: prima OK, poi errori
    def sort_key(r):
        if "error" in r:
            return (1, 999999)
        return (0, r.get("days_left", 999999))

    results.sort(key=sort_key)
    return results
