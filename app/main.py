from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from .checker import check_domains
from .notifier import notify
import io
import csv

app = FastAPI()


def sort_results(results):
    """Ordina per giorni rimanenti, mettendo gli errori in fondo."""
    def key_fn(r):
        if "error" in r:
            return (1, 999999)
        return (0, r.get("days_left", 999999))
    return sorted(results, key=key_fn)


@app.get("/", response_class=HTMLResponse)
def dashboard():
    results = check_domains()
    results = sort_results(results)
    notify(results)

    html = """
    <html>
    <head>
        <title>SSL Monitor</title>
        <style>
            body {
                background-image: url('https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1400&q=80');
                background-size: cover;
                background-position: center;
                background-attachment: fixed;
                color: white;
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                text-align: center;
            }

            header {
                background-color: rgba(0,0,0,0.65);
                padding: 20px;
            }
            header img {
                max-height: 80px;
            }
            h1 {
                margin-top: 10px;
                font-size: 2.7em;
            }

            .actions {
                margin-top: 10px;
            }

            .actions button {
                background-color: #1976d2;
                border: none;
                color: white;
                padding: 8px 16px;
                margin: 4px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 0.95em;
            }
            .actions button:hover {
                background-color: #12589a;
            }

            .legend {
                margin-top: 10px;
                background-color: rgba(0,0,0,0.55);
                display: inline-block;
                padding: 10px 22px;
                border-radius: 8px;
                font-size: 0.92em;
            }

            table {
                width: 94%;
                margin: 20px auto 40px auto;
                border-collapse: collapse;
                background-color: rgba(0, 0, 0, 0.7);
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 5px 18px rgba(0,0,0,0.55);
            }

            th {
                background-color: rgba(255,255,255,0.18);
                padding: 14px;
                font-size: 1.05em;
            }

            td {
                padding: 12px;
            }

            tr:nth-child(even) {
                background-color: rgba(255,255,255,0.08);
            }
            tr:hover {
                background-color: rgba(255,255,255,0.18);
            }

            .error {
                color: #ff8080;
                font-weight: bold;
                text-align: center;
            }

            .tooltip {
                position: relative;
                cursor: help;
            }
            .tooltip span {
                visibility: hidden;
                background-color: black;
                color: #fff;
                text-align: left;
                padding: 8px;
                border-radius: 5px;
                position: absolute;
                z-index: 1;
                width: 280px;
                left: 50%;
                transform: translateX(-50%);
                bottom: 130%;
                opacity: 0;
                transition: opacity 0.3s;
            }
            .tooltip:hover span {
                visibility: visible;
                opacity: 1;
            }

            footer {
                background-color: rgba(0,0,0,0.65);
                padding: 10px;
                position: fixed;
                bottom: 0;
                width: 100%;
                color: #ccc;
                font-size: 0.9em;
            }
        </style>
    </head>

    <body>
        <header>
            <img src="https://raw.githubusercontent.com/stefanomagagni/ssl-monitor/main/app/logo_deda.png" alt="Deda Next Logo">
            <h1>SSL Monitor</h1>
            <div class="actions">
                <button onclick="window.location.href='/export'">Esporta CSV</button>
            </div>
            <div class="legend">
                <b>Legenda:</b> &nbsp;
                🔵 Moderno (TLS ≥1.2) &nbsp; | &nbsp;
                🟡 Legacy (TLS 1.0 / 1.1) &nbsp; | &nbsp;
                🔴 Obsoleto / errore &nbsp; | &nbsp;
                ✔ Chain OK &nbsp; | &nbsp;
                ⚠ Chain incompleta
            </div>
        </header>

        <table>
            <tr>
                <th>Service</th>
                <th>Domain/IP</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Expires</th>
                <th>Days Left</th>
                <th>Issuer (CA)</th>
                <th>SAN</th>
                <th>Chain</th>
            </tr>
    """

    for r in results:
        if "error" in r:
            protocol_icon = "🔴"
            html += f"""
            <tr>
                <td>{r.get('service','')}</td>
                <td>{r['domain']}</td>
                <td>{r.get('port','')}</td>
                <td>{protocol_icon}</td>
                <td colspan="5" class="error">Errore: {r['error']}</td>
            </tr>"""
        else:
            # Protocol icon
            proto = r.get("protocol", "unknown")
            if proto in ("TLSv1.3", "TLSv1.2"):
                protocol_icon = "🔵"
            elif proto in ("TLSv1.1", "TLSv1.0"):
                protocol_icon = "🟡"
            else:
                protocol_icon = "🔴"

            # Semaforo colore date
            if r["days_left"] <= 0:
                color = "#ff4d4d"
            elif r.get("alert"):
                color = "#ffcc00"
            else:
                color = "lightgreen"

            issuer_preview = r["issuer"][:40] + "..." if len(r["issuer"]) > 40 else r["issuer"]
            san_preview = ", ".join(r["san"][:2])
            san_full = ", ".join(r["san"])

            chain_icon = "⚠" if r.get("chain_incomplete") else "✔"

            html += f"""
            <tr>
                <td>{r.get('service','')}</td>
                <td>{r['domain']}</td>
                <td>{r['port']}</td>
                <td>{protocol_icon}</td>
                <td>{r['expires']}</td>
                <td style="color:{color}; font-weight:bold;">{r['days_left']}</td>
                <td class='tooltip'>{issuer_preview}<span>{r['issuer']}</span></td>
                <td class='tooltip'>{san_preview}...<span>{san_full}</span></td>
                <td>{chain_icon}</td>
            </tr>
            """

    html += """
        </table>

        <footer>
            © 2025 Deda Next – Internal SSL Monitoring Dashboard
        </footer>
    </body>
    </html>
    """

    return html


@app.get("/export", response_class=PlainTextResponse)
def export_csv():
    results = check_domains()
    results = sort_results(results)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Service", "Domain", "Port", "Protocol", "Expires", "Days Left", "Issuer", "SAN", "Chain / Error"])

    for r in results:
        if "error" in r:
            writer.writerow([r.get("service",""), r.get("domain",""), r.get("port",""), "", "", "", "", "", f"ERROR: {r['error']}"])
        else:
            writer.writerow([
                r.get("service",""), r.get("domain",""), r.get("port",""), r.get("protocol",""),
                r.get("expires",""), r.get("days_left",""), r.get("issuer",""),
                "; ".join(r.get("san", [])), r.get("chain","")
            ])

    csv_data = output.getvalue()
    output.close()

    return PlainTextResponse(
        csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename=\"ssl_report.csv\"'}
    )
