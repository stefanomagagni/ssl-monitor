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

            .issuer {
                font-size: 0.85em;
                color: #e0e0e0;
                max-width: 250px;
                word-wrap: break-word;
            }

            .san {
                font-size: 0.75em;
                color: #ccc;
                max-width: 250px;
                word-wrap: break-word;
            }

            .chain-warning {
                color: orange;
                font-weight: bold;
                font-size: 1.3em;
            }

            .chain-ok {
                color: lightgreen;
                font-size: 1.3em;
                font-weight: bold;
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
        </header>

        <table>
            <tr>
                <th>Service</th>
                <th>Domain/IP</th>
                <th>Port</th>
                <th>Expires</th>
                <th>Days Left</th>
                <th>Issuer (CA)</th>
                <th>SAN</th>
                <th>Chain</th>
            </tr>
    """

    for r in results:
        if "error" in r:
            html += f"""
            <tr>
                <td>{r.get('service','')}</td>
                <td>{r['domain']}</td>
                <td>{r.get('port','')}</td>
                <td colspan="5" class="error">Errore: {r['error']}</td>
            </tr>"""
        else:
            # Colore semaforo: rosso / giallo / verde
            if r["days_left"] <= 0:
                color = "#ff4d4d"          # scaduto
            elif r.get("alert"):
                color = "#ffcc00"          # in alert
            else:
                color = "lightgreen"       # ok

            issuer_preview = r["issuer"][:40] + "..." if len(r["issuer"]) > 40 else r["issuer"]

            san_preview = ", ".join(r["san"][:2])
            san_full = ", ".join(r["san"])

            # Chain: se abbiamo chain_incomplete True → ⚠, altrimenti ✔
            if r.get("chain_incomplete"):
                chain_icon = (
                    "<span class='chain-warning tooltip'>⚠"
                    "<span>La chain del certificato potrebbe essere incompleta "
                    "(es. manca la CA intermedia), o non è stata validata completamente.</span>"
                    "</span>"
                )
            else:
                chain_icon = "<span class='chain-ok'>✔</span>"

            html += f"""
            <tr>
                <td>{r.get('service','')}</td>
                <td>{r['domain']}</td>
                <td>{r['port']}</td>
                <td>{r['expires']}</td>
                <td style="color:{color}; font-weight:bold;">{r['days_left']}</td>

                <td class='issuer tooltip'>
                    {issuer_preview}
                    <span>{r['issuer']}</span>
                </td>

                <td class='san tooltip'>
                    {san_preview}...
                    <span>{san_full}</span>
                </td>

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
    """Esporta lo stato corrente in CSV."""
    results = check_domains()
    results = sort_results(results)

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Service", "Domain", "Port", "Expires", "Days Left", "Issuer", "SAN", "Chain / Error"])

    for r in results:
        if "error" in r:
            writer.writerow([
                r.get("service", ""),
                r.get("domain", ""),
                r.get("port", ""),
                "",
                "",
                "",
                "",
                f"ERROR: {r['error']}",
            ])
        else:
            writer.writerow([
                r.get("service", ""),
                r.get("domain", ""),
                r.get("port", ""),
                r.get("expires", ""),
                r.get("days_left", ""),
                r.get("issuer", ""),
                "; ".join(r.get("san", [])),
                r.get("chain", ""),
            ])

    csv_data = output.getvalue()
    output.close()

    return PlainTextResponse(
        csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ssl_report.csv"'}
    )
