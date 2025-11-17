from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from .checker import check_domains
from .notifier import notify
import io
import csv
from openpyxl import Workbook
from openpyxl.styles import PatternFill
import datetime
import os

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
            header img { max-height: 80px; }
            h1 { margin-top: 10px; font-size: 2.7em; }

            .actions { margin-top: 10px; }
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
            .actions button:hover { background-color: #12589a; }

            .tooltip { position: relative; cursor: help; }
            .tooltip span {
                visibility: hidden;
                background-color: black;
                color: #fff;
                text-align: left;
                padding: 8px;
                border-radius: 5px;
                position: absolute;
                z-index: 1;
                width: 260px;
                left: 50%;
                transform: translateX(-50%);
                bottom: 130%;
                opacity: 0;
                transition: opacity 0.3s;
            }
            .tooltip:hover span { visibility: visible; opacity: 1; }

            table {
                width: 94%;
                margin: 10px auto 40px auto;
                border-collapse: collapse;
                background-color: rgba(0, 0, 0, 0.7);
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 5px 18px rgba(0,0,0,0.55);
            }
            th { background-color: rgba(255,255,255,0.18); padding: 14px; font-size: 1.05em; }
            td { padding: 12px; }
            tr:nth-child(even){ background-color: rgba(255,255,255,0.08); }
            tr:hover { background-color: rgba(255,255,255,0.18); }

            .error { color: #ff8080; font-weight: bold; text-align: center; }

            .issuer, .san { font-size: 0.85em; color: #e0e0e0; max-width: 250px; word-wrap: break-word; }
            .san { font-size: 0.75em; color: #ccc; }

            .legend-container {
                margin-top: 5px; margin-bottom: 10px;
                background: rgba(0,0,0,0.55);
                display: inline-block;
                padding: 8px 18px;
                border-radius: 10px;
                font-size: 1.05em;
            }
            .legend-item { margin: 0 14px; display: inline-block; }
        </style>
    </head>

    <body>
        <header>
            <img src="https://raw.githubusercontent.com/stefanomagagni/ssl-monitor/main/app/logo_deda.png">
            <h1>SSL Monitor</h1>
            <div class="actions">
                <button onclick="window.location.href='/export'">Esporta CSV</button>
                <button onclick="window.location.href='/export_xlsx'">Esporta Excel</button>
            </div>
        </header>

        <div class="legend-container">
            <span class="legend-item tooltip">🟢 TLS moderno<span>Supporta TLS1.2 / TLS1.3</span></span>
            <span class="legend-item tooltip">🟠 TLS legacy<span>Protocollo TLS debole o datato</span></span>
            <span class="legend-item tooltip">🔴 SSL obsoleto<span>SSLv2/3 non sicuro o fuori standard</span></span>
            <span class="legend-item tooltip">⚪ Nessun certificato<span>Connessione non SSL/TLS</span></span>
        </div>

        <table>
            <tr>
                <th>Service</th><th>Domain/IP</th><th>Port</th><th>Protocol</th>
                <th>Expires</th><th>Days Left</th><th>Issuer (CA)</th><th>SAN</th><th>Chain</th>
            </tr>
    """

    for r in results:
        if "error" in r:
            protocol_icon = "⚪"
            html += f"""
            <tr>
                <td>{r.get('service')}</td><td>{r['domain']}</td><td>{r.get('port','')}</td>
                <td style='font-size:1.4em'>{protocol_icon}</td>
                <td colspan="5" class="error">Errore: {r['error']}</td>
            </tr>"""
        else:
            if r["days_left"] <= 0: color = "#ff4d4d"
            elif r.get("alert"): color = "#ffcc00"
            else: color = "lightgreen"

            proto = r.get("protocol")
            protocol_icon = {"tls_modern": "🟢", "tls_legacy": "🟠", "ssl_obsolete": "🔴"}.get(proto, "⚪")

            issuer_preview = r["issuer"][:40] + "..." if len(r["issuer"]) > 40 else r["issuer"]
            san_preview = ", ".join(r["san"][:2])
            san_full = ", ".join(r["san"])
            chain_icon = "<span style='color:orange;font-size:1.4em;font-weight:bold;'>⚠</span>" \
                if r.get("chain_incomplete") else "<span style='color:lightgreen;font-size:1.4em;font-weight:bold;'>✔</span>"

            html += f"""
            <tr>
                <td>{r.get('service')}</td><td>{r['domain']}</td><td>{r['port']}</td>
                <td style='font-size:1.4em'>{protocol_icon}</td>
                <td>{r['expires']}</td>
                <td style="color:{color}; font-weight:bold;">{r['days_left']}</td>
                <td class='issuer tooltip'>{issuer_preview}<span>{r['issuer']}</span></td>
                <td class='san tooltip'>{san_preview}...<span>{san_full}</span></td>
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

    writer.writerow(["Service", "Domain", "Port", "Protocol", "Expires", "Days Left", "Issuer", "SAN", "Chain/Error"])

    for r in results:
        if "error" in r:
            writer.writerow([r.get("service",""), r.get("domain",""), r.get("port",""), "NO TLS", "", "", "", "", f"ERROR: {r['error']}"])
        else:
            writer.writerow([
                r.get("service",""), r.get("domain",""), r.get("port",""),
                r.get("protocol",""), r.get("expires",""), r.get("days_left",""),
                r.get("issuer",""), "; ".join(r.get("san", [])), r.get("chain", "")
            ])

    csv_data = output.getvalue()
    output.close()
    return PlainTextResponse(csv_data, media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ssl_report.csv"'})


@app.get("/export_xlsx")
def export_xlsx():
    results = check_domains()
    results = sort_results(results)

    filename = f"ssl_report_{datetime.datetime.now().strftime('%Y-%m-%d')}.xlsx"
    filepath = f"/tmp/{filename}"

    wb = Workbook()
    ws = wb.active
    ws.title = "SSL Report"

    # Legend
    ws.append([
        "Legenda:", "🟢 TLS moderno", "🟠 TLS legacy",
        "🔴 SSL obsoleto", "⚪ Nessun certificato"
    ])
    ws.append([])

    headers = ["Service", "Domain", "Port", "Protocol", "Expires", "Days Left", "Issuer", "SAN", "Chain"]
    ws.append(headers)

    for r in results:
        if "error" in r:
            ws.append([
                r.get("service",""), r.get("domain",""), r.get("port",""),
                "NO TLS", "", "", "", "", f"ERROR: {r['error']}"
            ])
            continue

        row = [
            r.get("service",""), r.get("domain",""), r.get("port",""),
            r.get("protocol",""), r.get("expires",""), r.get("days_left",""),
            r.get("issuer",""), "; ".join(r.get("san", [])), r.get("chain","")
        ]
        ws.append(row)

        # color Days Left
        cell = ws[f"F{ws.max_row}"]
        days = r.get("days_left")

        if days is not None:
            if days <= 0:
                fill = PatternFill(start_color="FF0000", fill_type="solid")
            elif r.get("alert"):
                fill = PatternFill(start_color="FFA500", fill_type="solid")
            else:
                fill = PatternFill(start_color="00CC00", fill_type="solid")
            cell.fill = fill

    wb.save(filepath)
    return FileResponse(filepath, filename=filename, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
