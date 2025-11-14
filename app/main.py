from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from .checker import check_domains
from .notifier import notify

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
def dashboard():
    results = check_domains()
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

            table {
                width: 94%;
                margin: 30px auto;
                border-collapse: collapse;
                background-color: rgba(0, 0, 0, 0.7);
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 5px 18px rgba(0,0,0,0.55);
            }

            th {
                background-color: rgba(255,255,255,0.18);
                padding: 14px;
                font-size: 1.1em;
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

        # -----------------------------------
        #   CASE 1 → ERROR ENTRY
        # -----------------------------------
        if "error" in r:
            html += f"""
            <tr>
                <td>{r.get('service','')}</td>
                <td>{r['domain']}</td>
                <td>{r.get('port','')}</td>
                <td colspan=5 class='error'>Errore: {r['error']}</td>
            </tr>"""
            continue

        # -----------------------------------
        #   CASE 2 → VALID CERTIFICATE
        # -----------------------------------
        color = "red" if r["alert"] else "lightgreen"

        issuer_preview = r["issuer"][:40] + "..." if len(r["issuer"]) > 40 else r["issuer"]

        san_preview = ", ".join(r["san"][:2])
        san_full = ", ".join(r["san"])

        if r.get("chain_incomplete", False):
            chain_icon = "<span class='chain-warning tooltip'>⚠<span>La chain del certificato è incompleta (manca CA intermedia)</span></span>"
        else:
            chain_icon = "<span style='color:lightgreen;font-size:1.3em;'>✔</span>"

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
