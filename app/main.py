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
                background-color: rgba(0, 0, 0, 0.6);
                padding: 20px;
            }
            header img {
                max-height: 80px;
            }
            h1 {
                margin-top: 10px;
                font-size: 2.5em;
            }
            table {
                width: 90%;
                margin: 30px auto;
                border-collapse: collapse;
                background-color: rgba(0, 0, 0, 0.7);
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5);
            }
            th, td {
                padding: 15px;
                text-align: center;
            }
            th {
                background-color: rgba(255, 255, 255, 0.2);
                font-size: 1.1em;
            }
            tr:nth-child(even) {
                background-color: rgba(255, 255, 255, 0.1);
            }
            tr:hover {
                background-color: rgba(255, 255, 255, 0.2);
            }
            .error {
                color: #ff8080;
                font-weight: bold;
            }
            .issuer {
                font-size: 0.9em;
                color: #ddd;
            }
            .san {
                font-size: 0.8em;
                color: #ccc;
            }
            footer {
                background-color: rgba(0, 0, 0, 0.6);
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
                <th>Domain</th>
                <th>Expires</th>
                <th>Days Left</th>
                <th>Issuer (CA)</th>
                <th>SAN</th>
            </tr>
    """

    for r in results:
        if "error" in r:
            html += f"""
            <tr>
                <td>{r['domain']}</td>
                <td colspan=4 class='error'>Errore: {r['error']}</td>
            </tr>"""
        else:
            color = "red" if r["alert"] else "lightgreen"
            html += f"""
            <tr>
                <td>{r['domain']}</td>
                <td>{r['expires']}</td>
                <td style='color:{color}'>{r['days_left']}</td>
                <td class='issuer'>{r['issuer']}</td>
                <td class='san'>{", ".join(r['san'])}</td>
            </tr>"""

    html += """
        </table>
        <footer>
            © 2025 Deda Next – Internal SSL Monitoring Dashboard
        </footer>
    </body>
    </html>
    """

    return html
