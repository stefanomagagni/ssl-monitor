from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from .checker import check_domains
from .notifier import notify

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
def dashboard():
    results = check_domains()
    notify(results)
    html = "<h1>SSL Monitor</h1><table border=1><tr><th>Domain</th><th>Expires</th><th>Days Left</th></tr>"
    for r in results:
        if "error" in r:
            html += f"<tr><td>{r['domain']}</td><td colspan=2 style='color:red;'>Errore: {r['error']}</td></tr>"
        else:
            color = "red" if r["alert"] else "green"
            html += f"<tr><td>{r['domain']}</td><td>{r['expires']}</td><td style='color:{color}'>{r['days_left']}</td></tr>"
    html += "</table>"
    return html
