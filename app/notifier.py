import smtplib
from email.mime.text import MIMEText
import json
import os
import datetime

LAST_SENT_FILE = "/tmp/ssl_monitor_last_sent.txt"  # file per gestire invio giornaliero

# 📢 LISTA PERSONE DA "MENZIONARE" PER NOTIFICA TEAMS
TEAMS_MENTIONS = [
    "stefano.magagni@dedagroup.it",
    "luca.freisa@dedagroup.it",
    "stefano.ravetto@dedagroup.it"
]

def notify(results, config_path="app/config.json"):
    with open(config_path) as f:
        conf = json.load(f)

    email_conf = conf.get("notification", {}).get("email", {})
    if not email_conf.get("enabled", False):
        print("ℹ️  Email notifications are disabled.")
        return

    smtp_server = email_conf["smtp_server"]
    smtp_port = email_conf.get("smtp_port", 25)
    use_tls = email_conf.get("use_tls", False)
    sender = email_conf["from"]
    recipients = email_conf["to"]

    alerts = [r for r in results if r.get("alert")]
    if not alerts:
        print("✅ Nessun certificato in scadenza.")
        return

    # 📅 Controlla se è già stata inviata oggi
    today = datetime.date.today().isoformat()
    if os.path.exists(LAST_SENT_FILE):
        with open(LAST_SENT_FILE) as f:
            last_sent = f.read().strip()
        if last_sent == today:
            print("📧 Email già inviata oggi, salto l'invio.")
            return

    # 🟦 CREA STRINGA MENZIONI TEAMS
    mention_text = " ".join([f"@{m}" for m in TEAMS_MENTIONS])

    # 📨 SUBJECT CON MENZIONI
    msg_subject = f"⚠️ Avviso scadenza certificati SSL {mention_text}"

    # 💄 CORPO HTML
    html_body = f"""
    <html>
    <head>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        h2 {{ color: #d9534f; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even){{background-color: #f9f9f9;}}
        .danger {{ color: red; font-weight: bold; }}
        .ok {{ color: green; }}
    </style>
    </head>
    <body>
        <h2>⚠️ Avviso scadenza certificati SSL</h2>
        <p>I seguenti certificati stanno per scadere:</p>
        <table>
            <tr><th>Dominio</th><th>Data Scadenza</th><th>Giorni Rimasti</th></tr>
    """

    for r in alerts:
        clean_domain = r['domain'].replace("https://", "").replace("http://", "")
        color_class = "danger" if r["days_left"] <= 15 else "ok"
        html_body += f"<tr><td>{clean_domain}</td><td>{r['expires']}</td><td class='{color_class}'>{r['days_left']}</td></tr>"

    html_body += f"""
        </table>

        <p style="margin-top:20px;">
        🔔 Notifica Teams automatica inviata ai seguenti utenti:<br>
        {"<br>".join([f"@{m}" for m in TEAMS_MENTIONS])}
        </p>

        <p style="margin-top:20px;">Email generata automaticamente da <b>SSL Monitor</b>.</p>
    </body>
    </html>
    """

    msg = MIMEText(html_body, "html")
    msg["Subject"] = msg_subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            if use_tls:
                server.starttls()
            server.sendmail(sender, recipients, msg.as_string())

        with open(LAST_SENT_FILE, "w") as f:
            f.write(today)

        print("✅ Email HTML inviata con successo! (Teams notificherà i tag)")

    except Exception as e:
        print(f"❌ Errore nell'invio dell'email: {e}")
