import smtplib
from email.mime.text import MIMEText
import json

def notify(results, config_path="app/config.json"):
    with open(config_path) as f:
        conf = json.load(f)

    # sezione email
    email_conf = conf.get("email", {})
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

    # costruisci messaggio email
    subject = "⚠️ Avviso scadenza certificati SSL"
    body = "I seguenti certificati stanno per scadere:\n\n"
    for r in alerts:
        body += f"- {r['domain']} scade tra {r['days_left']} giorni ({r['expires']})\n"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            if use_tls:
                server.starttls()
            server.sendmail(sender, recipients, msg.as_string())
        print("✅ Email di avviso inviata con successo!")
    except Exception as e:
        print(f"❌ Errore nell'invio dell'email: {e}")
