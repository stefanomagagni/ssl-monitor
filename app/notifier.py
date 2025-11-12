import smtplib, requests, json
from email.mime.text import MIMEText

def send_email(subject, body, conf):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = conf["username"]
    msg["To"] = ", ".join(conf["to"])

    with smtplib.SMTP(conf["smtp_server"], conf["smtp_port"]) as server:
        server.starttls()
        server.login(conf["username"], conf["password"])
        server.send_message(msg)

def send_telegram(message, conf):
    url = f"https://api.telegram.org/bot{conf['bot_token']}/sendMessage"
    data = {"chat_id": conf["chat_id"], "text": message}
    requests.post(url, json=data)

def notify(results, config_path="app/config.json"):
    with open(config_path) as f:
        conf = json.load(f)

    alerts = [r for r in results if r.get("alert")]
    if not alerts:
        return

    msg = "\n".join([f"{r['domain']} scade tra {r['days_left']} giorni ({r['expires']})" for r in alerts])
    method = conf["notification"]["method"]

    if method == "email":
        send_email("Avviso scadenza certificati SSL", msg, conf["notification"]["email"])
    elif method == "telegram":
        send_telegram(f"⚠️ Certificati in scadenza:\n{msg}", conf["notification"]["telegram"])
