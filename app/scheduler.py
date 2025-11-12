import time
import datetime
from .checker import check_domains
from .notifier import notify

print("📅 Avviato scheduler giornaliero SSL Monitor...")

while True:
    now = datetime.datetime.now()
    # Esegui ogni giorno alle 08:00
    if now.hour == 8 and now.minute == 0:
        print("🔔 Avvio controllo giornaliero certificati SSL...")
        results = check_domains()
        notify(results)
        print("✅ Controllo e notifica completati.")

        # Evita di reinviare più volte nello stesso minuto
        time.sleep(60)

    # Controlla ogni 30 secondi
    time.sleep(30)
