import json
import time
from datetime import datetime
import os

LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/web_access.log")
ATTACKER_IP = "10.0.0.666"

def write_log(data):
    with open(LOG_FILE, "a") as f:
        log_entry = json.dumps(data) + "\n"
        f.write(log_entry)
        print(f"[LOGGED] {log_entry.strip()}")

def simulate_sql_injection():
    print(f"[*] Starting SQL Injection Attack from {ATTACKER_IP}...")
    
    payloads = [
        "id=1",
        "id=1'",
        "id=1 OR 1=1",
        "id=1 UNION SELECT user, password FROM users",
        "id=1; DROP TABLE users"
    ]
    
    for payload in payloads:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": ATTACKER_IP,
            "url": f"/products?{payload}",
            "user_agent": "Mozilla/5.0 (HackerEdition)",
            "status": 200,
            "method": "GET"
        }
        write_log(entry)
        time.sleep(0.2)

if __name__ == "__main__":
    if not os.path.exists("../logs"):
        os.makedirs("../logs")
    simulate_sql_injection()
