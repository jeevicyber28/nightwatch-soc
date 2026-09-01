import random
import time
from datetime import datetime
import os

LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/auth.log")
TARGET_IP = "192.168.1.10"
ATTACKER_IP = "10.0.0.666"

def write_log(message):
    with open(LOG_FILE, "a") as f:
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        log_entry = f"{timestamp} sshd[1234]: {message}\n"
        f.write(log_entry)
        print(f"[LOGGED] {log_entry.strip()}")

def simulate_brute_force():
    target_user = "root"
    print(f"[*] Starting Brute Force Attack on {target_user} from {ATTACKER_IP}...")
    
    # 1. Failed attempts (Trigger Threshold)
    for i in range(random.randint(6, 10)):
        write_log(f"Failed password for user {target_user} from {ATTACKER_IP} port 22 ssh2")
        time.sleep(0.1)
    
    # 2. Success (Potential Sequence Correlation)
    print(f"[!] SUCCESSFUL LOGIN DETECTED!")
    write_log(f"Accepted password for {target_user} from {ATTACKER_IP} port 22 ssh2")

if __name__ == "__main__":
    if not os.path.exists("../logs"):
        os.makedirs("../logs")
    simulate_brute_force()
