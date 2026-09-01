import json
import time
from datetime import datetime
import os

LOG_FILE = os.path.join(os.path.dirname(__file__), "../logs/web_access.log")
USER_IP = "10.0.0.50" # Valid employee IP
HR_SYSTEM = "/hr/payroll/db"
ENG_SYSTEM = "/eng/blueprints/secret"

def write_log(data):
    with open(LOG_FILE, "a") as f:
        log_entry = json.dumps(data) + "\n"
        f.write(log_entry)
        print(f"[LOGGED] {log_entry.strip()}")

def simulate_insider_threat():
    print(f"[*] Starting Insider Threat Simulation from {USER_IP}...")
    
    # 3 AM access (Unusual time) - handled by a rule looking at timestamps (not implemented yet, but good for logs)
    # Accessing multiple sensitive systems in scenarios
    
    targets = [HR_SYSTEM, ENG_SYSTEM, "/admin/keys"]
    
    for target in targets:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": USER_IP,
            "url": target,
            "user_agent": "Mozilla/5.0 (CorporateLaptop)",
            "status": 200,
            "method": "GET"
        }
        write_log(entry)
        time.sleep(0.5)

if __name__ == "__main__":
    if not os.path.exists("../logs"):
        os.makedirs("../logs")
    simulate_insider_threat()
