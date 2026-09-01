import os
import json
import time
from ingest import LogIngestor
from parser import LogParser
from normalize import EventNormalizer
from detector import DetectionEngine
from correlator import CorrelationEngine

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
RULES_DIR = os.path.join(BASE_DIR, "detections")
ALERTS_FILE = os.path.join(BASE_DIR, "alerts", "alerts.json")

def main():
    print("[*] Starting SOC Detection Engine...")
    
    # Initialize Components
    ingestor = LogIngestor(LOG_DIR)
    parser = LogParser()
    normalizer = EventNormalizer()
    detector = DetectionEngine(RULES_DIR)
    correlator = CorrelationEngine()
    
    alerts = []

    # Process Auth Logs
    print("[*] Processing Auth Logs...")
    for line in ingestor.fetch_logs("auth.log"):
        parsed = parser.parse_auth(line)
        normalized = normalizer.normalize(parsed, "auth")
        
        if normalized:
            matches = detector.detect(normalized)
            for match in matches:
                correlated = correlator.process(match)
                if correlated:
                    print(f"[!] ALERT: {correlated['title']}")
                    alerts.append(correlated)

    # Process Web Logs
    print("[*] Processing Web Logs...")
    for line in ingestor.fetch_logs("web_access.log"):
        parsed = parser.parse_web(line)
        normalized = normalizer.normalize(parsed, "web")
        
        if normalized:
            matches = detector.detect(normalized)
            for match in matches:
                correlated = correlator.process(match)
                if correlated:
                    print(f"[!] ALERT: {correlated['title']}")
                    alerts.append(correlated)

    # Save Alerts
    print(f"[*] Saving {len(alerts)} alerts to {ALERTS_FILE}...")
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

if __name__ == "__main__":
    main()
