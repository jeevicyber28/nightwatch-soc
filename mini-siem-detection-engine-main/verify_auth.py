import os
from engine.ingest import LogIngestor
from engine.parser import LogParser
from engine.normalize import EventNormalizer
from engine.detector import DetectionEngine

def verify():
    # Running from soc-detection-engine/ dir
    log_dir = "logs"
    rules_dir = "detections"
    
    ingestor = LogIngestor(log_dir)
    parser = LogParser()
    normalizer = EventNormalizer()
    
    detector = DetectionEngine(rules_dir)

    print("--- Verifying Auth Logs ---")
    for line in ingestor.fetch_logs("auth.log"):
        print(f"RAW: {line.strip()}")
        parsed = parser.parse_auth(line)
        print(f"PARSED: {parsed}")
        
        if "error" in parsed:
            continue
            
        normalized = normalizer.normalize(parsed, "auth")
        print(f"NORMALIZED: {normalized}")
        
        matches = detector.detect(normalized)
        print(f"MATCHES: {matches}")
        print("-" * 20)

if __name__ == "__main__":
    verify()
