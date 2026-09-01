import time
from datetime import datetime

class CorrelationEngine:
    def __init__(self):
        # Store active state for threshold rules
        # Structure: { rule_id: { group_key: [timestamps] } }
        self.threshold_state = {}
        
        # Store recent high-risk alerts for sequence correlation
        # Structure: [ {alert, timestamp} ]
        self.alert_history = []

    def process(self, raw_alert):
        """
        Takes a raw alert (match) from Detector.
        Returns a "Correlated Alert" if a threshold or sequence is met.
        Otherwise triggers internal state updates.
        """
        rule_type = raw_alert.get('type')
        
        if rule_type == 'stateless':
            # Pass-through, but also store for sequence correlation
            self.alert_history.append({
                "alert": raw_alert,
                "timestamp": time.time()
            })
            return raw_alert

        elif rule_type == 'threshold':
            return self._process_threshold(raw_alert)

        return None

    def _process_threshold(self, alert):
        """
        Handles 'threshold' type rules (e.g. 5 fails in 5 mins).
        """
        rule_id = alert['rule_id']
        # We need the config from the rule (simulated passing it in alert or looking up)
        # For this PoC, we assume the detector passes the threshold config matches or we handle it here.
        # Ideally Detector shouldn't fire for 'threshold' types unless it's just passing the event.
        # A Better design: Detector passes ALL qualifying events to Correlator.
        
        # NOTE: In our design, Detector returns a match if the SINGLE event condition is met.
        event = alert['event']
        
        # Hardcoding logic for the DET-AUTH-001 example for simplicity
        # In a real engine, we'd parse rule['threshold_config']
        if rule_id == 'DET-AUTH-001':
            return self._check_brute_force_threshold(alert)
            
        return None

    def _check_brute_force_threshold(self, alert):
        # Config: 5 fails in 300s by src_ip
        src_ip = alert['event'].get('src_ip')
        if not src_ip: 
            return None

        key = f"DET-AUTH-001|{src_ip}"
        
        if key not in self.threshold_state:
            self.threshold_state[key] = []
        
        now = time.time()
        # Add current event time
        self.threshold_state[key].append(now)
        
        # Prune old events (older than 300s)
        self.threshold_state[key] = [t for t in self.threshold_state[key] if now - t <= 300]
        
        if len(self.threshold_state[key]) >= 5:
            # Threshold Met!
            # Reset state to avoid spamming alerts for the same burst? 
            # Or keep sliding? Let's clear for now.
            self.threshold_state[key] = []
            
            alert['title'] = "CONFIRMED Brute Force Attack"
            alert['severity'] = "HIGH"
            alert['correlation_notes'] = f"5+ failed logins from {src_ip} in 5 minutes"
            return alert
            
        return None
