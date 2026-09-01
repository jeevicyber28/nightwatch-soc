from datetime import datetime

class EventNormalizer:
    """
    Normalizes parsed events into a standard schema (ECS-like).
    Schema:
        - event_type (authentication, web_traffic, system)
        - outcome (success, failure)
        - user
        - src_ip
        - timestamp (ISO 8601)
        - details (dict)
    """

    def normalize(self, raw_event, source_type):
        if source_type == "auth":
            return self._normalize_auth(raw_event)
        elif source_type == "web":
            return self._normalize_web(raw_event)
        return raw_event

    def _normalize_auth(self, event):
        # Event from Parser: timestamp, action, user, src_ip
        if "error" in event:
            return None

        outcome = "failure" if event['action'] == "failed" else "success"
        
        return {
            "event_type": "authentication",
            "outcome": outcome,
            "user": event.get('user'),
            "src_ip": event.get('src_ip'),
            "timestamp": event.get('timestamp'), # In real world, parse to ISO
            "details": {
                "raw_action": event['action']
            }
        }

    def _normalize_web(self, event):
        # Event from JSON: ip, url, status, method, user_agent
        if "error" in event:
            return None

        # Check for attack signatures in URL (Naive classification)
        details = {
            "method": event.get("method"),
            "user_agent": event.get("user_agent"),
            "url": event.get("url")
        }

        return {
            "event_type": "web_traffic",
            "outcome": "success" if event.get("status", 200) < 400 else "failure",
            "user": "unknown",
            "src_ip": event.get("ip"),
            "timestamp": event.get("timestamp"),
            "details": details
        }
