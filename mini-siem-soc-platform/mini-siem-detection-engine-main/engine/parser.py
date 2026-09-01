import re
import json

class LogParser:
    """
    Pure parsing logic. Converts raw strings to dictionaries.
    """
    
    def parse_auth(self, line):
        # Jan 13 21:15:00 sshd[1234]: Failed password for user root from 192.168.1.10 ...
        # Regex needs to handle: "for root", "for user root", "for invalid user root"
        pattern = r"^(\w+ \d+ \d+:\d+:\d+) .* (Failed|Accepted) password for (?:(?:invalid )?user )?(\w+) from ([\d\.]+)"
        match = re.search(pattern, line)
        if match:
            return {
                "timestamp": match.group(1),
                "action": match.group(2).lower(), # failed or accepted
                "user": match.group(3),
                "src_ip": match.group(4),
                "original_log": line
            }
        return {"original_log": line, "error": "parse_error"}

    def parse_web(self, line):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return {"original_log": line, "error": "json_error"}
