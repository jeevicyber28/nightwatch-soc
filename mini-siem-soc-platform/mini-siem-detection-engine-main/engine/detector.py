import yaml
import re
import os

class DetectionEngine:
    def __init__(self, rules_dir):
        self.rules = self._load_rules(rules_dir)

    def _load_rules(self, rules_dir):
        rules = []
        if not os.path.exists(rules_dir):
            return rules
        
        for filename in os.listdir(rules_dir):
            if filename.endswith(".yml") or filename.endswith(".yaml"):
                with open(os.path.join(rules_dir, filename), 'r') as f:
                    try:
                        rule = yaml.safe_load(f)
                        if rule:
                            rules.append(rule)
                    except yaml.YAMLError as e:
                        print(f"Error loading rule {filename}: {e}")
        return rules

    def detect(self, event):
        """
        Checks an event against all loaded rules.
        """
        matches = []
        for rule in self.rules:
            # check type: stateless vs threshold (handled by correlator, but matched here)
            # For now, we only alert on 'stateless' here or return match for correlator
            
            if self._evaluate_condition(rule.get('condition'), event):
                if not self._is_false_positive(rule.get('false_positives', []), event):
                    matches.append({
                        "rule_id": rule['id'],
                        "title": rule['title'],
                        "severity": rule['severity'],
                        "mitre": rule.get('mitre', {}),
                        "type": rule.get('type', 'stateless'),
                        "event": event
                    })
        return matches

    def _evaluate_condition(self, condition, event):
        if not condition:
            return False

        # Support 'field' and 'pattern' (Regex)
        field = condition.get('field')
        pattern = condition.get('pattern')

        # Support 'event_type' match (Exact match)
        cond_event_type = condition.get('event_type')
        
        if cond_event_type:
             if event.get('event_type') != cond_event_type:
                 return False
             # If event_type matches, check other constraints if they exist
             # For simpler rules, event_type match might be enough (though rare)
        
        if field and pattern:
            # Drill down into details if field is nested? 
            # For simplicity, flat or details.field
            value = self._get_field_value(event, field)
            if value and re.search(pattern, str(value), re.IGNORECASE):
                return True
        elif cond_event_type and not field:
            # Rule that just matches event type (e.g. for threshold counting elsewhere)
            return True

        return False

    def _get_field_value(self, event, field_path):
        # Allow dotted access: details.url
        parts = field_path.split('.')
        curr = event
        for p in parts:
            if isinstance(curr, dict):
                curr = curr.get(p)
            else:
                return None
        return curr

    def _is_false_positive(self, fps, event):
        """
        Checks if event matches any false positive definition.
        FP structure: list of conditions.
        """
        if not fps:
            return False
            
        for fp in fps:
            field = fp.get('field')
            pattern = fp.get('pattern')
            value = self._get_field_value(event, field)
            if value and re.search(pattern, str(value), re.IGNORECASE):
                return True
        return False
