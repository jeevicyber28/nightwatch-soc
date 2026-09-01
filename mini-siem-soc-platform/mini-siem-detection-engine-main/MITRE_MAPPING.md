# MITRE ATT&CK Mapping

This document maps the detection rules in this project to the MITRE ATT&CK framework.

| ID | Rule Name | Tactic | Technique | Severity |
|----|-----------|--------|-----------|----------|
| DET-AUTH-001 | SSH Brute Force | Credential Access (TA0006) | Brute Force (T1110) | HIGH |
| DET-WEB-001 | SQL Injection | Initial Access (TA0001) | Exploit Public Facing Application (T1190) | HIGH |
| DET-WEB-002 | Directory Traversal | Initial Access (TA0001) | Exploit Public Facing Application (T1190) | MEDIUM |
| DET-SYS-001 | Privilege Escalation | Privilege Escalation (TA0004) | Sudo Caching (T1548.003) | HIGH |

## Coverage Summary
- **Initial Access**: 50%
- **Credential Access**: 25%
- **Privilege Escalation**: 25%

## Strategy
Our detection strategy focuses on the "Execution" and "Credential Access" stages of the kill chain, as these provide high-fidelity alerts with lower false positive rates compared to "Reconnaissance".
