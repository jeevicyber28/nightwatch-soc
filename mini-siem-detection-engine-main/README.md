# Nightwatch SOC

A lightweight **Mini SIEM and Incident Response Platform** built for security monitoring, detection engineering, and SOC analyst workflows.

Nightwatch demonstrates the complete security operations flow:

> **Log → Normalize → Detect → Alert → Investigate → Incident → Respond → Report**

## Features

- Modern SOC dashboard with green, yellow, and red severity indicators
- Security overview with event, alert, incident, and affected-host metrics
- Normalized authentication, web, process, network, and privilege events
- Detection rules for brute force, account compromise, SQL injection, suspicious PowerShell, suspicious IPs, and privilege escalation
- Alert management with New, Investigating, Resolved, and False Positive statuses
- Incident management with evidence, investigation notes, response actions, and resolution tracking
- MITRE ATT&CK technique mapping
- Local threat-intelligence lookup for IPs and domains
- Safe attack simulations that generate synthetic telemetry only
- SQLite persistence with a Flask REST API
- Responsive dashboard suitable for desktop and mobile screens

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript, Chart.js |
| Backend | Python, Flask, Flask-CORS |
| Database | SQLite |
| Detection | Python detection logic and YAML rule references |
| Framework | MITRE ATT&CK technique mapping |

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/mini-siem-soc-platform.git
cd mini-siem-soc-platform
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

The application automatically creates a local SQLite database and loads sample SOC telemetry on first run.

## Safe Attack Simulation

Use the **Simulate telemetry** button from the dashboard or call the API:

```bash
curl -X POST http://127.0.0.1:5000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"type":"brute_force"}'
```

Supported simulations include `brute_force`, `web_attack`, and `powershell`. These simulations create fake logs only and do not attack external systems.

## Project Structure

```text
app.py                 Flask API and SQLite application
requirements.txt       Python dependencies
dashboard/index.html   SOC dashboard interface
engine/                Ingestion, parsing, normalization, and detection modules
detections/            YAML detection rule references
red_team/              Safe synthetic telemetry generators
```

## MITRE ATT&CK Coverage

| Detection | Technique |
|---|---|
| Brute Force | T1110 |
| Account Compromise | T1078 |
| SQL Injection | T1190 |
| Suspicious PowerShell | T1059.001 |
| Privilege Escalation | T1068 |
| Suspicious IP Activity | T1071 |

## Disclaimer

This project is intended for education, portfolio demonstration, and local security testing. All attack simulations are synthetic and safe.

## License and Attribution

The original repository used as the starting point did not include a declared license or license file. The project has been substantially refactored and expanded into the Nightwatch SOC platform. Review licensing requirements before redistributing adapted source code.
