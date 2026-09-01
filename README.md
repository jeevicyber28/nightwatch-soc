# 🛡️ Nightwatch SOC

### Mini SIEM & Incident Response Platform

Nightwatch SOC is a lightweight security monitoring project designed to demonstrate how a Security Operations Center (SOC) can collect security events, detect suspicious activity, generate alerts, and investigate incidents.

The project focuses on the basic SOC workflow:

**Log → Normalize → Detect → Alert → Investigate → Respond**

---

## 🔍 Project Overview

Security teams deal with a large number of events every day. A SIEM helps collect and analyze these events to identify suspicious activity.

Nightwatch SOC simulates this process using security logs and detection rules. It provides a dashboard where security events and alerts can be monitored and investigated.

### Main workflow

```text
Security Logs
      ↓
Log Ingestion
      ↓
Normalization
      ↓
Detection Engine
      ↓
Correlation
      ↓
Security Alert
      ↓
Investigation
      ↓
Incident Response
```

---

## ✨ Features

* 📊 SOC monitoring dashboard
* 🔎 Security event monitoring and search
* 🚨 Alert generation and management
* 🛡️ Incident investigation workflow
* 🔐 Brute-force detection
* 👤 Account compromise detection
* 💻 Suspicious PowerShell detection
* 🌐 SQL injection detection
* 🚨 Suspicious IP activity detection
* 🔑 Privilege escalation detection
* 🧩 MITRE ATT&CK technique mapping
* 🌍 Local threat-intelligence lookup
* 🧪 Safe attack/telemetry simulations
* 💾 SQLite database persistence
* 🔌 Flask REST API
* 📱 Responsive dashboard

---

## 🧠 Detection Examples

### Brute Force

Multiple failed login attempts from the same source can trigger a brute-force alert.

```text
Failed Login
Failed Login
Failed Login
Failed Login
Failed Login
      ↓
🚨 Brute Force Alert
```

### Account Compromise

A series of failed logins followed by a successful login can indicate a possible account compromise.

```text
Failed Login × 5
       ↓
Successful Login
       ↓
🚨 Possible Account Compromise
```

---

## 🧪 Safe Attack Simulation

The project includes simulated security activity for testing the detection system.

Supported simulations:

```text
brute_force
web_attack
powershell
```

These simulations generate synthetic security telemetry locally. They are intended for testing and learning and do not perform attacks against real systems.

---

## 🖥️ Dashboard

The dashboard provides an overview of:

* Total events
* Active alerts
* Alert severity
* Open incidents
* Affected hosts
* Recent security activity

It also provides sections for:

**Alerts · Events · Incidents · Detection Rules · Threat Intelligence · MITRE ATT&CK**

---

## 🛠️ Technology Stack

| Component          | Technology            |
| ------------------ | --------------------- |
| Frontend           | HTML, CSS, JavaScript |
| Charts             | Chart.js              |
| Backend            | Python, Flask         |
| Database           | SQLite                |
| Detection          | Python + YAML rules   |
| Security Framework | MITRE ATT&CK          |

---

## 📂 Project Structure

```text
nightwatch-soc/
│
├── app.py
├── requirements.txt
│
├── dashboard/
│   └── index.html
│
├── engine/
│   ├── ingest.py
│   ├── parser.py
│   ├── normalize.py
│   └── detector.py
│
├── detections/
│   └── detection rules
│
├── red_team/
│   └── telemetry simulations
│
└── README.md
```

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/nightwatch-soc.git
cd nightwatch-soc
```

### 2. Create a virtual environment

**Windows:**

```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the application

```bash
python app.py
```

### 5. Open the dashboard

```text
http://127.0.0.1:5000
```

---

## 🎯 MITRE ATT&CK Coverage

| Detection              | MITRE Technique |
| ---------------------- | --------------- |
| Brute Force            | T1110           |
| Account Compromise     | T1078           |
| SQL Injection          | T1190           |
| PowerShell             | T1059.001       |
| Privilege Escalation   | T1068           |
| Suspicious IP Activity | T1071           |

---

## 📚 What I Learned

This project helped me understand practical SOC concepts including:

* Security log analysis
* SIEM architecture
* Detection engineering
* Event normalization
* Alert generation
* Event correlation
* Incident investigation
* Incident response
* MITRE ATT&CK mapping
* Basic threat intelligence

---

## ⚠️ Disclaimer

This project is intended for educational purposes, portfolio demonstration, and local security testing.

All attack simulations are synthetic and designed to generate test telemetry only.

---

## 📌 Project Status

**Status: Active Development**

Future improvements may include:

* More detection rules
* Real-time event monitoring
* Advanced threat intelligence
* Improved correlation
* Automated response recommendations
* Additional SOC investigation features

---

## License & Attribution

This project was developed using an existing Mini SIEM repository as a starting point. The original repository did not contain a declared license or license file. Any redistribution of adapted source code should therefore be reviewed for applicable licensing and attribution requirements.
