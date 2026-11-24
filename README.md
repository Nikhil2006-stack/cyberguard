# CYBERGUARD
## Live Ethical Hacking, AI-Powered Threat Detection & Defensive Cybersecurity Platform

> **"Think Like a Hacker. Defend Like a Professional."**

[![Python Version](https://img.shields.io/badge/Python-3.10%20|%203.11%20|%203.12%20|%203.14-blue.svg)](https://python.org)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.1-black.svg)](https://palletsprojects.com/p/flask/)
[![Database](https://img.shields.io/badge/Database-SQLite%203%20|%20SQLAlchemy-lightgrey.svg)](https://sqlite.org)
[![Tests](https://img.shields.io/badge/Tests-20%20Passed%20|%20100%25-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-Academic%20Lab%20Authorized-green.svg)]()

---

### Table of Contents
1. [Project Overview](#project-overview)
2. [Key Capabilities & Modules](#key-capabilities--modules)
3. [Technology Stack](#technology-stack)
4. [Modular Software Architecture](#modular-software-architecture)
5. [Installation & Windows Quick Start](#installation--windows-quick-start)
6. [Live Classroom Demonstration Workflow](#live-classroom-demonstration-workflow)
7. [Five-Member Team Responsibilities](#five-member-team-responsibilities)
8. [Automated Testing & Quality Assurance](#automated-testing--quality-assurance)
9. [Ethical Hacking Safety & Boundary Enforcement](#ethical-hacking-safety--boundary-enforcement)
10. [Companion Documentation](#companion-documentation)

---

## 1. Project Overview

**CYBERGUARD** is a live, interactive cybersecurity platform developed for classroom presentations and technical demonstrations. Unlike static mockups or slides, CYBERGUARD is an actual working multi-tier software application that demonstrates both **ATTACK** (ethical penetration testing) and **DEFENCE** (server-side authorization and threat detection) in an authorized, controlled laboratory environment.

Students and evaluators can connect in real-time from laptops and smartphones via a local classroom Wi-Fi hotspot to:
- Test suspicious links and emails in an explainable AI-assisted phishing detection engine.
- Decode and dissect QR codes safely without automatic URL execution (Quishing defence).
- Execute an **Insecure Direct Object Reference (IDOR/BOLA)** penetration test against a fictional college portal using **Burp Suite Community Edition**.
- Inspect live security events on a Security Operations Centre (SOC) dashboard.
- Generate auditable security assessment reports exportable to PDF.

---

## 2. Key Capabilities & Modules

| Module | Core Functionality | Real-World Application |
|---|---|---|
| **Module 1: SOC Dashboard** | Database-backed dynamic telemetry, Chart.js severity doughnut and 7-day activity trend, MITRE ATT&CK mapping. | Enterprise Security Operations Centre situational awareness. |
| **Module 2: Phishing Detection** | Explainable 0–100 risk scoring, urgency/panic parsing, credential harvesting detection, deep URL structural analysis, optional VirusTotal API. | Email security gateways (SEG) and anti-phishing mail filters. |
| **Module 3: QR Security Scanner** | Decodes QR images, flags malicious schemes (`javascript:`, `data:`), IP hostnames, and includes 3 pre-generated classroom demo QRs. | Countering Quishing (QR Phishing) campaigns on physical flyers. |
| **Module 4: Penetration Lab** | Fictional student portal comparing deliberately vulnerable IDOR endpoint (`/lab/vulnerable/profile/<id>`) vs secured endpoint (`/lab/secured/profile/<id>`). | Demonstrating OWASP Top 10 A01:2021 Broken Access Control / CWE-639. |
| **Module 5: Security Tools Centre** | Step-by-step verified walkthroughs for Burp Suite, OWASP ZAP, Wireshark, Nmap, and VirusTotal with genuine local socket status checks. | Tool-assisted offensive and defensive vulnerability auditing. |
| **Module 6: Network Monitoring** | Live event logging, severity filters, full technical trace inspector modal, 5-second dynamic polling. | Application Security Incident & Event Management (SIEM). |
| **Module 7: AI Security Analyst** | Multi-vector attack correlation (Quishing -> Credential Theft -> IDOR), root cause diagnostics, and patch verification. | Autonomous tier-1 security analyst reasoning. |
| **Module 8: Security Reports** | Executive summary, finding details, remediation proof, formal sign-off, printable HTML (1-click PDF export), and JSON export. | Formal penetration testing audit deliverables. |
| **Module 9: Settings & Hotspot** | Hotspot IP auto-detection, audience participation QR, VirusTotal API key configuration, and database reseeding. | Live presentation logistics and audience engagement. |

---

## 3. Technology Stack

- **Backend:** Python 3.10+, Flask 3.1, Flask-Login, Flask-SQLAlchemy, SQLAlchemy 2.0
- **Database:** SQLite 3 (stored locally in `instance/cyberguard.db`)
- **Frontend:** HTML5, CSS3 (SOC Dark Navy Theme), JavaScript (ES6+), Bootstrap 5.3, Bootstrap Icons, Chart.js 4.4
- **Image & QR Processing:** Pillow (PIL), `qrcode` library, OpenCV compatible decoder
- **Testing & QA:** `pytest` (20 automated unit and integration tests)
- **Supported Security Tools:** Burp Suite Community Edition, OWASP ZAP, Wireshark, Nmap, VirusTotal API

---

## 4. Modular Software Architecture

```
CYBERGUARD/
├── app.py                      # Application factory, route orchestration & database seeding
├── config.py                   # Central environment & session security configuration
├── database.py                 # SQLAlchemy and LoginManager instances
├── models.py                   # Database schemas (User, StudentProfile, SecurityEvent, etc.)
├── requirements.txt            # Python dependencies
├── run.bat                     # Windows 1-click double-clickable batch launcher
├── run.ps1                     # PowerShell startup script
│
├── modules/                    # Self-contained backend security engines
│   ├── phishing.py             # Explainable rule-based phishing engine & VT integration
│   ├── url_analyzer.py         # Deep URL syntactic, IP, and domain structure inspection
│   ├── qr_scanner.py           # QR decoding, payload risk evaluation & demo QR generator
│   ├── penetration_lab.py      # Dummy student portal (Vulnerable IDOR vs Secured endpoint)
│   ├── risk_engine.py          # Posture scoring (0-100) & MITRE ATT&CK correlation
│   ├── security_events.py      # Central event ingestion, aggregation & stats
│   ├── tool_integrations.py    # Burp, ZAP, Wireshark, Nmap & VT integration manager
│   └── report_generator.py     # Formal audit report compiler
│
├── templates/                  # Jinja2 responsive dark SOC HTML templates
│   ├── base.html               # Base layout, responsive sidebar & account switcher
│   ├── index.html              # Platform overview & classroom connect instructions
│   ├── dashboard.html          # SOC Dashboard with live Chart.js charts & metrics
│   ├── phishing.html           # Interactive phishing analysis console
│   ├── qr_scanner.html         # QR scanner & classroom demonstration codes
│   ├── penetration_lab.html    # IDOR lab with Burp Suite inspector simulator
│   ├── network_monitor.html    # Live security event stream & modal inspector
│   ├── ai_analyst.html         # Explainable threat correlation & patch advice
│   ├── tool_center.html        # Tool center walkthroughs & local port checker
│   ├── reports.html            # Audit report viewer
│   ├── report_printable.html   # Standalone printable report (Save as PDF)
│   ├── settings.html           # Classroom hotspot setup & settings
│   └── login.html              # Authentication screen with 1-click test credentials
│
├── static/
│   ├── css/style.css           # SOC Dark Theme CSS (#070c18, cyan glow, severity badges)
│   ├── js/
│   │   ├── dashboard.js        # Chart.js initialization & live updates
│   │   ├── phishing.js         # Phishing submission & evidence rendering
│   │   ├── qr_scanner.js       # QR image upload & sample evaluation
│   │   └── penetration_lab.js  # Live HTTP request dispatcher & verdict renderer
│   └── images/
│       └── sample_qrs/         # Auto-generated classroom demonstration QR codes
│
├── tests/                      # Automated test suite (Pytest)
│   ├── conftest.py             # Fixtures & authenticated client helpers
│   ├── test_phishing.py        # Phishing & URL analyzer test cases
│   ├── test_qr.py              # QR decoding & payload risk evaluation test cases
│   ├── test_authorization.py   # IDOR vulnerability & remediation verification tests
│   └── test_events.py          # Event logging & dashboard aggregation test cases
│
└── docs/                       # Educational documentation & Viva guides
    ├── VIVA_QUESTION_BANK.md
    ├── CLASSROOM_DEMO_GUIDE.md
    ├── TEAM_RESPONSIBILITIES_AND_SCRIPTS.md
    ├── SECURITY_TOOLS_GUIDE.md
    ├── TEST_REPORT.md
    ├── ACCOUNTS_AND_CREDENTIALS.md
    └── TROUBLESHOOTING.md
```

---

## 5. Installation & Windows Quick Start

### Prerequisites
- Windows 10 or 11
- Python 3.10 or higher (make sure *"Add Python to PATH"* is checked during installation)

### Option A: 1-Click Launch (Recommended for Windows)
1. Double-click `run.bat` (or right-click `run.ps1` and select *"Run with PowerShell"*).
2. The script will automatically verify dependencies, initialize the database, generate classroom demonstration QR codes, launch the server, and open your browser to `http://localhost:5000`.

### Option B: Manual Terminal Execution
```powershell
# 1. Open PowerShell or Command Prompt in the project folder
cd c:\Users\HP\Desktop\cyberguard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch application
python app.py
```

The application will display:
```
=================================================================
  CYBERGUARD: LIVE ETHICAL HACKING & DEFENCE PLATFORM
  Local Access:      http://localhost:5000
  Classroom Hotspot: http://192.168.1.X:5000
=================================================================
```

---

## 6. Live Classroom Demonstration Workflow

Follow this **10-Step Live Presentation Sequence** (approx. 15 minutes):

1. **Host Setup:** Turn on the Windows Mobile Hotspot on the host laptop. Launch `app.py`. Note the IP address (e.g. `192.168.137.1`).
2. **Audience Connect:** Classmates connect their phones to the host hotspot and navigate to `http://<host_ip>:5000`.
3. **Phishing Test:** Member 5 invites a classmate to click *"Sample 1: Account Suspension Lure"* in Phishing Detection. The engine analyzes urgency and shows an 85/100 Critical Risk score.
4. **QR Code Quishing:** A classmate scans the simulated phishing QR on their smartphone. CYBERGUARD decodes the payload, flags the raw IP and non-standard port 8080, and safely prevents automatic redirection.
5. **Dashboard Reflection:** Show that the live SOC Dashboard instantly incremented the event counters and phishing statistics.
6. **Enter Penetration Lab:** Switch to Student A (`student_a`). Explain the fictional student portal scenario.
7. **Burp Suite Interception:** Open Burp Suite Proxy. Send request `GET /lab/vulnerable/profile/1` to Burp Repeater.
8. **Demonstrate IDOR Exploit:** In Burp Repeater, tamper parameter `1` to `2`. Send request. Observe Student B's private PII, medical allergy note, and emergency contacts disclosed in 200 OK.
9. **Verify Remediation:** Change endpoint to `GET /lab/secured/profile/2`. Send request. The server strictly enforces server-side ownership (`current_user.id == profile.user_id`) and blocks the attack with **HTTP 403 Forbidden**.
10. **Report Sign-Off:** Navigate to Security Reports. Demonstrate the formal audit report with remediation sign-off and click *"Print / Save as PDF"*.

---

## 7. Five-Member Team Responsibilities

- **Member 1 (Project Leader & Integration):** Overall architecture, penetration testing lab coordination, Burp Suite live execution.
- **Member 2 (Backend & Database Architecture):** Flask application factory, SQLite/SQLAlchemy models, server-side ownership authorization enforcement.
- **Member 3 (Frontend & SOC Dashboard):** Dark theme UI, responsive mobile design, Chart.js live charts, event filter tables.
- **Member 4 (Security Tool Auditing):** OWASP ZAP scanning, Nmap port discovery, Wireshark packet capture analysis.
- **Member 5 (Threat Detection & Reporting):** Phishing rule engine, QR security scanner, VirusTotal integration, formal PDF report compilation.

*(Refer to [TEAM_RESPONSIBILITIES_AND_SCRIPTS.md](docs/TEAM_RESPONSIBILITIES_AND_SCRIPTS.md) for individual speaking scripts and teacher Q&A answers.)*

---

## 8. Automated Testing & Quality Assurance

Run the complete 20-test test suite anytime using:
```bash
python -m pytest tests/ -v
```

### Verified Test Categories:
- **Authentication:** Valid logins, session preservation, and invalid password rejections.
- **IDOR Vulnerability:** Confirms that the deliberately vulnerable endpoint reproduces unauthorized cross-user data leakage.
- **Remediation Enforcement:** Confirms that the secured endpoint strictly returns HTTP 403 Forbidden on mismatched ownership.
- **Phishing Engine:** Verifies high-urgency detection, credential bait classification, and low false-positive rates on benign notices.
- **QR Decoder:** Validates payload extraction across URLs, plain text CTF tokens, and malicious `javascript:` URI schemes.
- **Telemetry & SOC Metrics:** Confirms database event ingestion and correct arithmetic aggregation.

---

## 9. Ethical Hacking Safety & Boundary Enforcement

- **Strictly Localhost & Private Hotspot:** CYBERGUARD is strictly engineered for authorized local testing (`127.0.0.1` and private class hotspot).
- **Fabricated Dummy Data Only:** All student profiles (`student_a`, `student_b`) contain purely fabricated mock data (no real student PII).
- **No Remote Scanning:** Nmap instructions and port checks are strictly restricted to local host loopback interfaces.
- **Safe QR Dissection:** QR codes are decoded and inspected inside memory buffers; URLs are never automatically launched in the browser.

---

## 10. Companion Documentation

Detailed companion guides located in the `docs/` folder:
- [VIVA_QUESTION_BANK.md](docs/VIVA_QUESTION_BANK.md) &mdash; **100 Comprehensive Viva Questions & Answers**
- [CLASSROOM_DEMO_GUIDE.md](docs/CLASSROOM_DEMO_GUIDE.md) &mdash; **15-Minute Live Presentation Script & Hotspot Guide**
- [TEAM_RESPONSIBILITIES_AND_SCRIPTS.md](docs/TEAM_RESPONSIBILITIES_AND_SCRIPTS.md) &mdash; **Individual Member Roles & Scripts**
- [SECURITY_TOOLS_GUIDE.md](docs/SECURITY_TOOLS_GUIDE.md) &mdash; **Burp Suite, OWASP ZAP, Wireshark & Nmap Manual**
- [TEST_REPORT.md](docs/TEST_REPORT.md) &mdash; **Automated Test Results & Evidence**
- [ACCOUNTS_AND_CREDENTIALS.md](docs/ACCOUNTS_AND_CREDENTIALS.md) &mdash; **Demonstration Personas & Credentials**
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) &mdash; **Common Issues & Debugging Solutions**
