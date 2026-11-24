# CYBERGUARD: Five-Member Team Responsibilities & Speaking Scripts

---

## Team Roster & Module Ownership

| Member | Assigned Role | Primary Module Ownership | Tools Utilized |
|---|---|---|---|
| **Member 1** | **Project Leader & Penetration Tester** | Module 4 (Penetration Lab), Overall Integration, Architecture | Burp Suite Community Edition |
| **Member 2** | **Backend Engineer & Database Architect** | Flask Routing, SQLAlchemy ORM, Models, Access Control Logic | SQLite 3, Python 3.14, Werkzeug |
| **Member 3** | **Frontend Engineer & UI/UX Designer** | Module 1 (SOC Dashboard), Responsive Mobile Design, Chart.js | HTML5, CSS3, Bootstrap 5.3, Chart.js |
| **Member 4** | **Security Tools Specialist & Auditor** | Module 5 (Tool Centre), Module 6 (Monitoring), Protocol Inspection | OWASP ZAP, Wireshark, Nmap |
| **Member 5** | **Threat Detection Specialist & Reporter** | Module 2 (Phishing), Module 3 (QR Scanner), Module 8 (Reports) | Heuristic Rule Engine, Pillow, OpenCV, PDF Generator |

---

## Detailed Member Speaking Scripts & Viva Defense

---

### MEMBER 1: PROJECT LEADER & PENETRATION TESTER
- **Presentation Segment:** Minutes 0:00 – 2:00 (Introduction) and Minutes 8:30 – 11:00 (Burp Suite IDOR Live Attack).
- **Key Talking Points:**
  - Introduce CYBERGUARD: *"Think Like a Hacker. Defend Like a Professional."*
  - Explain why penetration testing requires controlled lab boundaries.
  - Walk the evaluators through intercepting `GET /lab/vulnerable/profile/1` in Burp Suite and modifying it to `/profile/2` in Burp Repeater.
- **Top 3 Teacher Questions for Member 1:**
  1. *Q: "What is an IDOR vulnerability and why is it dangerous?"*
     - **Answer:** "Insecure Direct Object Reference (CWE-639) occurs when an application exposes a reference to an internal database object directly in user input without verifying session ownership. It is dangerous because any authenticated user can enumerate IDs and dump the entire database."
  2. *Q: "Why did you use Burp Suite instead of just editing the URL in the browser?"*
     - **Answer:** "Burp Suite allows precise HTTP request inspection and header tampering. It shows that even if client-side validation or frontend links are hidden, an attacker can directly craft raw HTTP requests to exploit vulnerable server APIs."
  3. *Q: "What is the difference between Insecure Direct Object Reference (IDOR) and Broken Object Level Authorization (BOLA)?"*
     - **Answer:** "They represent the exact same root flaw: IDOR is the traditional web application term (CWE-639), whereas BOLA is the modern API term designated as #1 in the OWASP API Security Top 10."

---

### MEMBER 2: BACKEND ENGINEER & DATABASE ARCHITECT
- **Presentation Segment:** Minutes 11:00 – 12:00 (Remediation & Server-Side Authorization).
- **Key Talking Points:**
  - Explain the Flask application factory pattern (`create_app()`) and modular blueprints.
  - Explain database models: `User`, `StudentProfile`, `SecurityEvent`, and password hashing.
  - Walk through the exact code fix in `modules/penetration_lab.py`:
    ```python
    if profile.user_id != current_user.id and current_user.role != 'admin':
      return jsonify({'error': 'Access Denied'}), 403
```
- **Top 3 Teacher Questions for Member 2:**
  1. *Q: "How does the backend know who is currently logged in?"*
     - **Answer:** "Via Flask-Login and cryptographically signed session cookies. When a student logs in, their user ID is stored in a tamper-proof cookie signed with our `SECRET_KEY`. On every request, Flask-Login validates the signature and populates `current_user`."
  2. *Q: "Why did you use SQLite instead of MySQL or PostgreSQL?"*
     - **Answer:** "SQLite is zero-configuration, serverless, and self-contained in a single file (`instance/cyberguard.db`). It provides full ACID compliance and rapid performance for a classroom laboratory without requiring complicated server installations on student laptops."
  3. *Q: "Why is password hashing with Werkzeug secure?"*
     - **Answer:** "Werkzeug utilizes PBKDF2 with SHA-256 and generates a unique cryptographic salt per user. This prevents precomputed rainbow table attacks and ensures identical passwords result in completely different hashes in the database."

---

### MEMBER 3: FRONTEND ENGINEER & UI/UX DESIGNER
- **Presentation Segment:** Minutes 2:00 – 4:00 (Classroom Hotspot & Mobile Layout) and Minutes 12:00 – 13:00 (SOC Dashboard).
- **Key Talking Points:**
  - Explain the SOC Dark Navy aesthetic (`#070c18`, cyan glow, responsive Bootstrap 5 grid).
  - Demonstrate mobile responsiveness on smartphones connected via the classroom hotspot.
  - Explain Chart.js integration: severity distribution doughnut and 7-day activity line chart.
- **Top 3 Teacher Questions for Member 3:**
  1. *Q: "Are the dashboard numbers real or hardcoded?"*
     - **Answer:** "Every number is 100% genuine and queried directly from our SQLite database. When a phishing message or IDOR test is executed, the backend database row count increments, and our Chart.js charts reflect the update upon refresh."
  2. *Q: "How does the mobile responsiveness work?"*
     - **Answer:** "We utilized Bootstrap 5.3's flexbox grid system with responsive breakpoints (`col-sm-6`, `col-lg-3`), collapsible mobile navigation bars, and fluid canvas containers for Chart.js."
  3. *Q: "How does the Quick Account Switcher dropdown help the demonstration?"*
     - **Answer:** "In a live oral exam, typing passwords repeatedly slows down the demo. The switcher allows us to seamlessly swap active sessions between Student A (Attacker Persona) and Student B (Victim Persona) with one click."

---

### MEMBER 4: SECURITY TOOLS SPECIALIST & AUDITOR
- **Presentation Segment:** Minutes 13:00 – 14:00 (Security Tools & Protocol Inspection).
- **Key Talking Points:**
  - Explain the Security Tool Centre in Module 5.
  - Walk through how **Wireshark** packet captures inspect HTTP stream data.
  - Explain how **OWASP ZAP** spiders endpoints and flags missing security headers.
  - Explain authorized **Nmap** port discovery against `127.0.0.1`.
- **Top 3 Teacher Questions for Member 4:**
  1. *Q: "What did Wireshark reveal about HTTP traffic on the classroom hotspot?"*
     - **Answer:** "Wireshark demonstrated that over cleartext HTTP, session cookies, student IDs, and confidential profile JSON payloads travel unencrypted across the Wi-Fi network, proving why enterprise production environments mandate HTTPS."
  2. *Q: "What is the difference between an Nmap connect scan (`-sT`) and SYN scan (`-sS`)?"*
     - **Answer:** "The TCP Connect scan (`-sT`) completes the full 3-way handshake using standard operating system socket calls and requires no admin rights. The SYN stealth scan (`-sS`) sends raw SYN packets and tears down the connection with RST before completion, requiring administrator privileges."
  3. *Q: "What did OWASP ZAP find on our test portal?"*
     - **Answer:** "ZAP identified the lack of anti-caching headers on sensitive profile data, the absence of Content-Security-Policy (CSP), and mapped out the query parameters across `/lab/vulnerable/profile/`."

---

### MEMBER 5: THREAT DETECTION SPECIALIST & REPORTER
- **Presentation Segment:** Minutes 4:00 – 8:30 (Phishing & QR Scanner) and Minutes 14:00 – 15:00 (Reports).
- **Key Talking Points:**
  - Explain explainable heuristic phishing detection (urgency, credential harvesting, URL anomalies).
  - Demonstrate QR Code scanning and Quishing countermeasures.
  - Present the formal PDF/Printable Security Assessment Report in Module 8.
- **Top 3 Teacher Questions for Member 5:**
  1. *Q: "Why did you build an explainable rule-based engine instead of a deep learning model?"*
     - **Answer:** "In cybersecurity, explainability is essential. A black-box deep learning model cannot explain *why* it flagged an email. Our rule-based heuristic engine provides transparent weights: +20 for urgency, +25 for suspension threats, +40 for IP hostnames, giving auditable evidence for security analysts."
  2. *Q: "What is 'Quishing' and how does CYBERGUARD defend against it?"*
     - **Answer:** "Quishing is QR-code phishing. Attackers place malicious QR stickers over legitimate posters to bypass email filters. CYBERGUARD decodes the QR in memory, inspects the payload safely, and suppresses automatic browser redirection, preventing drive-by attacks."
  3. *Q: "How does your URL analyzer identify suspicious links?"*
     - **Answer:** "It checks for raw IP addresses, high-risk top-level domains (.xyz, .top), excessive subdomain depth, non-standard web ports like 8080, and embedded `@` symbols used to disguise the destination host."
