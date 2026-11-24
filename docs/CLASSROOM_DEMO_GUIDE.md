# CYBERGUARD: 15-Minute Live Classroom Demonstration Guide

> **Target Presentation Time:** 15 Minutes  
> **Audience:** College Professors, Evaluators, and Classmates  
> **Hardware Setup:** 1 Host Laptop running Windows 10/11, connected to an authorized private Wi-Fi Mobile Hotspot.  
> **Participant Devices:** 10–30 student smartphones and laptops.

---

## 1. Pre-Presentation Checklist (10 Minutes Before Presentation)

- [ ] **Step 1:** Boot Host Laptop and ensure Python 3.10+ is working.
- [ ] **Step 2:** Open Windows Settings -> **Network & Internet** -> **Mobile hotspot**. Turn it **ON**.
  - Hotspot Network Name (SSID): e.g., `CYBERGUARD-LAB`
  - Hotspot Password: e.g., `CyberGuard2026!`
- [ ] **Step 3:** Open PowerShell or Command Prompt in `c:\Users\HP\Desktop\cyberguard`.
- [ ] **Step 4:** Launch the platform using:
  ```powershell
  python app.py
  ```
  Note the displayed IP address (e.g., `http://192.168.137.1:5000` or `http://192.168.1.105:5000`).
- [ ] **Step 5:** Open your laptop browser to `http://localhost:5000`.
- [ ] **Step 6:** Launch **Burp Suite Community Edition** in the background so it is ready for the IDOR demo.
- [ ] **Step 7:** (Optional) Launch **Wireshark** in the background, set to listen on the Wi-Fi/Loopback adapter.

---

## 2. Minute-by-Minute Demonstration Sequence (15-Minute Flow)

### Minutes 0:00 – 2:00: Platform Introduction & Tagline (Member 1 - Project Leader)
- **Action:** Project Leader displays the **CYBERGUARD Overview page** on the classroom projector.
- **Script:**
  > *"Good morning respected professors and classmates. Today our team presents **CYBERGUARD: Live Ethical Hacking, AI-Powered Threat Detection and Defensive Cybersecurity Platform**. Our core engineering philosophy is simple: **'Think Like a Hacker. Defend Like a Professional.'**
  >
  > This is not a static website or a slide deck. CYBERGUARD is an actual working cybersecurity software platform running on this host laptop, equipped with an active SQLite database, real-time threat detection algorithms, and deliberately vulnerable student portal endpoints created to demonstrate OWASP Top 10 vulnerabilities and defensive remediation live."*

---

### Minutes 2:00 – 4:00: Classroom Hotspot & Audience Participation (Member 3 - Frontend Lead)
- **Action:** Member 3 shows the top navbar and the Hotspot instruction card with the host IP.
- **Script:**
  > *"To demonstrate live engagement, we invite everyone in the front row to connect their smartphones to our private lab hotspot `CYBERGUARD-LAB` and navigate to `http://<host_ip>:5000`.
  >
  > When classmates submit scans, their telemetry will instantly feed into our live Security Operations Centre (SOC) Dashboard without requiring any external internet access."*

---

### Minutes 4:00 – 6:30: AI-Assisted Phishing Detection (Member 5 - Threat Detection Specialist)
- **Action:** Member 5 navigates to `/phishing` and clicks *"Sample 1: Account Suspension Lure"*, then hits **Analyze Threat**.
- **Script:**
  > *"Phishing remains the number-one initial access vector across higher education and enterprise networks. Here in Module 2, we have engineered an explainable threat detection engine.
  >
  > When we analyze this message: 'URGENT! Your college account will be suspended within 24 hours...', our engine doesn't just return a black-box guess. It breaks down the exact psychological triggers:
  > 1. Artificial urgency and deadline pressure (+20 risk points).
  > 2. Account suspension threats (+25 risk points).
  > 3. Embedded IP-based URL pointing to port 8080 (+40 risk points).
  >
  > The result is a transparent 85/100 Critical Risk score, accompanied by actionable recommendations telling the student never to enter credentials on raw IP addresses."*

---

### Minutes 6:30 – 8:30: QR Code Security & Quishing Defence (Member 5)
- **Action:** Member 5 navigates to `/qr-scanner` and displays the **Classroom Demonstration QR Pack**.
- **Script:**
  > *"Attackers now exploit physical QR codes (Quishing) on college bulletin boards to bypass email filters.
  >
  > In Module 3, our QR Security Scanner decodes images safely in an isolated memory buffer. Notice that when we test Demo QR #2, it decodes the suspicious URL, identifies the raw IP and port 8080, and strictly suppresses automatic browser redirection. We also include an educational CTF verification flag in Demo QR #3."*

---

### Minutes 8:30 – 12:00: THE CORE DEMO: Penetration Testing Lab & Burp Suite (Members 1 & 2)
- **Action:** Member 1 switches to `/lab/`. Points out Student A (Alex Rivera) and Student B (Bianca Chen).
- **Script (Member 1 - Ethical Hacker):**
  > *"Now for the most important module of our project: **Live Ethical Hacking and Penetration Testing**.
  >
  > We have constructed a fictional student portal with two accounts: Student A (User ID 2, Alex Rivera) and Student B (User ID 3, Bianca Chen).
  >
  > First, observe **Scenario A: The Deliberately Vulnerable Endpoint** (`/lab/vulnerable/profile/<id>`).
  > Student A is logged in. When Student A clicks 'Request Profile #1', they see their own data.
  >
  > Now, let us think like an attacker. In **Burp Suite Community Edition**, we intercept the outgoing HTTP request. We observe that the application blindly references the database record via a user-controlled parameter: `/profile/1`.
  >
  > We send this request to **Burp Repeater**. We tamper with the integer from `1` to `2` and hit Send.
  >
  > Look at the response: **HTTP 200 OK**. The server immediately dumps Student B's complete confidential profile—including Bianca Chen's private phone number, emergency contact, and sensitive medical notes! This is a textbook **Insecure Direct Object Reference (CWE-639 / BOLA)**."*

- **Script (Member 2 - Backend Architect):**
  > *"Now, how does a professional software engineer defend against this?
  >
  > We do not rely on hiding the button in HTML. In **Scenario B: The Secured Endpoint** (`/lab/secured/profile/<id>`), we implement server-side resource ownership verification:
  >
  > On every request, the backend extracts `current_user.id` from the cryptographically signed session cookie and verifies:
  > `if profile.user_id != current_user.id and current_user.role != 'admin': return 403 Forbidden`.
  >
  > Let us repeat the exact same attack against the secured endpoint in Burp Suite: `GET /lab/secured/profile/2`.
  >
  > Look at the result: **HTTP 403 Forbidden (Access Denied)**. Unauthorized access is completely blocked, and an unauthorized access attempt event is immediately dispatched to our SOC monitoring engine."*

---

### Minutes 12:00 – 13:30: SOC Dashboard & Network Monitoring (Member 3 & Member 4)
- **Action:** Member 3 opens `/dashboard` and `/network-monitor`.
- **Script (Member 3):**
  > *"Notice that our Security Operations Centre dashboard has live-updated. The total security events counter incremented, the severity doughnut chart shows the critical IDOR exploit attempt we just triggered, and our MITRE ATT&CK matrix reflects active technique T1068."*
- **Script (Member 4 - Tools Specialist):**
  > *"In Module 5 (Security Tool Centre), we have documented genuine workflows for **Wireshark** cleartext traffic analysis, **OWASP ZAP** automated spidering, and **Nmap** port discovery against our authorized lab target."*

---

### Minutes 13:30 – 15:00: Formal Security Report & Conclusion (Project Leader)
- **Action:** Member 1 opens `/reports` and clicks *"Print / Save as PDF"* to show the printable report dialog.
- **Script (Project Leader):**
  > *"Finally, in Module 8, CYBERGUARD compiles all laboratory findings into a formal Security Assessment Report—complete with executive summaries, CWE citations, remediation sign-off, and one-click PDF export for institutional compliance.
  >
  > All 20 automated unit and integration tests pass with 100% deterministic reliability in Pytest.
  >
  > Thank you, professors and classmates. We are now ready for your questions!"*

---

## 3. Emergency Backup Procedures (If Anything Goes Wrong)

| Issue | Quick Fix |
|---|---|
| **Classroom Wi-Fi fails** | Everything is 100% offline! Use `http://localhost:5000` on the laptop; zero internet connection is required. |
| **Hotspot IP changes** | The top navbar automatically displays the current detected IP; students just need to enter the updated IP. |
| **Burp Suite proxy isn't open** | Use our built-in **HTTP Inspector Simulator** directly on `penetration_lab.html`! It displays the exact raw HTTP request and response on screen without needing external software. |
| **Database gets cluttered** | Navigate to Settings (`/settings`) and click **"Reseed DB"** to reset to clean demo baseline in 1 second. |
