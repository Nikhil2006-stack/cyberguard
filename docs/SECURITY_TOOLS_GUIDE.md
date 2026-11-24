# CYBERGUARD: Security Tool Integration & Laboratory Guide
## Hands-on Walkthrough for Burp Suite, OWASP ZAP, Wireshark, Nmap & VirusTotal

> **Target Environment:** `http://127.0.0.1:5000` (Localhost) and Private Classroom Hotspot  
> **Safety Notice:** All tests are strictly authorized for this local laboratory environment. Never scan or intercept external networks or systems without explicit written permission.

---

## 1. Burp Suite Community Edition: Manual IDOR Penetration Testing

### Objective:
Intercept, inspect, and modify the student profile request to achieve unauthorized access to another student's confidential profile (CWE-639 / BOLA), and subsequently verify the server-side fix.

### Step-by-Step Procedure:
1. **Launch Burp Suite:** Open Burp Suite Community Edition on your Windows laptop. Select **Temporary Project** -> **Use Burp defaults** -> **Start Burp**.
2. **Configure Proxy:**
   - Go to the **Proxy** tab -> **Proxy settings**.
   - Confirm that the proxy listener is bound to `127.0.0.1:8080` (Running).
3. **Open Browser:**
   - In Burp, go to **Proxy** -> **Intercept** -> Click **Open Browser** (Burp’s built-in Chromium browser, which routes all traffic through 127.0.0.1:8080 automatically).
4. **Authenticate as Student A:**
   - In the browser, navigate to `http://localhost:5000/login`.
   - Log in using username: `student_a`, password: `student_a_pass`.
5. **Intercept Request:**
   - In Burp, ensure **"Intercept is on"**.
   - In the browser, navigate to `http://localhost:5000/lab/` and click **"Request Profile #1"**.
   - Burp catches the outgoing HTTP request:
     ```http
     GET /lab/vulnerable/profile/1 HTTP/1.1
     Host: localhost:5000
     User-Agent: Mozilla/5.0 ...
     Cookie: session=...
     ```
6. **Send to Repeater:**
   - Right-click anywhere in the request pane and select **Send to Repeater** (or press <kbd>Ctrl+R</kbd>).
   - In Burp's Proxy tab, click **Intercept is on** to toggle it **OFF** so normal traffic flows.
7. **Exploit the Vulnerability in Repeater:**
   - Switch to the **Repeater** tab.
   - Edit the target parameter in the request line from `1` to `2`:
     ```http
     GET /lab/vulnerable/profile/2 HTTP/1.1
     Host: localhost:5000
     Cookie: session=...
     ```
   - Click **Send**.
   - Observe the HTTP response:
     ```http
     HTTP/1.1 200 OK
     Content-Type: application/json

     {
       "endpoint_status": "VULNERABLE",
       "idor_detected": true,
       "profile_data": {
         "full_name": "Bianca Chen",
         "student_id": "STU-2026-0922",
         "phone": "+1 (555) 019-8472",
         "emergency_contact": "Arthur Chen (Father) - +1 (555) 019-8479",
         "confidential_notes": "Holds Department Research Fellowship. Emergency medical alert: Severe penicillin allergy."
       }
     }
     ```
   - **Finding Confirmed:** Student A successfully accessed Student B's confidential records without authorization.
8. **Verify the Remediation:**
   - In Repeater, change the endpoint path to the secured route:
     ```http
     GET /lab/secured/profile/2 HTTP/1.1
     Host: localhost:5000
     Cookie: session=...
     ```
   - Click **Send**.
   - Observe the HTTP response:
     ```http
     HTTP/1.1 403 FORBIDDEN
     Content-Type: application/json

     {
       "endpoint_status": "SECURED",
       "code": 403,
       "message": "Access Denied: You do not possess authorization to view this student profile.",
       "security_control": "Server-Side Resource Ownership Verification enforced."
     }
     ```
   - **Remediation Confirmed:** The server-side ownership check strictly blocked the attack.

---

## 2. OWASP ZAP (Zed Attack Proxy): Automated Web Application Scanning

### Objective:
Perform automated crawling, passive security header inspection, and vulnerability identification against the CYBERGUARD local instance.

### Step-by-Step Procedure:
1. **Launch OWASP ZAP** on the host laptop.
2. In the central workspace, select **Automated Scan**.
3. Under **URL to attack**, enter:
   ```
   http://localhost:5000
   ```
4. Check **Use traditional spider**.
5. Click **Attack**.
6. **Analyze Findings in the Alerts Tab:**
   - **Missing Anti-Clickjacking Header:** ZAP flags that `X-Frame-Options` is not set on non-critical endpoints.
   - **Server Information Leaks:** ZAP notes `Server: Werkzeug/Python 3.14.0` in HTTP response headers.
   - **Sensitive Parameter Auditing:** ZAP identifies integer parameters in `/lab/vulnerable/profile/1`.
7. **Export Audit Report:**
   - In ZAP menu, click **Report** -> **Generate Report**.
   - Select HTML format and save to the team project archive.

---

## 3. Wireshark: Network Traffic Analysis & Cleartext Sniffing

### Objective:
Demonstrate how unencrypted HTTP traffic exposes sensitive student credentials and session tokens to any eavesdropper on the local classroom Wi-Fi hotspot.

### Step-by-Step Procedure:
1. **Launch Wireshark** as Administrator on the host laptop.
2. **Select Capture Interface:**
   - For localhost testing: Select **Adapter for loopback traffic capture**.
   - For classroom hotspot: Select your laptop's **Wi-Fi** adapter.
3. **Set Display Filter:**
   In the filter bar at the top, type:
   ```wireshark
   tcp.port == 5000 || http
   ```
   Press Enter.
4. **Generate Traffic:**
   - In your browser, log in to CYBERGUARD as `student_a`.
   - Access the profile and phishing analysis pages.
5. **Inspect Cleartext Frames in Wireshark:**
   - Locate an `HTTP POST /login` packet.
   - In the lower packet details pane, expand **Hypertext Transfer Protocol**.
   - Expand **HTML Form URL Encoded**.
   - Observe:
     ```
     username: student_a
     password: student_a_pass
     ```
   - Right-click any HTTP packet -> select **Follow** -> **HTTP Stream**.
   - The entire conversation (headers, session cookie, JSON profile response) is displayed in plaintext.
6. **Educational Takeaway:**
   Explain to classmates: *"This live packet capture proves why standard HTTP is unsafe over public or campus Wi-Fi networks and why production systems enforce HTTPS with TLS 1.3 encryption."*

---

## 4. Nmap: Authorized Network Discovery & Service Enumeration

### Objective:
Perform service fingerprinting and open-port discovery against our authorized local test target (`127.0.0.1`).

### Step-by-Step Procedure:
1. Open Command Prompt or PowerShell.
2. **Verify Nmap Installation:**
   ```powershell
   nmap --version
   ```
3. **Execute TCP Connect Port Scan against CYBERGUARD:**
   ```powershell
   nmap -sT -sV -p 5000 127.0.0.1
   ```
4. **Observe Output:**
   ```
   Starting Nmap 7.94 ( https://nmap.org )
   Nmap scan report for localhost (127.0.0.1)
   Host is up (0.00010s latency).

   PORT     STATE SERVICE VERSION
   5000/tcp open  http    Werkzeug httpd 3.1.8 (Python 3.14.0)

   Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
   Nmap done: 1 IP address (1 host up) scanned in 2.15 seconds
   ```
5. **Classroom Security Boundary Rule:**
   Remind students that Nmap should only ever be targeted at authorized, self-hosted systems or explicitly permitted lab environments (`127.0.0.1`).

---

## 5. VirusTotal API: Cloud Threat Intelligence Integration

### Objective:
Query cloud multi-engine reputation intelligence for suspected phishing links.

### Step-by-Step Procedure:
1. Obtain a free API key from [virustotal.com](https://www.virustotal.com) (free registration).
2. Open CYBERGUARD -> Navigate to **Settings** (`/settings`).
3. Paste the API key into the **VirusTotal API Key** input field.
4. Click **Save Configuration**.
5. Navigate to **Phishing Detection** (`/phishing`).
6. Submit any external link. If configured, CYBERGUARD issues a background REST API lookup to:
   ```
   https://www.virustotal.com/api/v3/urls/{url_id}
   ```
   and renders the live multi-engine detection ratio directly on the analysis card.
7. If no API key is provided, CYBERGUARD continues to operate seamlessly using its offline heuristic detection engine!
