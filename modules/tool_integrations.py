import socket
import subprocess
import shutil
import os
import requests

class SecurityToolCenter:
    """
    Security Tool Center Integration & Laboratory Verification Manager.
    Evaluates real local environment status for Burp Suite, OWASP ZAP,
    Wireshark, Nmap, and VirusTotal without faking outputs.
    """

    @classmethod
    def check_port(cls, host, port, timeout=1.0):
        """Check if a network service/proxy port is actively listening locally."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((host, port))
                return result == 0
        except Exception:
            return False

    @classmethod
    def get_tool_statuses(cls, vt_key=None):
        """
        Inspect genuine environment status for all 5 professional cybersecurity tools.
        Reports actual binary detection on PATH and proxy socket listeners.
        """
        statuses = {}

        # 1. BURP SUITE COMMUNITY EDITION
        burp_listening = cls.check_port('127.0.0.1', 8080)
        statuses['burp'] = {
            'name': 'Burp Suite Community Edition',
            'role': 'Interception Proxy & Manual Penetration Testing',
            'installed_or_listening': burp_listening,
            'status_label': 'Proxy Active (127.0.0.1:8080)' if burp_listening else 'Proxy Inactive / Standby',
            'status_color': 'success' if burp_listening else 'secondary',
            'details': 'Burp Suite intercepts HTTP/HTTPS requests between browser and CYBERGUARD. Used to tamper with profile_id parameters during the IDOR demonstration.',
            'default_proxy': '127.0.0.1:8080',
            'quick_guide': [
                '1. Launch Burp Suite Community Edition on your laptop.',
                '2. Navigate to Proxy -> Intercept -> Turn "Intercept is on".',
                '3. Configure your browser proxy to 127.0.0.1:8080 or use Burp\'s built-in Chromium browser.',
                '4. Log into CYBERGUARD student portal as "student_a".',
                '5. In Burp HTTP history, find GET /lab/vulnerable/profile/1.',
                '6. Send request to Burp Repeater (Ctrl+R). Modify 1 to 2 and hit Send.',
                '7. Observe unauthorized disclosure of Student B\'s private data.'
            ]
        }

        # 2. OWASP ZAP (Zed Attack Proxy)
        zap_listening = cls.check_port('127.0.0.1', 8081) or cls.check_port('127.0.0.1', 8090)
        zap_port = 8081 if cls.check_port('127.0.0.1', 8081) else 8090
        statuses['zap'] = {
            'name': 'OWASP ZAP (Zed Attack Proxy)',
            'role': 'Automated DAST Scanner & Vulnerability Assessment',
            'installed_or_listening': zap_listening,
            'status_label': f'Active on 127.0.0.1:{zap_port}' if zap_listening else 'Standby / Ready for Scan',
            'status_color': 'success' if zap_listening else 'secondary',
            'details': 'OWASP ZAP automatically spiders the CYBERGUARD web endpoints, checks security headers (CSP, HSTS, X-Frame-Options), and flags missing server-side controls.',
            'default_proxy': '127.0.0.1:8080 or 8090',
            'quick_guide': [
                '1. Launch OWASP ZAP.',
                '2. In the "Automated Scan" prompt, enter: http://localhost:5000',
                '3. Click "Attack" to initiate passive spidering and endpoint discovery.',
                '4. Examine Alerts tab: Note absence of cache-control on sensitive profiles and IDOR parameter alerts.',
                '5. Export ZAP HTML Report for the team assessment archive.'
            ]
        }

        # 3. WIRESHARK
        tshark_path = shutil.which('tshark') or shutil.which('wireshark')
        statuses['wireshark'] = {
            'name': 'Wireshark Network Protocol Analyzer',
            'role': 'Packet Capture, Protocol Analysis & Cleartext Inspection',
            'installed_or_listening': bool(tshark_path),
            'status_label': 'Binary Detected on PATH' if tshark_path else 'Available via GUI on Host',
            'status_color': 'success' if tshark_path else 'info',
            'binary_path': tshark_path or 'Standard GUI installation',
            'details': 'Captures network frames on the classroom wireless hotspot or loopback adapter. Demonstrates how HTTP transmissions expose student credentials and session cookies in cleartext.',
            'quick_guide': [
                '1. Launch Wireshark as Administrator on the host laptop.',
                '2. Select the Adapter: "Adapter for loopback traffic capture" (for localhost) or "Wi-Fi" (for classroom hotspot).',
                '3. Apply capture filter: http or tcp.port == 5000',
                '4. Perform a login in CYBERGUARD.',
                '5. Right-click any HTTP packet in Wireshark -> Follow -> HTTP Stream.',
                '6. Explain to classmates how cleartext HTTP exposes session cookies and student IDs to anyone on the same Wi-Fi.'
            ]
        }

        # 4. NMAP
        nmap_path = shutil.which('nmap')
        statuses['nmap'] = {
            'name': 'Nmap Network Security Scanner',
            'role': 'Host Discovery, Port Scanning & Service Fingerprinting',
            'installed_or_listening': bool(nmap_path),
            'status_label': f'Installed ({nmap_path})' if nmap_path else 'CLI not in system PATH',
            'status_color': 'success' if nmap_path else 'warning',
            'binary_path': nmap_path or 'Not in PATH',
            'details': 'Performs controlled, authorized service enumeration against localhost:5000 and local classroom test interfaces.',
            'quick_guide': [
                '1. Open terminal / command prompt.',
                '2. Run authorized localhost scan: nmap -sT -sV -p 5000 127.0.0.1',
                '3. Observe open port 5000 running Werkzeug / Python web server.',
                '4. Run OS fingerprint test on lab machine: nmap -O 127.0.0.1 (requires Admin).',
                '5. Highlight to students: Never scan external or unauthorized networks without written permission.'
            ]
        }

        # 5. VIRUSTOTAL
        statuses['virustotal'] = {
            'name': 'VirusTotal Intelligence API',
            'role': 'Cloud Threat Intelligence & Domain Reputation',
            'installed_or_listening': bool(vt_key),
            'status_label': 'API Key Active' if vt_key else 'Offline Heuristic Mode (Key Optional)',
            'status_color': 'success' if vt_key else 'secondary',
            'details': 'Leverages 70+ antivirus and URL scanner engines to verify suspected phishing links detected by CYBERGUARD.',
            'quick_guide': [
                '1. Obtain a free API key from virustotal.com.',
                '2. Navigate to CYBERGUARD Settings page.',
                '3. Paste API key into the "VirusTotal API Key" field and click Save.',
                '4. Submit any suspicious link in Phishing Detection to view live multi-engine reputation data.'
            ]
        }

        return statuses

    @classmethod
    def execute_safe_local_port_check(cls, target_port=5000):
        """
        Safely check if the CYBERGUARD local server port is active
        and return socket inspection details for demonstration.
        """
        is_open = cls.check_port('127.0.0.1', target_port)
        return {
            'target': f'127.0.0.1:{target_port}',
            'status': 'OPEN / LISTENING' if is_open else 'CLOSED / UNREACHABLE',
            'service': 'CYBERGUARD Web Server' if target_port == 5000 else 'Custom Port',
            'timestamp': os.environ.get('TZ', 'Local')
        }
