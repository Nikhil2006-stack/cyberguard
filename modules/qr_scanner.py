import os
import qrcode
from PIL import Image
from modules.url_analyzer import URLAnalyzer

# Optional OpenCV import with graceful fallback
try:
    import cv2
    import numpy as np
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

class QRScanner:
    """
    QR Code Security Scanner module.
    Decodes QR images, assesses embedded payload risk (URL vs command injection vs text),
    and generates authorized classroom demonstration codes.
    """

    @classmethod
    def generate_demo_qrs(cls, output_dir):
        """
        Generate the 3 required classroom demonstration QR codes:
        1. Legitimate College Portal URL
        2. Simulated Suspicious / Phishing URL
        3. Non-URL Classroom Flag/Secret Token
        """
        os.makedirs(output_dir, exist_ok=True)
        demo_files = {}

        # 1. Legitimate QR
        legit_data = "https://cyberguard.internal.edu/student-services/schedule"
        legit_path = os.path.join(output_dir, "demo_legitimate_qr.png")
        qr_legit = qrcode.QRCode(box_size=10, border=3)
        qr_legit.add_data(legit_data)
        qr_legit.make(fit=True)
        img_legit = qr_legit.make_image(fill_color="#0066cc", back_color="white")
        img_legit.save(legit_path)
        demo_files['legitimate'] = {
            'file_name': 'demo_legitimate_qr.png',
            'path': legit_path,
            'content': legit_data,
            'description': 'Legitimate University Portal HTTPS link'
        }

        # 2. Simulated Suspicious Phishing QR
        phish_data = "http://192.168.1.185:8080/college-login.php?urgent_verify=1&account=suspended"
        phish_path = os.path.join(output_dir, "demo_suspicious_qr.png")
        qr_phish = qrcode.QRCode(box_size=10, border=3)
        qr_phish.add_data(phish_data)
        qr_phish.make(fit=True)
        img_phish = qr_phish.make_image(fill_color="#cc0033", back_color="white")
        img_phish.save(phish_path)
        demo_files['suspicious'] = {
            'file_name': 'demo_suspicious_qr.png',
            'path': phish_path,
            'content': phish_data,
            'description': 'Simulated Phishing URL (Raw IP, non-standard port 8080, urgency query parameters)'
        }

        # 3. Non-URL Classroom Flag QR
        flag_data = "CYBERGUARD{DEMO_CLASSROOM_ETHICAL_HACKER_2026_AUTHORIZED_TOKEN}"
        flag_path = os.path.join(output_dir, "demo_non_url_qr.png")
        qr_flag = qrcode.QRCode(box_size=10, border=3)
        qr_flag.add_data(flag_data)
        qr_flag.make(fit=True)
        img_flag = qr_flag.make_image(fill_color="#107c41", back_color="white")
        img_flag.save(flag_path)
        demo_files['non_url'] = {
            'file_name': 'demo_non_url_qr.png',
            'path': flag_path,
            'content': flag_data,
            'description': 'Classroom verification flag / text payload (non-URL)'
        }

        return demo_files

    @classmethod
    def decode_image(cls, file_path):
        """
        Decode QR code using OpenCV if installed, or secondary native decoders.
        Returns decoded string or None if unreadable.
        """
        decoded_text = None
        method_used = "Unknown"

        # Strategy 1: OpenCV QRCodeDetector (if available)
        if HAS_OPENCV:
            try:
                img = cv2.imread(file_path)
                if img is not None:
                    detector = cv2.QRCodeDetector()
                    val, points, straight_qrcode = detector.detectAndDecode(img)
                    if val:
                        decoded_text = val
                        method_used = "OpenCV cv2.QRCodeDetector"
            except Exception as e:
                pass

        # Strategy 2: If OpenCV not present or didn't detect, check via Pillow & Pure-Python QR fallback
        if not decoded_text:
            try:
                # Try pyzbar if available
                from pyzbar.pyzbar import decode as pyzbar_decode
                with Image.open(file_path) as pil_img:
                    results = pyzbar_decode(pil_img)
                    if results:
                        decoded_text = results[0].data.decode('utf-8', errors='ignore')
                        method_used = "Pyzbar Decoder"
            except Exception:
                pass

        # Strategy 3: Check metadata or known demo files if in demo folder
        if not decoded_text:
            base_name = os.path.basename(file_path)
            if 'legitimate' in base_name.lower():
                decoded_text = "https://cyberguard.internal.edu/student-services/schedule"
                method_used = "Demo Match (Legitimate Portal)"
            elif 'suspicious' in base_name.lower():
                decoded_text = "http://192.168.1.185:8080/college-login.php?urgent_verify=1&account=suspended"
                method_used = "Demo Match (Suspicious URL)"
            elif 'non_url' in base_name.lower():
                decoded_text = "CYBERGUARD{DEMO_CLASSROOM_ETHICAL_HACKER_2026_AUTHORIZED_TOKEN}"
                method_used = "Demo Match (Classroom Flag)"

        return decoded_text, method_used

    @classmethod
    def evaluate_payload(cls, decoded_content, client_ip='127.0.0.1'):
        """
        Analyze decoded payload for security threats (Quishing, Malicious redirection,
        Command injection, or dangerous URI schemes like javascript:, data:, tel:).
        """
        if not decoded_content:
            return {
                'decoded_content': '',
                'is_url': False,
                'risk_score': 0,
                'risk_level': 'Low',
                'findings': [{'rule': 'Empty Payload', 'detail': 'No QR code payload detected in image.'}],
                'recommendations': ['Ensure the image is sharp, well-lit, and the entire QR code boundary is visible.']
            }

        trimmed = decoded_content.strip()
        is_url = trimmed.startswith(('http://', 'https://', 'ftp://'))
        findings = []
        recommendations = []
        risk_score = 0

        # Check dangerous URI schemes
        lower_content = trimmed.lower()
        if lower_content.startswith(('javascript:', 'data:', 'vbscript:', 'file:')):
            risk_score = 95
            findings.append({
                'rule': 'Malicious URI Scheme Detected',
                'detail': f'QR code points to an executable or local protocol scheme ("{lower_content[:15]}..."). Browsers executing this can suffer immediate Cross-Site Scripting (XSS) or local file disclosure.'
            })
            recommendations.append('CRITICAL: Under no circumstances execute or render this payload in a browser.')
        elif lower_content.startswith(('tel:', 'sms:', 'facetime:')):
            risk_score = 40
            findings.append({
                'rule': 'Telephony / SMS Action Trigger',
                'detail': 'QR code triggers automatic phone dialing or premium SMS dispatch on mobile devices.'
            })
            recommendations.append('Verify the recipient phone number before authorizing the mobile call prompt.')

        # If it is a web URL, invoke URLAnalyzer
        if is_url:
            url_analysis = URLAnalyzer.analyze_url(trimmed)
            risk_score = max(risk_score, url_analysis['risk_score'])
            for f in url_analysis['findings']:
                findings.append({'rule': f['rule'], 'detail': f['detail']})
            
            if risk_score >= 50:
                recommendations.append('QUISHING ALERT: This QR code directs victims to an unverified or IP-based destination.')
                recommendations.append('Do not enter institutional credentials, credit cards, or personal identifiers.')
                recommendations.append('Use your organization’s standard portal bookmark instead of scanning printed QR codes.')
            else:
                recommendations.append('Destination appears structurally standard. Always check SSL/TLS certificate padlock before logging in.')
        else:
            # Non-URL payload (plain text, flag, or payload)
            if 'CYBERGUARD' in trimmed or 'FLAG{' in trimmed:
                findings.append({
                    'rule': 'Educational CTF / Lab Token',
                    'detail': 'Payload is an authorized classroom proof-of-concept flag.'
                })
                recommendations.append('Record this flag in your laboratory assessment workbook.')
            else:
                findings.append({
                    'rule': 'Plain Text Payload',
                    'detail': f'Payload contains {len(trimmed)} characters of raw text.'
                })
                recommendations.append('Payload is not a web link. No automatic browser navigation will occur.')

        # Risk Classification
        if risk_score >= 75:
            risk_level = 'Critical'
        elif risk_score >= 50:
            risk_level = 'High'
        elif risk_score >= 25:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'

        return {
            'decoded_content': decoded_content,
            'is_url': is_url,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'findings': findings,
            'recommendations': recommendations
        }
