import re
import requests
from modules.url_analyzer import URLAnalyzer

# Explainable rules with weighted signals
URGENCY_PATTERNS = [
    (r'\b(immediate(ly)?|urgent(ly)?|right now|at once|within \d+ (hours?|minutes?|days?))\b', 'Immediate Deadline', 20),
    (r'\b(account (will be|has been) (suspended|terminated|disabled|restricted|deactivated|locked))\b', 'Account Suspension Threat', 25),
    (r'\b(unauthorized (access|login|activity|transaction) detected)\b', 'False Alarm / Security Panic Lure', 25),
    (r'\b(final (notice|warning)|last chance|action required)\b', 'High-Pressure Coercion', 15),
    (r'\b(verify (your )?(identity|account|credentials|email|details) immediately)\b', 'Urgent Verification Directive', 20),
]

CREDENTIAL_HARVESTING_PATTERNS = [
    (r'\b(enter|confirm|verify|update|reset) (your )?(password|pin|passcode|otp|credentials|ssn|card details)\b', 'Direct Credential Request', 35),
    (r'\b(login to (keep|restore|reactivate|verify) your account)\b', 'Access Re-validation Phish', 25),
    (r'\b(click (here|the link below|this link) to (verify|unlock|validate|update))\b', 'Call-to-Action Link Bait', 20),
    (r'\b(free (gift|reward|cash|bonus|crypto|bitcoin|voucher|prize)|lottery winner)\b', 'Baiting / Reward Lure', 20),
]

SPOOFING_IMPERSONATION_PATTERNS = [
    (r'\b(college it (helpdesk|support|security|administration)|university portal admin)\b', 'Institutional IT Impersonation', 25),
    (r'\b(microsoft (account|security|team)|google security|apple id|paypal security)\b', 'Major Brand Impersonation', 25),
    (r'\b(student affairs|finance department|dean of students)\b', 'Campus Authority Impersonation', 20),
    (r'\b(dear (customer|student|user|member|account holder))\b', 'Impersonal / Generic Greeting', 10),
]

class PhishingDetector:
    """
    Explainable, hybrid rule-based and structural phishing detection engine.
    Analyzes message semantics, psychological triggers (urgency, panic, authority lures),
    and validates embedded URLs using the URLAnalyzer module.
    """

    def __init__(self, virustotal_api_key=None):
        self.vt_api_key = virustotal_api_key

    def analyze(self, content, client_ip='127.0.0.1'):
        """
        Analyze arbitrary text, email body, or single URL.
        Returns explainable metrics, risk level, evidence trail, and safety advice.
        """
        content_lower = content.lower()
        evidence = []
        detected_keywords = []
        total_risk = 0
        urgency_score = 0
        
        # 1. Urgency & Panic Triggers
        for pattern, label, weight in URGENCY_PATTERNS:
            matches = re.findall(pattern, content_lower)
            if matches:
                urgency_score += weight
                total_risk += weight
                matched_snippet = matches[0] if isinstance(matches[0], str) else matches[0][0]
                detected_keywords.append(matched_snippet)
                evidence.append({
                    'category': 'Urgency & Coercion',
                    'trigger': label,
                    'snippet': matched_snippet,
                    'impact': f'+{weight} Risk Points',
                    'explanation': 'Attackers use artificial urgency to force victims into acting impulsively before verifying authenticity.'
                })

        # 2. Credential Harvesting & Action Requests
        for pattern, label, weight in CREDENTIAL_HARVESTING_PATTERNS:
            matches = re.findall(pattern, content_lower)
            if matches:
                total_risk += weight
                matched_snippet = matches[0] if isinstance(matches[0], str) else matches[0][0]
                detected_keywords.append(matched_snippet)
                evidence.append({
                    'category': 'Credential Harvesting',
                    'trigger': label,
                    'snippet': matched_snippet,
                    'impact': f'+{weight} Risk Points',
                    'explanation': 'Legitimate institutions never demand direct password/OTP disclosure via email or unverified landing pages.'
                })

        # 3. Authority Impersonation & Generic Greetings
        for pattern, label, weight in SPOOFING_IMPERSONATION_PATTERNS:
            matches = re.findall(pattern, content_lower)
            if matches:
                total_risk += weight
                matched_snippet = matches[0] if isinstance(matches[0], str) else matches[0][0]
                detected_keywords.append(matched_snippet)
                evidence.append({
                    'category': 'Brand & Authority Impersonation',
                    'trigger': label,
                    'snippet': matched_snippet,
                    'impact': f'+{weight} Risk Points',
                    'explanation': 'Attackers impersonate IT departments, campus administrations, or familiar tech vendors to manufacture trust.'
                })

        # 4. Extract and deeply analyze embedded URLs
        extracted_urls = URLAnalyzer.extract_urls(content)
        url_analyses = []
        highest_url_risk = 0

        for url in extracted_urls:
            analysis = URLAnalyzer.analyze_url(url)
            url_analyses.append(analysis)
            if analysis['risk_score'] > highest_url_risk:
                highest_url_risk = analysis['risk_score']
            
            # Incorporate individual URL findings
            for finding in analysis['findings']:
                evidence.append({
                    'category': 'Suspicious URL Structure',
                    'trigger': finding['rule'],
                    'snippet': url,
                    'impact': f'+{finding["weight"]} Risk Points',
                    'explanation': finding['detail']
                })

        # Blend URL risk with semantic risk
        if extracted_urls:
            total_risk = int(total_risk * 0.6 + highest_url_risk * 0.6)
        
        # Check for excessive exclamation marks or all-caps shouting
        shouting_caps = len(re.findall(r'\b[A-Z]{4,}\b', content))
        if shouting_caps >= 3:
            total_risk += 10
            evidence.append({
                'category': 'Presentation Anomaly',
                'trigger': 'Excessive Capitalization',
                'snippet': f'{shouting_caps} capitalized words found',
                'impact': '+10 Risk Points',
                'explanation': 'Aggressive typography designed to induce panic and cognitive overload.'
            })

        # Normalize score 0-100
        final_score = min(100, max(0, total_risk))

        # Risk Classification
        if final_score >= 75:
            risk_level = 'Critical'
            badge_class = 'danger'
        elif final_score >= 50:
            risk_level = 'High'
            badge_class = 'warning'
        elif final_score >= 25:
            risk_level = 'Medium'
            badge_class = 'info'
        else:
            risk_level = 'Low'
            badge_class = 'success'

        # Generate Actionable Recommendations
        recommendations = self._generate_recommendations(final_score, extracted_urls, evidence)

        # Optional VirusTotal integration
        vt_report = self._check_virustotal(extracted_urls[0]) if (extracted_urls and self.vt_api_key) else {
            'checked': False,
            'status': 'VirusTotal API key not configured (offline heuristic mode active)'
        }

        return {
            'content': content,
            'client_ip': client_ip,
            'input_type': 'url' if (len(extracted_urls) == 1 and content.strip() == extracted_urls[0]) else 'text',
            'risk_score': final_score,
            'risk_level': risk_level,
            'badge_class': badge_class,
            'urgency_score': min(100, urgency_score),
            'extracted_urls': extracted_urls,
            'url_analyses': url_analyses,
            'detected_keywords': list(dict.fromkeys(detected_keywords)),
            'evidence': evidence,
            'recommendations': recommendations,
            'virustotal': vt_report
        }

    def _generate_recommendations(self, score, urls, evidence):
        recs = []
        if score >= 50:
            recs.append('DO NOT click any links, open attachments, or reply to this message.')
            recs.append('Never provide passwords, OTPs, or multi-factor authentication codes.')
            if urls:
                recs.append('Verify the destination domain directly via an official browser bookmark or official college portal.')
            recs.append('Forward the full message headers to your institution’s Security Operations Center (SOC).')
        elif score >= 25:
            recs.append('Exercise caution. Verify the sender identity through a secondary, independent communication channel.')
            recs.append('Inspect embedded links by hovering over them to verify the true destination URL.')
        else:
            recs.append('No overt phishing indicators detected. Continue adhering to standard cyber hygiene.')
            recs.append('Keep your browser, password manager, and endpoint protection software updated.')
        return recs

    def _check_virustotal(self, url):
        """Perform genuine VirusTotal API v3 URL submission and report lookup."""
        if not self.vt_api_key:
            return {'checked': False, 'status': 'No API Key configured.'}

        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.vt_api_key}
            api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            resp = requests.get(api_endpoint, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'checked': True,
                    'status': 'Analysis Retrieved',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0)
                }
            elif resp.status_code == 404:
                return {'checked': True, 'status': 'URL not yet indexed by VirusTotal'}
            else:
                return {'checked': False, 'status': f'VirusTotal API error ({resp.status_code})'}
        except Exception as e:
            return {'checked': False, 'status': f'VT Lookup failed: {str(e)}'}
