import re
import urllib.parse
import ipaddress

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'buzz', 'fit', 'tk', 'ml', 'ga', 'cf', 'gq',
    'click', 'rest', 'loan', 'cam', 'country', 'stream', 'download', 'racing',
    'win', 'bid', 'review', 'men', 'party', 'date', 'faith', 'accountant'
}

HIGH_RISK_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'banking', 'update',
    'confirm', 'password', 'credential', 'auth', 'portal', 'admin', 'wallet',
    'support', 'service', 'helpdesk', 'revalidate', 'suspend', 'recover'
]

TRUSTED_DOMAINS = [
    'google.com', 'microsoft.com', 'github.com', 'wikipedia.org',
    'edu', 'gov', 'ac.in', 'edu.in', 'mit.edu', 'stanford.edu'
]

class URLAnalyzer:
    """
    Deep URL lexical, syntactic, and structural security analyzer.
    Detects IP-based hostnames, typosquatting/homograph patterns, deceptive subdomains,
    abnormal ports, and embedded credentials.
    """

    @staticmethod
    def extract_urls(text):
        """Extract all URLs from a text or message."""
        url_pattern = re.compile(
            r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
            re.IGNORECASE
        )
        # Also catch IP-based URLs
        ip_url_pattern = re.compile(
            r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[-a-zA-Z0-9()@:%_\+.~#?&//=]*)?',
            re.IGNORECASE
        )
        urls = url_pattern.findall(text)
        ip_urls = ip_url_pattern.findall(text)
        all_urls = list(dict.fromkeys(urls + ip_urls))
        return all_urls

    @classmethod
    def analyze_url(cls, url):
        """
        Perform in-depth structural security analysis on a single URL.
        Returns a dictionary containing risk score, findings, and parsed elements.
        """
        findings = []
        risk_score = 0
        
        # Ensure url has scheme for parsing
        normalized_url = url.strip()
        if not normalized_url.startswith(('http://', 'https://')):
            normalized_url = 'http://' + normalized_url

        try:
            parsed = urllib.parse.urlparse(normalized_url)
            hostname = (parsed.hostname or '').lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
        except Exception as e:
            return {
                'url': url,
                'is_valid': False,
                'risk_score': 85,
                'risk_level': 'High',
                'findings': [{'rule': 'Malformed URL', 'detail': f'Could not parse URL structure: {str(e)}', 'weight': 85}],
                'recommendation': 'Do not open this URL; its structure is malformed.'
            }

        # 1. Check for IP address in hostname (classic evasion technique)
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
            risk_score += 40
            findings.append({
                'rule': 'IP-Based URL',
                'detail': f'URL uses a raw IP address ({hostname}) instead of a registered domain name. Phishers frequently host attack pages directly on IP addresses to evade domain-reputation filters.',
                'weight': 40
            })
        except ValueError:
            pass

        # 2. Check for Embedded Credentials / At-Symbol trick (e.g. http://google.com@evil.com)
        if '@' in url:
            risk_score += 45
            findings.append({
                'rule': 'URL Credentials / Obfuscation (@ symbol)',
                'detail': 'URL contains an "@" symbol. Modern browsers treat text before "@" as username credentials and route traffic to the domain AFTER the "@", effectively spoofing user perception.',
                'weight': 45
            })

        # 3. Check for Suspicious Top-Level Domains (TLDs)
        tld = hostname.split('.')[-1] if '.' in hostname else ''
        if tld in SUSPICIOUS_TLDS:
            risk_score += 25
            findings.append({
                'rule': 'High-Risk TLD',
                'detail': f'Domain uses the top-level domain ".{tld}", which exhibits a statistically elevated rate of disposable phishing registrations.',
                'weight': 25
            })

        # 4. Check for Subdomain Impersonation / Deceptive Brand Stacking
        subdomain_parts = hostname.split('.')
        if len(subdomain_parts) > 3 and not is_ip:
            risk_score += 20
            findings.append({
                'rule': 'Excessive Subdomains',
                'detail': f'The domain contains {len(subdomain_parts)} parts ({hostname}). Attackers frequently prepend trusted names as subdomains (e.g., "paypal.com.verify.evil.com").',
                'weight': 20
            })

        # Check if legitimate keywords are stuffed into subdomains or path
        stuffed_keywords = [kw for kw in HIGH_RISK_KEYWORDS if kw in hostname or kw in path]
        if len(stuffed_keywords) >= 2:
            weight = min(30, len(stuffed_keywords) * 10)
            risk_score += weight
            findings.append({
                'rule': 'Security Keyword Stacking',
                'detail': f'URL stacks security-sensitive keywords ({", ".join(stuffed_keywords)}). Often used to deceive users into believing the page is an official security/auth portal.',
                'weight': weight
            })

        # 5. Check for Hyphen-Stuffing in domain
        hyphen_count = hostname.count('-')
        if hyphen_count >= 2:
            risk_score += 15
            findings.append({
                'rule': 'Multiple Hyphens in Domain',
                'detail': f'Hostname has {hyphen_count} hyphens ({hostname}). Frequently used in typo-squatting campaigns to spoof institutional domains.',
                'weight': 15
            })

        # 6. Check for Punycode / Homograph evasion (IDN)
        if 'xn--' in hostname:
            risk_score += 35
            findings.append({
                'rule': 'Punycode / Homograph Attack Suspected',
                'detail': f'Domain uses Internationalized Domain Name (IDN) punycode "{hostname}". Attackers use Cyrillic or Greek homoglyphs that visually mimic Latin letters to trick victims.',
                'weight': 35
            })

        # 7. Check for Non-Standard Web Ports
        if parsed.port and parsed.port not in (80, 443, 8080, 5000):
            risk_score += 20
            findings.append({
                'rule': 'Non-Standard Service Port',
                'detail': f'URL explicitly routes to unusual port {parsed.port}. Attackers often run phishing landing pages on non-standard ports to bypass simple egress proxy filters.',
                'weight': 20
            })

        # 8. Check for excessively long URL (obfuscation)
        if len(url) > 120:
            risk_score += 10
            findings.append({
                'rule': 'Abnormal URL Length',
                'detail': f'URL length ({len(url)} characters) is unusually long, frequently seen in evasion payloads designed to hide the true destination off-screen on mobile devices.',
                'weight': 10
            })

        # Cap risk score at 100
        risk_score = min(100, max(0, risk_score))

        # Determine Risk Classification
        if risk_score >= 70:
            risk_level = 'Critical'
        elif risk_score >= 50:
            risk_level = 'High'
        elif risk_score >= 25:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'

        return {
            'url': url,
            'hostname': hostname,
            'is_valid': True,
            'is_ip': is_ip,
            'tld': tld,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'findings': findings,
            'scheme': parsed.scheme or 'http',
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'path': parsed.path,
            'query_params_count': len(urllib.parse.parse_qs(parsed.query))
        }
