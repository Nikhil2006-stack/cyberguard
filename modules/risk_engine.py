from datetime import datetime, timezone, timedelta
from database import db
from models import SecurityEvent, PhishingScan, QRScan, VulnerabilityRecord

class RiskEngine:
    """
    Explainable institutional risk aggregation and correlation engine.
    Maps detected threats to MITRE ATT&CK framework and computes
    overall system defensive posture (0-100 score).
    """

    @classmethod
    def calculate_posture_score(cls):
        """
        Calculate dynamic cybersecurity posture score (0 - 100):
        100 = Fully Hardened / Zero unmitigated high/critical risks
        0   = Critical Exposure / Multiple active unpatched exploits
        """
        base_score = 100
        
        # 1. Unmitigated Vulnerabilities impact
        unfixed_vulns = VulnerabilityRecord.query.filter_by(is_remediated=False).all()
        for v in unfixed_vulns:
            if v.severity == 'Critical':
                base_score -= 30
            elif v.severity == 'High':
                base_score -= 20
            elif v.severity == 'Medium':
                base_score -= 10
            else:
                base_score -= 5

        # 2. Critical & High security events in past 24 hours
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        recent_critical = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= cutoff,
            SecurityEvent.severity == 'Critical',
            SecurityEvent.remediation_status != 'Remediated'
        ).count()
        recent_high = SecurityEvent.query.filter(
            SecurityEvent.timestamp >= cutoff,
            SecurityEvent.severity == 'High',
            SecurityEvent.remediation_status != 'Remediated'
        ).count()

        base_score -= (recent_critical * 15)
        base_score -= (recent_high * 8)

        # 3. Phishing scan severity
        high_risk_phish = PhishingScan.query.filter(
            PhishingScan.risk_score >= 70
        ).count()
        base_score -= min(15, high_risk_phish * 3)

        posture_score = max(5, min(100, base_score))
        
        if posture_score >= 80:
            status = 'Defensive Posture: Strong / Hardened'
            grade = 'A'
            color = 'success'
        elif posture_score >= 60:
            status = 'Defensive Posture: Moderate / Actions Required'
            grade = 'B'
            color = 'info'
        elif posture_score >= 40:
            status = 'Defensive Posture: Elevated Risk / Vulnerabilities Detected'
            grade = 'C'
            color = 'warning'
        else:
            status = 'Defensive Posture: Critical Exposure / Immediate Remediation Required'
            grade = 'F'
            color = 'danger'

        return {
            'score': posture_score,
            'grade': grade,
            'status': status,
            'color': color,
            'unfixed_vulnerabilities': len(unfixed_vulns),
            'active_threats': recent_critical + recent_high
        }

    @classmethod
    def get_mitre_correlations(cls):
        """Map laboratory findings to standard MITRE ATT&CK tactics & techniques."""
        correlations = [
            {
                'tactic': 'Initial Access (TA0001)',
                'technique': 'T1566: Phishing',
                'sub_technique': 'T1566.002: Spearphishing Link / QR Quishing',
                'description': 'Attackers distribute deceptive links or malicious QR codes mimicking college portals to establish initial foothold.',
                'detected_events': PhishingScan.query.count() + QRScan.query.count(),
                'status': 'Monitored & Filtered'
            },
            {
                'tactic': 'Privilege Escalation (TA0004)',
                'technique': 'T1068: Exploitation for Privilege Escalation',
                'sub_technique': 'CWE-639 / BOLA: Broken Object Level Authorization',
                'description': 'Attacker modifies resource identifiers (IDOR) to access unauthorized horizontal profiles without privilege validation.',
                'detected_events': SecurityEvent.query.filter(SecurityEvent.category.like('%IDOR%')).count(),
                'status': 'Demonstrated in Lab'
            },
            {
                'tactic': 'Credential Access (TA0006)',
                'technique': 'T1552: Unsecured Credentials',
                'sub_technique': 'T1552.001: Credentials in Files / Data Exposure',
                'description': 'Unprotected student endpoints disclose emergency contacts, financial balances, and identity markers.',
                'detected_events': SecurityEvent.query.filter_by(severity='Critical').count(),
                'status': 'Secured via Ownership Verification'
            },
            {
                'tactic': 'Reconnaissance (TA0043)',
                'technique': 'T1595: Active Scanning',
                'sub_technique': 'T1595.001: Port & Service Enumeration',
                'description': 'Nmap and OWASP ZAP active sweeps identifying open local laboratory ports and unhardened endpoints.',
                'detected_events': SecurityEvent.query.filter(SecurityEvent.category.like('%Scan%')).count(),
                'status': 'Inspected in Tool Centre'
            }
        ]
        return correlations
