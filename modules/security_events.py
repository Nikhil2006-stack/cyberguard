from datetime import datetime, timezone, timedelta
from database import db
from models import SecurityEvent, PhishingScan, QRScan, VulnerabilityRecord

class SecurityEventManager:
    """
    Centralized security telemetry, event ingestion, and statistical aggregation manager.
    Powers the SOC live dashboard and provides real-time event filtering.
    """

    @classmethod
    def log_event(cls, category, severity, description, technical_details='', endpoint='/', source_ip='127.0.0.1', user_agent='System', remediation_status='Discovered', remediation_action=''):
        """Log a new security event into the database."""
        event = SecurityEvent(
            category=category,
            severity=severity,
            description=description,
            technical_details=technical_details,
            endpoint=endpoint,
            source_ip=source_ip,
            user_agent=user_agent,
            remediation_status=remediation_status,
            remediation_action=remediation_action,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(event)
        db.session.commit()
        return event

    @classmethod
    def get_dashboard_metrics(cls):
        """
        Aggregate authentic database records for SOC metrics.
        Guaranteed: NO fabricated data; directly queries SQLite tables.
        """
        total_events = SecurityEvent.query.count()
        total_phishing = PhishingScan.query.count()
        suspicious_urls = PhishingScan.query.filter(PhishingScan.risk_score >= 50).count()
        qr_scanned = QRScan.query.count()
        
        # Vulnerabilities discovered vs fixed
        total_vulns = VulnerabilityRecord.query.count()
        fixed_vulns = VulnerabilityRecord.query.filter_by(is_remediated=True).count()
        
        # Severity breakdown
        sev_critical = SecurityEvent.query.filter_by(severity='Critical').count()
        sev_high = SecurityEvent.query.filter_by(severity='High').count()
        sev_medium = SecurityEvent.query.filter_by(severity='Medium').count()
        sev_low = SecurityEvent.query.filter_by(severity='Low').count()
        sev_info = SecurityEvent.query.filter_by(severity='Info').count()

        # Category breakdown
        cat_counts = {}
        for category in ['Authentication', 'Access Control (IDOR)', 'Phishing', 'QR Security', 'Port Scan', 'Remediation', 'System']:
            cat_counts[category] = SecurityEvent.query.filter(SecurityEvent.category.like(f'%{category[:6]}%')).count()

        # Recent 10 security events
        recent_events = [
            e.to_dict() for e in SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(10).all()
        ]

        # Activity timeline for past 7 days
        timeline = []
        now = datetime.now(timezone.utc)
        for i in range(6, -1, -1):
            day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            day_label = day_start.strftime('%b %d')
            count = SecurityEvent.query.filter(
                SecurityEvent.timestamp >= day_start,
                SecurityEvent.timestamp < day_end
            ).count()
            timeline.append({'date': day_label, 'count': count})

        return {
            'total_events': total_events,
            'total_phishing': total_phishing,
            'suspicious_urls': suspicious_urls,
            'qr_scanned': qr_scanned,
            'vulnerabilities_discovered': total_vulns,
            'vulnerabilities_fixed': fixed_vulns,
            'severity_distribution': {
                'Critical': sev_critical,
                'High': sev_high,
                'Medium': sev_medium,
                'Low': sev_low,
                'Info': sev_info
            },
            'category_counts': cat_counts,
            'recent_events': recent_events,
            'timeline': timeline
        }
