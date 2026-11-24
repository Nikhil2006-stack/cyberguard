import pytest
from database import db
from models import SecurityEvent, VulnerabilityRecord
from modules.security_events import SecurityEventManager
from modules.report_generator import ReportGenerator

def test_security_event_logging(app):
    with app.app_context():
        initial_count = SecurityEvent.query.count()
        evt = SecurityEventManager.log_event(
            category='Access Control (IDOR)',
            severity='Critical',
            description='Test IDOR attempt detected in unit test.',
            technical_details='Automated verification event.',
            endpoint='/lab/vulnerable/profile/2'
        )
        assert evt.id is not None
        assert SecurityEvent.query.count() == initial_count + 1

def test_dashboard_metrics_aggregation(app):
    with app.app_context():
        metrics = SecurityEventManager.get_dashboard_metrics()
        assert 'total_events' in metrics
        assert 'severity_distribution' in metrics
        assert 'timeline' in metrics
        assert metrics['vulnerabilities_discovered'] >= 1

def test_core_page_routes_load_cleanly(client):
    routes = [
        '/',
        '/dashboard',
        '/phishing',
        '/qr-scanner',
        '/lab/',
        '/network-monitor',
        '/ai-analyst',
        '/tool-center',
        '/reports',
        '/reports/printable',
        '/settings',
        '/login'
    ]
    for route in routes:
        resp = client.get(route)
        assert resp.status_code == 200, f"Route {route} failed with {resp.status_code}"

def test_report_generation(app):
    with app.app_context():
        report = ReportGenerator.compile_full_assessment()
        assert report['metadata']['project_name'] == 'CYBERGUARD'
        assert 'executive_summary' in report
        assert len(report['vulnerabilities']) >= 1
        assert len(report['tools_utilized']) == 5
