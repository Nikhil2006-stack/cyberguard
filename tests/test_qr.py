import os
import pytest
from modules.qr_scanner import QRScanner

def test_generate_demo_qrs(tmp_path):
    output_dir = str(tmp_path)
    codes = QRScanner.generate_demo_qrs(output_dir)
    assert 'legitimate' in codes
    assert 'suspicious' in codes
    assert 'non_url' in codes
    
    assert os.path.exists(codes['legitimate']['path'])
    assert os.path.exists(codes['suspicious']['path'])
    assert os.path.exists(codes['non_url']['path'])

def test_evaluate_payload_legitimate_url():
    payload = "https://cyberguard.internal.edu/student-services"
    result = QRScanner.evaluate_payload(payload)
    assert result['is_url'] is True
    assert result['risk_level'] == 'Low'
    assert result['risk_score'] < 30

def test_evaluate_payload_suspicious_ip_url():
    payload = "http://192.168.1.185:8080/college-login.php?urgent_verify=1"
    result = QRScanner.evaluate_payload(payload)
    assert result['is_url'] is True
    assert result['risk_score'] >= 40
    assert any('IP-Based URL' in f['rule'] for f in result['findings'])

def test_evaluate_payload_malicious_javascript_uri():
    payload = "javascript:alert(document.cookie)"
    result = QRScanner.evaluate_payload(payload)
    assert result['risk_score'] >= 90
    assert result['risk_level'] == 'Critical'
    assert any('Malicious URI Scheme' in f['rule'] for f in result['findings'])

def test_evaluate_payload_non_url_flag():
    payload = "CYBERGUARD{DEMO_CLASSROOM_TOKEN_2026}"
    result = QRScanner.evaluate_payload(payload)
    assert result['is_url'] is False
    assert result['risk_level'] == 'Low'
    assert any('Educational CTF' in f['rule'] for f in result['findings'])
