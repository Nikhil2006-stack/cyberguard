import pytest
from modules.url_analyzer import URLAnalyzer
from modules.phishing import PhishingDetector

def test_url_extractor():
    text = "Please check http://192.168.1.50/login and also https://google.com for updates."
    urls = URLAnalyzer.extract_urls(text)
    assert len(urls) >= 2
    assert "http://192.168.1.50/login" in urls

def test_url_analyzer_ip_based():
    url = "http://192.168.1.185:8080/portal-login.php"
    analysis = URLAnalyzer.analyze_url(url)
    assert analysis['is_ip'] is True
    assert analysis['risk_score'] >= 40
    assert any(f['rule'] == 'IP-Based URL' for f in analysis['findings'])

def test_url_analyzer_at_symbol_obfuscation():
    url = "http://google.com@phishing-target.xyz/login"
    analysis = URLAnalyzer.analyze_url(url)
    assert any('Credentials / Obfuscation' in f['rule'] for f in analysis['findings'])
    assert analysis['risk_score'] >= 45

def test_phishing_detector_urgent_suspension():
    detector = PhishingDetector()
    sample = "URGENT! Your college account will be suspended within 24 hours. Verify your password immediately at http://192.168.1.185:8080/login"
    result = detector.analyze(sample)
    
    assert result['risk_score'] >= 50
    assert result['risk_level'] in ['High', 'Critical']
    assert len(result['evidence']) > 0
    assert len(result['recommendations']) > 0

def test_phishing_detector_benign_message():
    detector = PhishingDetector()
    sample = "Hello students, the library will be open until 9 PM for quiet study. Have a good week!"
    result = detector.analyze(sample)
    
    assert result['risk_score'] < 30
    assert result['risk_level'] == 'Low'

def test_phishing_api_endpoint(client):
    response = client.post('/api/phishing/analyze', json={
        'content': 'URGENT action required! Reset your password immediately: http://10.0.0.1/auth'
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'success'
    assert data['data']['risk_score'] >= 40
