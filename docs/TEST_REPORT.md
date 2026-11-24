# CYBERGUARD: Automated Testing & Quality Assurance Report

> **Execution Date:** 2026-11-24  
> **Test Framework:** `pytest 9.2.0`  
> **Python Version:** Python 3.14.0  
> **Target Application:** CYBERGUARD Platform  
> **Final Verdict:** **100% PASS (20 Passed, 0 Failed)**

---

## 1. Test Execution Summary

```
============================= test session starts =============================
platform win32 -- Python 3.14.0, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\HP\Desktop\cyberguard
collected 20 items

tests/test_authorization.py::test_student_authentication PASSED          [  5%]
tests/test_authorization.py::test_vulnerable_idor_endpoint_reproduces_vulnerability PASSED [ 10%]
tests/test_authorization.py::test_secured_endpoint_blocks_unauthorized_idor PASSED [ 15%]
tests/test_authorization.py::test_secured_endpoint_allows_authorized_owner_access PASSED [ 20%]
tests/test_authorization.py::test_secured_endpoint_requires_authentication PASSED [ 25%]
tests/test_events.py::test_security_event_logging PASSED                 [ 30%]
tests/test_events.py::test_dashboard_metrics_aggregation PASSED          [ 35%]
tests/test_events.py::test_core_page_routes_load_cleanly PASSED          [ 40%]
tests/test_events.py::test_report_generation PASSED                      [ 45%]
tests/test_phishing.py::test_url_extractor PASSED                        [ 50%]
tests/test_phishing.py::test_url_analyzer_ip_based PASSED                [ 55%]
tests/test_phishing.py::test_url_analyzer_at_symbol_obfuscation PASSED   [ 60%]
tests/test_phishing.py::test_phishing_detector_urgent_suspension PASSED  [ 65%]
tests/test_phishing.py::test_phishing_detector_benign_message PASSED     [ 70%]
tests/test_phishing.py::test_phishing_api_endpoint PASSED                [ 75%]
tests/test_qr.py::test_generate_demo_qrs PASSED                          [ 80%]
tests/test_qr.py::test_evaluate_payload_legitimate_url PASSED            [ 85%]
tests/test_qr.py::test_evaluate_payload_suspicious_ip_url PASSED         [ 90%]
tests/test_qr.py::test_evaluate_payload_malicious_javascript_uri PASSED  [ 95%]
tests/test_qr.py::test_evaluate_payload_non_url_flag PASSED              [100%]

============================= 20 passed in 40.39s =============================
```

---

## 2. Detailed Test Case Verification Matrix

| Test Identifier | Category | Observable Objective | Verification Result |
|---|---|---|---|
| `test_student_authentication` | Authentication | Verifies valid login for `student_a`, session creation, and rejection of invalid passwords. | **PASSED** (HTTP 200 / Flash Warning) |
| `test_vulnerable_idor_endpoint_reproduces_vulnerability` | Penetration Lab | Verifies that `GET /lab/vulnerable/profile/2` accessed by Student A leaks Student B's confidential PII. | **PASSED** (IDOR reproduced) |
| `test_secured_endpoint_blocks_unauthorized_idor` | Defensive Access Control | Verifies that `GET /lab/secured/profile/2` accessed by Student A is strictly blocked with HTTP 403 Forbidden. | **PASSED** (HTTP 403 Forbidden) |
| `test_secured_endpoint_allows_authorized_owner_access` | Access Control | Verifies that Student A can view their own profile (#1) without false positives. | **PASSED** (HTTP 200 OK) |
| `test_secured_endpoint_requires_authentication` | Authentication | Verifies that unauthenticated anonymous callers are redirected to login. | **PASSED** (HTTP 302 Redirect) |
| `test_security_event_logging` | Telemetry & Audit | Verifies `SecurityEventManager.log_event()` inserts rows with valid timestamps and categories. | **PASSED** (Database Row Created) |
| `test_dashboard_metrics_aggregation` | SOC Dashboard | Verifies arithmetic counts for total events, severity distribution, and activity timelines. | **PASSED** (Authentic DB Aggregation) |
| `test_core_page_routes_load_cleanly` | Web Navigation | Confirms all 12 core URLs load with HTTP 200 status code and zero 500 server errors. | **PASSED** (All 12 Routes OK) |
| `test_report_generation` | Audit Deliverables | Verifies `ReportGenerator.compile_full_assessment()` produces all required audit fields. | **PASSED** (Complete JSON Structure) |
| `test_url_extractor` | Phishing / URL | Verifies extraction of standard FQDN and IP-based URLs from unstructured message bodies. | **PASSED** (Regex Parsed) |
| `test_url_analyzer_ip_based` | URL Inspection | Confirms raw IPv4 hostnames trigger IP anomaly detection (+40 risk points). | **PASSED** (Risk Score >= 40) |
| `test_url_analyzer_at_symbol_obfuscation` | URL Inspection | Confirms embedded `@` credential obfuscation triggers detection (+45 risk points). | **PASSED** (Risk Score >= 45) |
| `test_phishing_detector_urgent_suspension` | Phishing Engine | Tests urgent account suspension message; asserts risk score >= 50 and High/Critical level. | **PASSED** (Critical Risk Assigned) |
| `test_phishing_detector_benign_message` | Phishing Engine | Tests normal classroom announcement; asserts low false-positive score (< 30). | **PASSED** (Low Risk Assigned) |
| `test_phishing_api_endpoint` | REST API | Verifies `/api/phishing/analyze` JSON API responds with structured risk data. | **PASSED** (HTTP 200 JSON) |
| `test_generate_demo_qrs` | QR Generator | Confirms automatic disk generation of legitimate, suspicious, and non-URL demo QR codes. | **PASSED** (3 Images Generated) |
| `test_evaluate_payload_legitimate_url` | QR Safety | Asserts that an official HTTPS portal URL receives a Low Risk rating. | **PASSED** (Low Risk Rating) |
| `test_evaluate_payload_suspicious_ip_url` | Quishing Countermeasure | Asserts that simulated phishing QR codes trigger Quishing alerts and IP warnings. | **PASSED** (Quishing Alert Flagged) |
| `test_evaluate_payload_malicious_javascript_uri` | Exploit Defense | Confirms that `javascript:` URI schemes trigger Critical Risk rating (>= 90). | **PASSED** (Critical Risk Assigned) |
| `test_evaluate_payload_non_url_flag` | Non-URL Payloads | Verifies that classroom CTF token payloads are recognized as plain text rather than URLs. | **PASSED** (CTF Token Identified) |

---

## 3. How to Execute Tests Independently

To reproduce these results on your own machine:
```bash
python -m pytest tests/ -v
```
To run a specific test suite:
```bash
python -m pytest tests/test_authorization.py -v
```
