import os
import socket
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_from_directory, Response
from flask_login import login_user, logout_user, login_required, current_user

from config import Config
from database import db, login_manager
from models import User, StudentProfile, SecurityEvent, PhishingScan, QRScan, VulnerabilityRecord, SystemSetting
from modules.phishing import PhishingDetector
from modules.qr_scanner import QRScanner
from modules.penetration_lab import penetration_lab_bp
from modules.security_events import SecurityEventManager
from modules.risk_engine import RiskEngine
from modules.tool_integrations import SecurityToolCenter
from modules.report_generator import ReportGenerator

def create_app():
    """Application factory for CYBERGUARD."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)

    # Register blueprints
    app.register_blueprint(penetration_lab_bp)

    # Ensure required directories exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['SAMPLE_QR_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)

    with app.app_context():
        db.create_all()
        seed_database()
        # Generate initial classroom demonstration QR codes
        try:
            QRScanner.generate_demo_qrs(app.config['SAMPLE_QR_FOLDER'])
        except Exception as e:
            app.logger.warning(f"Could not generate demo QRs at startup: {e}")

    # =========================================================================
    # CORE NAVIGATION ROUTES
    # =========================================================================

    @app.route('/')
    def index():
        """Public homepage & platform overview."""
        posture = RiskEngine.calculate_posture_score()
        host_ip = get_local_ip()
        return render_template('index.html', posture=posture, host_ip=host_ip)

    @app.route('/dashboard')
    def dashboard():
        """Professional SOC Dashboard with live metrics, charts, and activity."""
        metrics = SecurityEventManager.get_dashboard_metrics()
        posture = RiskEngine.calculate_posture_score()
        mitre = RiskEngine.get_mitre_correlations()
        host_ip = get_local_ip()
        return render_template(
            'dashboard.html',
            metrics=metrics,
            posture=posture,
            mitre=mitre,
            host_ip=host_ip
        )

    # =========================================================================
    # MODULE TWO: PHISHING DETECTION
    # =========================================================================

    @app.route('/phishing')
    def phishing_page():
        """Interactive Phishing Analysis Console."""
        recent_scans = PhishingScan.query.order_by(PhishingScan.timestamp.desc()).limit(8).all()
        return render_template('phishing.html', recent_scans=recent_scans)

    @app.route('/api/phishing/analyze', methods=['POST'])
    def api_phishing_analyze():
        """API endpoint for heuristic phishing analysis."""
        data = request.get_json() or {}
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({'status': 'error', 'message': 'Please provide text or a URL to analyze.'}), 400

        vt_key = SystemSetting.get('VIRUSTOTAL_API_KEY', app.config.get('VIRUSTOTAL_API_KEY', ''))
        detector = PhishingDetector(virustotal_api_key=vt_key)
        client_ip = request.remote_addr or '127.0.0.1'
        
        result = detector.analyze(content, client_ip=client_ip)

        # Record scan in database
        import json
        scan_record = PhishingScan(
            source_ip=client_ip,
            input_type=result['input_type'],
            raw_content=content,
            risk_score=result['risk_score'],
            risk_level=result['risk_level'],
            extracted_urls=json.dumps(result['extracted_urls']),
            detected_keywords=json.dumps(result['detected_keywords']),
            urgency_score=result['urgency_score'],
            evidence_json=json.dumps(result['evidence']),
            recommendations_json=json.dumps(result['recommendations']),
            vt_status=result['virustotal'].get('status', 'Not Checked')
        )
        db.session.add(scan_record)

        # Log security event if risk is medium, high, or critical
        if result['risk_score'] >= 30:
            severity = 'Critical' if result['risk_score'] >= 75 else ('High' if result['risk_score'] >= 50 else 'Medium')
            SecurityEventManager.log_event(
                category='Phishing',
                severity=severity,
                description=f'Suspicious message/URL evaluated (Risk Score: {result["risk_score"]}/100)',
                technical_details=f'Input snippet: "{content[:100]}..." | Evidence: {len(result["evidence"])} indicators flagged.',
                endpoint='/api/phishing/analyze',
                source_ip=client_ip,
                user_agent=request.headers.get('User-Agent', 'Browser'),
                remediation_status='Investigating',
                remediation_action='Advised user not to click links or enter credentials.'
            )
        else:
            db.session.commit()

        return jsonify({'status': 'success', 'data': result})

    # =========================================================================
    # MODULE THREE: QR CODE SECURITY SCANNER
    # =========================================================================

    @app.route('/qr-scanner')
    def qr_scanner_page():
        """QR Code Security Analysis & Demonstration Console."""
        recent_scans = QRScan.query.order_by(QRScan.timestamp.desc()).limit(8).all()
        return render_template('qr_scanner.html', recent_scans=recent_scans)

    @app.route('/api/qr/upload', methods=['POST'])
    def api_qr_upload():
        """Upload and decode a QR code image."""
        if 'qr_image' not in request.files:
            return jsonify({'status': 'error', 'message': 'No image file uploaded.'}), 400

        file = request.files['qr_image']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No selected file.'}), 400

        # Validate file extension
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext not in app.config['ALLOWED_IMAGE_EXTENSIONS']:
            return jsonify({'status': 'error', 'message': 'Invalid file format. Allowed: PNG, JPG, JPEG, WEBP, BMP'}), 400

        filename = f"qr_{int(datetime.now().timestamp())}_{file.filename}"
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)

        # Decode using OpenCV / Native decoder
        decoded_text, method = QRScanner.decode_image(save_path)
        client_ip = request.remote_addr or '127.0.0.1'

        if not decoded_text:
            return jsonify({
                'status': 'error',
                'message': 'No QR code could be decoded from the uploaded image. Please ensure good lighting and clear contrast.'
            }), 422

        # Evaluate decoded payload
        evaluation = QRScanner.evaluate_payload(decoded_text, client_ip=client_ip)
        evaluation['decoder_method'] = method

        # Store in database
        import json
        scan_record = QRScan(
            file_name=filename,
            decoded_content=decoded_text,
            is_url=evaluation['is_url'],
            risk_score=evaluation['risk_score'],
            risk_level=evaluation['risk_level'],
            findings_json=json.dumps(evaluation['findings']),
            recommendations_json=json.dumps(evaluation['recommendations']),
            source_ip=client_ip
        )
        db.session.add(scan_record)

        # Log security event if payload is risky
        if evaluation['risk_score'] >= 30:
            severity = 'Critical' if evaluation['risk_score'] >= 75 else ('High' if evaluation['risk_score'] >= 50 else 'Medium')
            SecurityEventManager.log_event(
                category='QR Security',
                severity=severity,
                description=f'Potentially dangerous QR Code decoded (Risk Score: {evaluation["risk_score"]}/100)',
                technical_details=f'Decoded content: "{decoded_text[:120]}" | Method: {method}',
                endpoint='/api/qr/upload',
                source_ip=client_ip,
                user_agent=request.headers.get('User-Agent', 'Browser'),
                remediation_status='Investigating',
                remediation_action='Alerted user to Quishing risk. Automatic URL navigation suppressed.'
            )
        else:
            db.session.commit()

        return jsonify({'status': 'success', 'data': evaluation})

    @app.route('/api/qr/demo-codes')
    def api_qr_demo_codes():
        """Retrieve pre-generated classroom demonstration QR codes."""
        demo_files = QRScanner.generate_demo_qrs(app.config['SAMPLE_QR_FOLDER'])
        return jsonify({'status': 'success', 'codes': demo_files})

    # =========================================================================
    # MODULE SIX: NETWORK & SECURITY EVENT MONITORING
    # =========================================================================

    @app.route('/network-monitor')
    def network_monitor_page():
        """Live Event Logger & Security Operations Monitoring Console."""
        events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(50).all()
        categories = ['All', 'Authentication', 'Access Control (IDOR)', 'Phishing', 'QR Security', 'Port Scan', 'Remediation', 'System']
        return render_template('network_monitor.html', events=events, categories=categories)

    @app.route('/api/events/live')
    def api_events_live():
        """JSON polling endpoint returning latest events and high-level stats."""
        category = request.args.get('category', 'All')
        query = SecurityEvent.query
        if category != 'All':
            query = query.filter(SecurityEvent.category.like(f'%{category[:6]}%'))
        
        events = query.order_by(SecurityEvent.timestamp.desc()).limit(30).all()
        metrics = SecurityEventManager.get_dashboard_metrics()
        
        return jsonify({
            'status': 'success',
            'events': [e.to_dict() for e in events],
            'metrics': metrics
        })

    # =========================================================================
    # MODULE SEVEN: AI SECURITY ANALYST
    # =========================================================================

    @app.route('/ai-analyst')
    def ai_analyst_page():
        """Explainable AI Security Analyst console."""
        vulnerabilities = VulnerabilityRecord.query.all()
        posture = RiskEngine.calculate_posture_score()
        mitre = RiskEngine.get_mitre_correlations()
        recent_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(10).all()
        
        return render_template(
            'ai_analyst.html',
            vulnerabilities=vulnerabilities,
            posture=posture,
            mitre=mitre,
            recent_events=recent_events
        )

    # =========================================================================
    # MODULE FIVE: SECURITY TOOL CENTRE
    # =========================================================================

    @app.route('/tool-center')
    def tool_center_page():
        """Security Tool Integration & Lab Verification Centre."""
        vt_key = SystemSetting.get('VIRUSTOTAL_API_KEY', app.config.get('VIRUSTOTAL_API_KEY', ''))
        tool_statuses = SecurityToolCenter.get_tool_statuses(vt_key=vt_key)
        local_port_check = SecurityToolCenter.execute_safe_local_port_check(5000)
        host_ip = get_local_ip()
        return render_template(
            'tool_center.html',
            tool_statuses=tool_statuses,
            port_check=local_port_check,
            host_ip=host_ip
        )

    @app.route('/api/tools/port-check')
    def api_tools_port_check():
        """Check socket status of local test ports."""
        port = int(request.args.get('port', 5000))
        check_result = SecurityToolCenter.execute_safe_local_port_check(port)
        return jsonify({'status': 'success', 'result': check_result})

    # =========================================================================
    # MODULE EIGHT: SECURITY REPORT GENERATION
    # =========================================================================

    @app.route('/reports')
    def reports_page():
        """Security Assessment Reports overview."""
        assessment = ReportGenerator.compile_full_assessment()
        return render_template('reports.html', assessment=assessment)

    @app.route('/reports/printable')
    def reports_printable():
        """Standalone printable HTML report formatted for instant PDF export."""
        assessment = ReportGenerator.compile_full_assessment()
        return render_template('report_printable.html', assessment=assessment)

    @app.route('/reports/export/json')
    def reports_export_json():
        """Export raw assessment data as downloadable JSON."""
        assessment = ReportGenerator.compile_full_assessment()
        return jsonify(assessment)

    # =========================================================================
    # MODULE NINE & CLASSROOM DEMO: SETTINGS & CLASSROOM MANAGEMENT
    # =========================================================================

    @app.route('/settings')
    def settings_page():
        """Platform configuration & Classroom demonstration controls."""
        vt_key = SystemSetting.get('VIRUSTOTAL_API_KEY', '')
        classroom_mode = SystemSetting.get('CLASSROOM_MODE', 'true').lower() == 'true'
        host_ip = get_local_ip()
        return render_template(
            'settings.html',
            vt_key=vt_key,
            classroom_mode=classroom_mode,
            host_ip=host_ip
        )

    @app.route('/api/settings/save', methods=['POST'])
    def api_settings_save():
        """Save runtime configuration settings."""
        data = request.get_json() or {}
        vt_key = data.get('vt_key', '').strip()
        classroom_mode = 'true' if data.get('classroom_mode') else 'false'

        SystemSetting.set('VIRUSTOTAL_API_KEY', vt_key, 'VirusTotal Intelligence API Key')
        SystemSetting.set('CLASSROOM_MODE', classroom_mode, 'Live Classroom Demonstration Mode')

        flash('Platform settings updated successfully.', 'success')
        return jsonify({'status': 'success', 'message': 'Settings saved.'})

    @app.route('/api/settings/reseed', methods=['POST'])
    def api_settings_reseed():
        """Reset and reseed database with fresh demonstration records."""
        reseed_database()
        return jsonify({'status': 'success', 'message': 'Database reseeded successfully.'})

    # =========================================================================
    # AUTHENTICATION ROUTES
    # =========================================================================

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Authentication route for administrators and students."""
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user)
                SecurityEventManager.log_event(
                    category='Authentication',
                    severity='Info',
                    description=f'User "{username}" logged in successfully.',
                    technical_details=f'Assigned role: {user.role}, User ID: {user.id}',
                    endpoint='/login',
                    source_ip=request.remote_addr or '127.0.0.1',
                    user_agent=request.headers.get('User-Agent', 'Browser'),
                    remediation_status='Closed'
                )
                flash(f'Welcome back, {user.username}!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                SecurityEventManager.log_event(
                    category='Authentication',
                    severity='Medium',
                    description=f'Failed login attempt for username "{username}".',
                    technical_details='Invalid credentials supplied.',
                    endpoint='/login',
                    source_ip=request.remote_addr or '127.0.0.1',
                    user_agent=request.headers.get('User-Agent', 'Browser'),
                    remediation_status='Investigating'
                )
                flash('Invalid username or password. Please try again.', 'danger')

        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        """Log out active user session."""
        username = current_user.username
        logout_user()
        flash(f'User {username} logged out.', 'info')
        return redirect(url_for('index'))

    # Serve sample QR images directly
    @app.route('/static/images/sample_qrs/<path:filename>')
    def serve_sample_qrs(filename):
        return send_from_directory(app.config['SAMPLE_QR_FOLDER'], filename)

    return app

def get_local_ip():
    """Detect local IP address of host laptop on classroom WiFi or hotspot."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to actually connect; routes kernel routing table
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def seed_database():
    """Seed initial demonstration records if tables are empty."""
    # 1. Admin account
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@cyberguard.local', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)

    # 2. Student A (Attacker perspective in IDOR demonstration)
    user_a = User.query.filter_by(username='student_a').first()
    if not user_a:
        user_a = User(username='student_a', email='alex.rivera@college.edu', role='student')
        user_a.set_password('student_a_pass')
        db.session.add(user_a)
        db.session.flush()

        profile_a = StudentProfile(
            user_id=user_a.id,
            student_id='STU-2026-0814',
            full_name='Alex Rivera',
            department='Computer Science & Cybersecurity',
            semester='6th Semester',
            gpa=3.85,
            fee_status='Paid - Fully Cleared',
            phone='+1 (555) 019-2831',
            email='alex.rivera@college.edu',
            home_address='142 University Drive, Tech Campus',
            emergency_contact='Dr. Eleanor Rivera (Mother) - +1 (555) 019-2839',
            confidential_notes='Enrolled in Ethical Hacking & Secure Coding lab. Student Council Member.',
            account_balance=0.00
        )
        db.session.add(profile_a)

    # 3. Student B (Victim perspective in IDOR demonstration)
    user_b = User.query.filter_by(username='student_b').first()
    if not user_b:
        user_b = User(username='student_b', email='bianca.chen@college.edu', role='student')
        user_b.set_password('student_b_pass')
        db.session.add(user_b)
        db.session.flush()

        profile_b = StudentProfile(
            user_id=user_b.id,
            student_id='STU-2026-0922',
            full_name='Bianca Chen',
            department='Information Security & Cryptography',
            semester='6th Semester',
            gpa=3.96,
            fee_status='Paid - Fully Cleared',
            phone='+1 (555) 019-8472',
            email='bianca.chen@college.edu',
            home_address='892 Oakridge Boulevard, Apt 4B',
            emergency_contact='Arthur Chen (Father) - +1 (555) 019-8479',
            confidential_notes='Holds Department Research Fellowship. Emergency medical alert: Severe penicillin allergy.',
            account_balance=1450.00
        )
        db.session.add(profile_b)

    # 4. Vulnerability Record (IDOR / BOLA)
    if not VulnerabilityRecord.query.filter_by(vulnerability_type='IDOR / Broken Object Level Authorization').first():
        vuln = VulnerabilityRecord(
            title='Insecure Direct Object Reference (IDOR) in Student Profile Endpoint',
            vulnerability_type='IDOR / Broken Object Level Authorization',
            cwe_id='CWE-639',
            severity='High',
            endpoint='/lab/vulnerable/profile/<profile_id>',
            description='The student profile lookup endpoint directly retrieves and displays sensitive records based on an untrusted user-supplied profile_id parameter without verifying session ownership.',
            impact='Complete unauthorized disclosure of student Personally Identifiable Information (PII), emergency contacts, home addresses, and confidential medical/academic notes.',
            reproduction_steps='1. Authenticate as student_a.\n2. In Burp Suite, observe GET /lab/vulnerable/profile/1.\n3. Change profile_id to 2.\n4. Server responds with 200 OK containing student_b’s private records.',
            remediation_guide='Verify on the server that session current_user.id strictly matches profile.user_id. Deny with 403 Forbidden if mismatched.',
            is_remediated=False
        )
        db.session.add(vuln)

    # 5. Initial Seed Security Events for rich dashboard presentation
    if SecurityEvent.query.count() == 0:
        initial_events = [
            SecurityEvent(
                category='System',
                severity='Info',
                source_ip='127.0.0.1',
                description='CYBERGUARD Security Defense Engine initialized in classroom mode.',
                technical_details='Engine version 2.4.0-SEC | SQLite storage mounted | Logging initialized.',
                remediation_status='Closed'
            ),
            SecurityEvent(
                category='Authentication',
                severity='Info',
                source_ip='127.0.0.1',
                description='Pre-configured test accounts "student_a" and "student_b" provisioned.',
                technical_details='Hash scheme: Werkzeug PBKDF2:SHA256.',
                remediation_status='Closed'
            ),
            SecurityEvent(
                category='Access Control (IDOR)',
                severity='High',
                source_ip='127.0.0.1',
                description='Baseline IDOR vulnerability registered in /lab/vulnerable/profile/ endpoint.',
                technical_details='CWE-639 registered for live Burp Suite demonstration.',
                remediation_status='Discovered',
                remediation_action='Pending classroom remediation demonstration.'
            )
        ]
        db.session.bulk_save_objects(initial_events)

    db.session.commit()

def reseed_database():
    """Clear telemetry and reload initial demonstration baseline."""
    SecurityEvent.query.delete()
    PhishingScan.query.delete()
    QRScan.query.delete()
    db.session.commit()
    seed_database()

app = create_app()

if __name__ == '__main__':
    port = app.config['PORT']
    host = app.config['HOST']
    local_ip = get_local_ip()
    print("=" * 65)
    print("  CYBERGUARD: LIVE ETHICAL HACKING & DEFENCE PLATFORM")
    print(f"  Local Access:      http://localhost:{port}")
    print(f"  Classroom Hotspot: http://{local_ip}:{port}")
    print("=" * 65)
    app.run(host=host, port=port, debug=False)
