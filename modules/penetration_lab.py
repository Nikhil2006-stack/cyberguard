from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from database import db
from models import User, StudentProfile, SecurityEvent, VulnerabilityRecord
from datetime import datetime, timezone

penetration_lab_bp = Blueprint('penetration_lab', __name__, url_prefix='/lab')

@penetration_lab_bp.route('/')
def lab_home():
    """Penetration Testing Lab index & comparison guide."""
    # Fetch profiles for demonstration reference
    student_a_user = User.query.filter_by(username='student_a').first()
    student_b_user = User.query.filter_by(username='student_b').first()
    
    profile_a = student_a_user.student_profile if student_a_user else None
    profile_b = student_b_user.student_profile if student_b_user else None

    # Fetch recorded IDOR vulnerability status
    idor_vuln = VulnerabilityRecord.query.filter_by(vulnerability_type='IDOR / Broken Object Level Authorization').first()

    return render_template(
        'penetration_lab.html',
        profile_a=profile_a,
        profile_b=profile_b,
        current_lab_user=current_user if current_user.is_authenticated else None,
        idor_vuln=idor_vuln
    )

@penetration_lab_bp.route('/quick-switch/<username>')
def quick_switch_account(username):
    """
    Classroom convenience helper: Quickly log in as student_a or student_b
    to facilitate live side-by-side Burp Suite demonstrations.
    """
    user = User.query.filter_by(username=username).first()
    if user:
        login_user(user)
        # Log authentication event
        evt = SecurityEvent(
            category='Authentication',
            severity='Info',
            source_ip=request.remote_addr or '127.0.0.1',
            endpoint=request.path,
            user_agent=request.headers.get('User-Agent', 'Browser'),
            description=f'User "{username}" logged into dummy student portal for lab demonstration.',
            technical_details=f'Assigned User ID: {user.id}, Role: {user.role}',
            remediation_status='Closed'
        )
        db.session.add(evt)
        db.session.commit()
        flash(f'Switched active session to: {username} (ID: {user.id})', 'success')
    else:
        flash(f'User {username} not found in database.', 'danger')
    return redirect(url_for('penetration_lab.lab_home'))

# =========================================================================
# SCENARIO A: DELIBERATELY VULNERABLE ENDPOINT (IDOR / BOLA)
# =========================================================================
@penetration_lab_bp.route('/vulnerable/profile/<int:profile_id>', methods=['GET'])
def vulnerable_profile(profile_id):
    """
    [DELIBERATELY VULNERABLE ENDPOINT - CWE-639 / OWASP API1:2023 Broken Object Level Authorization]
    
    VULNERABILITY EXPLANATION:
    The server receives a `profile_id` integer parameter directly from the client URL.
    It queries the database for that `profile_id` and immediately serializes all sensitive
    records (phone, emergency contact, home address, confidential remarks, financial balance)
    WITHOUT checking whether the requesting session owns the record!
    
    EXPLOITATION PROCEDURE IN BURP SUITE:
    1. Attacker logs in as Student A (profile_id = 1).
    2. Attacker intercepts GET /lab/vulnerable/profile/1 in Burp Suite Proxy.
    3. Attacker modifies the URL parameter to /lab/vulnerable/profile/2.
    4. Attacker receives Student B's complete private profile!
    """
    client_ip = request.remote_addr or '127.0.0.1'
    caller_username = current_user.username if current_user.is_authenticated else 'Anonymous Guest'
    caller_id = current_user.id if current_user.is_authenticated else None

    # Query target profile directly by client-supplied ID (NO OWNERSHIP CHECK!)
    profile = db.session.get(StudentProfile, profile_id)

    if not profile:
        return jsonify({
            'status': 'error',
            'code': 404,
            'message': f'Student profile #{profile_id} does not exist.'
        }), 404

    # DETECT IF AN UNAUTHORIZED ACCESS OCCURRED (FOR LAB TELEMETRY & SOC MONITORING)
    is_idor_attack = False
    if caller_id and profile.user_id != caller_id:
        is_idor_attack = True
        
        # Log critical IDOR security event in database
        event = SecurityEvent(
            category='Access Control (IDOR)',
            severity='Critical',
            source_ip=client_ip,
            endpoint=f'/lab/vulnerable/profile/{profile_id}',
            user_agent=request.headers.get('User-Agent', 'BurpSuite/1.0'),
            description=f'IDOR Exploit Detected: User "{caller_username}" (User ID: {caller_id}) accessed private profile of Student ID "{profile.student_id}" (Owner User ID: {profile.user_id})!',
            technical_details=(
                f"Vulnerable Endpoint: GET /lab/vulnerable/profile/{profile_id}\n"
                f"Caller Identity: {caller_username} (ID: {caller_id})\n"
                f"Victim Profile Owner: User ID {profile.user_id} ({profile.full_name})\n"
                f"Missing Check: No server-side session-to-object ownership verification.\n"
                f"Data Disclosed: Full Name, Address, Phone, Emergency Contacts, GPA, Academic Notes."
            ),
            remediation_status='Discovered',
            remediation_action='Implement server-side ownership verification comparing session.user_id to resource.user_id.'
        )
        db.session.add(event)
        
        # Update vulnerability record in database
        vuln = VulnerabilityRecord.query.filter_by(vulnerability_type='IDOR / Broken Object Level Authorization').first()
        if vuln:
            vuln.is_remediated = False
        db.session.commit()

    return jsonify({
        'endpoint_status': 'VULNERABLE',
        'vulnerability': 'CWE-639: Insecure Direct Object Reference (IDOR)',
        'security_warning': 'This endpoint lacks server-side authorization checks.',
        'idor_detected': is_idor_attack,
        'profile_id_requested': profile_id,
        'requesting_user': caller_username,
        'profile_data': profile.to_dict(sensitive=True)
    }), 200

# =========================================================================
# SCENARIO B: SECURED ENDPOINT (PROPER SERVER-SIDE AUTHORIZATION)
# =========================================================================
@penetration_lab_bp.route('/secured/profile/<int:profile_id>', methods=['GET'])
@login_required
def secured_profile(profile_id):
    """
    [SECURED ENDPOINT - DEFENSE-IN-DEPTH REMEDIATION]
    
    SECURITY CONTROLS IMPLEMENTED:
    1. Authentication Required: User must possess a valid, tamper-proof session cookie (@login_required).
    2. Server-Side Ownership Verification:
       The application inspects `current_user.id` from the cryptographically signed session cookie
       and compares it directly to `profile.user_id`.
    3. Strict Access Control Enforcement:
       If `current_user.id != profile.user_id` and the user is NOT an administrator,
       the server immediately terminates the request with HTTP 403 Forbidden.
    4. Detailed Security Auditing:
       Every unauthorized probe is logged to the Security Operations Center (SOC).
    """
    client_ip = request.remote_addr or '127.0.0.1'
    
    # 1. Fetch requested profile
    profile = db.session.get(StudentProfile, profile_id)
    if not profile:
        return jsonify({
            'status': 'error',
            'code': 404,
            'message': 'Student profile not found.'
        }), 404

    # 2. SERVER-SIDE AUTHORIZATION CHECK
    # Only the account owner or an admin is authorized to view private student details!
    if profile.user_id != current_user.id and current_user.role != 'admin':
        # Unauthorized access attempt intercepted!
        # Log defensive interception event
        event = SecurityEvent(
            category='Access Control (Blocked)',
            severity='Medium',
            source_ip=client_ip,
            endpoint=f'/lab/secured/profile/{profile_id}',
            user_agent=request.headers.get('User-Agent', 'BurpSuite/1.0'),
            description=f'Access Denied (403): User "{current_user.username}" attempted unauthorized access to Student Profile #{profile_id}. Request blocked by server-side authorization check.',
            technical_details=(
                f"Secured Endpoint: GET /lab/secured/profile/{profile_id}\n"
                f"Authenticated User: {current_user.username} (ID: {current_user.id})\n"
                f"Resource Owner: User ID {profile.user_id}\n"
                f"Enforcement Rule: if profile.user_id != current_user.id -> return 403 Forbidden"
            ),
            remediation_status='Remediated',
            remediation_action='Server-side ownership verification successfully blocked IDOR probe.'
        )
        db.session.add(event)
        
        # Mark vulnerability as verified/remediated
        vuln = VulnerabilityRecord.query.filter_by(vulnerability_type='IDOR / Broken Object Level Authorization').first()
        if vuln:
            vuln.is_remediated = True
            vuln.verified_at = datetime.now(timezone.utc)
        db.session.commit()

        return jsonify({
            'endpoint_status': 'SECURED',
            'status': 'error',
            'code': 403,
            'message': 'Access Denied: You do not possess authorization to view this student profile.',
            'security_control': 'Server-Side Resource Ownership Verification enforced.',
            'audit_logged': True
        }), 403

    # Authorized access granted
    return jsonify({
        'endpoint_status': 'SECURED',
        'status': 'success',
        'message': 'Authorized access granted. Resource ownership verified.',
        'requesting_user': current_user.username,
        'profile_data': profile.to_dict(sensitive=True)
    }), 200
