from datetime import datetime, timezone
import json
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from database import db, login_manager

class User(UserMixin, db.Model):
    """Application user model for authentication and role-based access control."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='student')  # admin, analyst, student
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationship with student profile
    student_profile = db.relationship('StudentProfile', backref='user', uselist=False, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class StudentProfile(db.Model):
    """Fictional student profile for ethical hacking and IDOR penetration testing lab."""
    __tablename__ = 'student_profiles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    student_id = db.Column(db.String(30), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), default='Computer Science & Engineering')
    semester = db.Column(db.String(20), default='6th Semester')
    gpa = db.Column(db.Float, default=3.85)
    fee_status = db.Column(db.String(50), default='Paid - Fully Cleared')
    phone = db.Column(db.String(30), default='+1 (555) 019-2831')
    email = db.Column(db.String(120), nullable=False)
    home_address = db.Column(db.String(255), default='142 University Drive, Tech Campus')
    emergency_contact = db.Column(db.String(100), default='Dr. Eleanor Rivera (Mother) - +1 (555) 019-2839')
    confidential_notes = db.Column(db.Text, default='Merit scholarship holder; Dean list candidate 2025-2026.')
    account_balance = db.Column(db.Float, default=0.00)

    def to_dict(self, sensitive=False):
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'student_id': self.student_id,
            'full_name': self.full_name,
            'department': self.department,
            'semester': self.semester,
            'gpa': self.gpa,
            'fee_status': self.fee_status,
            'email': self.email
        }
        if sensitive:
            data.update({
                'phone': self.phone,
                'home_address': self.home_address,
                'emergency_contact': self.emergency_contact,
                'confidential_notes': self.confidential_notes,
                'account_balance': self.account_balance
            })
        return data


class SecurityEvent(db.Model):
    """Tracks application and lab security events for real-time monitoring and SOC display."""
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    category = db.Column(db.String(50), nullable=False, index=True) # Auth, IDOR, Phishing, QR, PortScan, Remediation
    severity = db.Column(db.String(20), nullable=False, index=True) # Critical, High, Medium, Low, Info
    source_ip = db.Column(db.String(45), default='127.0.0.1')
    endpoint = db.Column(db.String(255), default='/')
    user_agent = db.Column(db.String(255), default='Unknown Client')
    description = db.Column(db.String(255), nullable=False)
    technical_details = db.Column(db.Text, default='')
    remediation_status = db.Column(db.String(30), default='Discovered') # Discovered, Investigating, Remediated, Closed
    remediation_action = db.Column(db.Text, default='')

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if self.timestamp else '',
            'category': self.category,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'endpoint': self.endpoint,
            'user_agent': self.user_agent,
            'description': self.description,
            'technical_details': self.technical_details,
            'remediation_status': self.remediation_status,
            'remediation_action': self.remediation_action
        }


class PhishingScan(db.Model):
    """Stores records of submitted texts and URLs analyzed for phishing characteristics."""
    __tablename__ = 'phishing_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = db.Column(db.String(45), default='127.0.0.1')
    input_type = db.Column(db.String(20), default='text') # text, url
    raw_content = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False) # 0-100
    risk_level = db.Column(db.String(20), nullable=False) # Low, Medium, High, Critical
    extracted_urls = db.Column(db.Text, default='[]')
    detected_keywords = db.Column(db.Text, default='[]')
    urgency_score = db.Column(db.Integer, default=0)
    evidence_json = db.Column(db.Text, default='[]')
    recommendations_json = db.Column(db.Text, default='[]')
    vt_status = db.Column(db.String(50), default='Not Checked')

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else '',
            'source_ip': self.source_ip,
            'input_type': self.input_type,
            'raw_content': self.raw_content[:200] + ('...' if len(self.raw_content) > 200 else ''),
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'extracted_urls': json.loads(self.extracted_urls or '[]'),
            'detected_keywords': json.loads(self.detected_keywords or '[]'),
            'urgency_score': self.urgency_score,
            'evidence': json.loads(self.evidence_json or '[]'),
            'recommendations': json.loads(self.recommendations_json or '[]'),
            'vt_status': self.vt_status
        }


class QRScan(db.Model):
    """Stores records of decoded QR code images and their security evaluations."""
    __tablename__ = 'qr_scans'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    file_name = db.Column(db.String(255), nullable=False)
    decoded_content = db.Column(db.Text, nullable=False)
    is_url = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), default='Low')
    findings_json = db.Column(db.Text, default='[]')
    recommendations_json = db.Column(db.Text, default='[]')
    source_ip = db.Column(db.String(45), default='127.0.0.1')

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else '',
            'file_name': self.file_name,
            'decoded_content': self.decoded_content,
            'is_url': self.is_url,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'findings': json.loads(self.findings_json or '[]'),
            'recommendations': json.loads(self.recommendations_json or '[]'),
            'source_ip': self.source_ip
        }


class VulnerabilityRecord(db.Model):
    """Tracks laboratory penetration testing findings and remediation states."""
    __tablename__ = 'vulnerability_records'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    vulnerability_type = db.Column(db.String(80), nullable=False) # IDOR, Missing Auth, etc.
    cwe_id = db.Column(db.String(30), default='CWE-639')
    severity = db.Column(db.String(20), default='High')
    endpoint = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    impact = db.Column(db.Text, nullable=False)
    reproduction_steps = db.Column(db.Text, nullable=False)
    remediation_guide = db.Column(db.Text, nullable=False)
    is_remediated = db.Column(db.Boolean, default=False)
    discovered_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    verified_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'vulnerability_type': self.vulnerability_type,
            'cwe_id': self.cwe_id,
            'severity': self.severity,
            'endpoint': self.endpoint,
            'description': self.description,
            'impact': self.impact,
            'reproduction_steps': self.reproduction_steps,
            'remediation_guide': self.remediation_guide,
            'is_remediated': self.is_remediated,
            'discovered_at': self.discovered_at.strftime('%Y-%m-%d %H:%M:%S') if self.discovered_at else '',
            'verified_at': self.verified_at.strftime('%Y-%m-%d %H:%M:%S') if self.verified_at else 'Pending'
        }


class SystemSetting(db.Model):
    """Runtime dynamic settings such as VirusTotal API key, classroom mode, etc."""
    __tablename__ = 'system_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.Text, default='')
    description = db.Column(db.String(255), default='')

    @classmethod
    def get(cls, key, default=''):
        record = cls.query.filter_by(key=key).first()
        return record.value if record else default

    @classmethod
    def set(cls, key, value, description=''):
        record = cls.query.filter_by(key=key).first()
        if not record:
            record = cls(key=key, value=value, description=description)
            db.session.add(record)
        else:
            record.value = value
            if description:
                record.description = description
        db.session.commit()
