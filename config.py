import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'reports'), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'static', 'images', 'sample_qrs'), exist_ok=True)

class Config:
    """Base application configuration for CYBERGUARD."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyberguard-secret-security-key-2026-auth')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', f'sqlite:///{os.path.join(INSTANCE_DIR, "cyberguard.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session security settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # File upload configurations
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    SAMPLE_QR_FOLDER = os.path.join(BASE_DIR, 'static', 'images', 'sample_qrs')
    REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')
    ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'bmp'}
    
    # Optional Threat Intelligence API
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    # Classroom Demonstration Settings
    CLASSROOM_MODE = True
    PORT = int(os.environ.get('PORT', 5000))
    HOST = os.environ.get('HOST', '0.0.0.0')

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
