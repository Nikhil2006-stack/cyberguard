import pytest
import os
from app import create_app
from database import db
from models import User, StudentProfile

@pytest.fixture
def app():
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    os.environ['TESTING'] = 'True'
    application = create_app()
    application.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False
    })

    with application.app_context():
        db.create_all()
        # Seed test users
        from app import seed_database
        seed_database()
        yield application
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def auth_client_student_a(client):
    # Log in as student_a
    client.post('/login', data={'username': 'student_a', 'password': 'student_a_pass'}, follow_redirects=True)
    return client

@pytest.fixture
def auth_client_student_b(client):
    # Log in as student_b
    client.post('/login', data={'username': 'student_b', 'password': 'student_b_pass'}, follow_redirects=True)
    return client
