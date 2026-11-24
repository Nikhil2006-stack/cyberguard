import pytest

def test_student_authentication(client):
    # Valid login for student_a
    resp = client.post('/login', data={'username': 'student_a', 'password': 'student_a_pass'}, follow_redirects=True)
    assert resp.status_code == 200
    assert b'Welcome back' in resp.data or b'student_a' in resp.data

    # Log out
    client.get('/logout')

    # Invalid login with bad password
    bad_resp = client.post('/login', data={'username': 'student_a', 'password': 'wrongpassword'}, follow_redirects=True)
    assert b'Invalid username or password' in bad_resp.data

def test_vulnerable_idor_endpoint_reproduces_vulnerability(auth_client_student_a):
    """
    ETHICAL HACKING VERIFICATION:
    Verify that Student A (User ID 2, Profile ID 1) can access Student B's
    private profile (#2) through the deliberately vulnerable endpoint.
    """
    response = auth_client_student_a.get('/lab/vulnerable/profile/2')
    assert response.status_code == 200
    data = response.get_json()
    
    assert data['endpoint_status'] == 'VULNERABLE'
    # Check that Student B's confidential record was leaked!
    assert data['profile_data']['full_name'] == 'Bianca Chen'
    assert 'emergency_contact' in data['profile_data']
    assert 'Arthur Chen' in data['profile_data']['emergency_contact']

def test_secured_endpoint_blocks_unauthorized_idor(auth_client_student_a):
    """
    DEFENSIVE REMEDIATION VERIFICATION:
    Verify that when Student A attempts unauthorized access to Student B's
    profile (#2) through the secured endpoint, access is strictly BLOCKED with HTTP 403.
    """
    response = auth_client_student_a.get('/lab/secured/profile/2')
    assert response.status_code == 403
    data = response.get_json()
    assert data['endpoint_status'] == 'SECURED'
    assert 'Access Denied' in data['message']

def test_secured_endpoint_allows_authorized_owner_access(auth_client_student_a):
    """
    Verify that Student A CAN view their OWN profile (#1) on the secured endpoint.
    """
    response = auth_client_student_a.get('/lab/secured/profile/1')
    assert response.status_code == 200
    data = response.get_json()
    assert data['endpoint_status'] == 'SECURED'
    assert data['profile_data']['full_name'] == 'Alex Rivera'

def test_secured_endpoint_requires_authentication(client):
    """
    Verify that unauthenticated anonymous callers are redirected to login.
    """
    response = client.get('/lab/secured/profile/1')
    # Flask-Login redirects unauthenticated requests (302) to login view
    assert response.status_code == 302
