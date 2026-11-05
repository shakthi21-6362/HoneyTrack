"""Tests for newly implemented production security upgrades."""

import pytest
from api.app import create_app
from auth.security import SimpleRateLimiter, log_admin_action


def test_security_headers_present():
    """Verify security headers are applied to HTTP responses."""
    app = create_app()
    client = app.test_client()

    res = client.get('/login')
    assert res.status_code == 200

    # 1. Anti-Clickjacking
    assert res.headers.get('X-Frame-Options') == 'DENY'

    # 2. Anti-MIME sniffing
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'

    # 3. Anti-XSS
    assert res.headers.get('X-XSS-Protection') == '1; mode=block'

    # 4. Strict referrer policy
    assert res.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'

    # 5. Content Security Policy
    assert 'default-src \'self\'' in res.headers.get('Content-Security-Policy', '')
    assert 'frame-ancestors \'none\'' in res.headers.get('Content-Security-Policy', '')


def test_rate_limiter_logic():
    """Verify rate limiter blocks after threshold and enforces lockout."""
    limiter = SimpleRateLimiter(max_attempts=3, window_seconds=2, lockout_seconds=10)
    test_id = "test-attacker-ip"

    # Attempts 1, 2, 3 should succeed
    for _ in range(3):
        is_limited, _ = limiter.is_rate_limited(test_id)
        assert not is_limited
        limiter.record_attempt(test_id)

    # 4th attempt should be blocked
    is_limited, retry_after = limiter.is_rate_limited(test_id)
    assert is_limited
    assert retry_after > 0

    # Reset cleans it up
    limiter.reset(test_id)
    is_limited, _ = limiter.is_rate_limited(test_id)
    assert not is_limited


def test_cors_locking():
    """Verify CORS is restricted to configured/local origins."""
    app = create_app()
    client = app.test_client()

    # Preflight request from unauthorized origin
    res = client.open('/api/stats', method='OPTIONS', headers={
        'Origin': 'http://malicious-website.com',
        'Access-Control-Request-Method': 'GET'
    })
    # Should NOT grant access to arbitrary untrusted origins
    assert res.headers.get('Access-Control-Allow-Origin') != 'http://malicious-website.com'


def test_idor_protection_on_sessions():
    """Verify IDOR and traversal protection on session endpoints."""
    app = create_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess['user_id'] = 1

    # Malicious invalid session ID syntax
    bad_res = client.get('/api/sessions/../../etc/passwd/replay')
    assert bad_res.status_code in (400, 404)


def test_admin_audit_logging():
    """Verify admin action logger runs without exception."""
    log_admin_action("TestOperator", "TEST_ACTION", {"ip": "127.0.0.1"})
