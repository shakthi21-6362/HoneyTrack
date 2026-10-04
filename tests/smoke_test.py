"""Quick smoke test for HoneyTrack integration."""

import sys
import os

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)

print("=" * 50)
print("HoneyTrack Integration Smoke Test")
print("=" * 50)

# Test 1: Database
print("\n[1/5] Testing database initialization...")
from database.database import init_db, SessionLocal
init_db()
print("  [OK] Database initialized")

# Test 2: Demo event generation
print("\n[2/5] Testing demo event generation...")
from demo import generate_demo_event
event = generate_demo_event()
print(f"  [OK] Generated: {event['source_ip']} -> {event['service']} | {event['attack_type']} | Risk: {event['risk_score']}")

# Test 3: Save event
print("\n[3/5] Testing event persistence...")
from database.repositories import save_event
db = SessionLocal()
saved = save_event(db, event)
print(f"  [OK] Event saved with ID: {saved.id}")
db.close()

# Test 4: Read events back
print("\n[4/5] Testing event retrieval...")
from database.repositories import get_events, get_total_events, get_unique_ips
db = SessionLocal()
events = get_events(db, limit=10)
total = get_total_events(db)
unique = get_unique_ips(db)
print(f"  [OK] Retrieved {len(events)} events | Total: {total} | Unique IPs: {unique}")
db.close()

# Test 5: Analysis pipeline
print("\n[5/5] Testing analysis pipeline...")
from analysis.fingerprint import analyze_event
result = analyze_event(
    source_ip="8.8.8.8",
    service="SSH",
    username="root",
    password="123456",
    command="whoami",
    attempt_count=5
)
print(f"  [OK] Analysis: type={result['attack_type']} | risk={result['risk_score']} | level={result['risk_level']}")

print("\n" + "=" * 50)
print("  ALL TESTS PASSED [OK]")
print("=" * 50)
