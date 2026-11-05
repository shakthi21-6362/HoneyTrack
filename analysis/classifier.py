def classify_attack(
    service=None,
    username=None,
    password=None,
    command=None,
    attempt_count=1
):
    """
    Classify an attack using rule-based logic.

    Returns:
        reverse_shell
        malware_download
        privilege_escalation
        exploit_attempt
        recon
        brute_force
        credential_spray
        credential_attempt
    """
    cmd_lower = (command or "").strip().lower()

    # 1. Reverse shell detection
    if cmd_lower:
        revshell_keywords = ["nc -e", "/bin/sh", "/bin/bash", "bash -i", "/dev/tcp/", "pty.spawn", "mkfifo", "socat"]
        if any(k in cmd_lower for k in revshell_keywords):
            return "reverse_shell"

    # 2. Malware download detection
    if cmd_lower:
        download_keywords = ["wget", "curl", "ftpget", "tftp", "certutil", "bitsadmin"]
        if any(k in cmd_lower for k in download_keywords):
            return "malware_download"

    # 3. Privilege escalation
    if cmd_lower:
        privesc_keywords = ["sudo", "chmod +x", "chmod 777", "chown", "useradd", "chpasswd", "/etc/sudoers"]
        if any(k in cmd_lower for k in privesc_keywords):
            return "privilege_escalation"

    # 4. Reconnaissance
    if cmd_lower:
        recon_keywords = [
            "whoami", "id", "uname", "hostname", "pwd", "ls", "ifconfig",
            "ip addr", "ip a", "netstat", "ps aux", "ps -ef", "cat /etc/passwd",
            "cat /etc/shadow", "cat /etc/issue", "lscpu"
        ]
        if any(k in cmd_lower for k in recon_keywords):
            return "recon"

    # 5. Exploit indicators (SQLi, path traversal, injection)
    if cmd_lower:
        exploit_indicators = ["' or '1'='1", "union select", "../", "jndi:", "cat <(", "bash -c", "system("]
        if any(k in cmd_lower for k in exploit_indicators):
            return "exploit_attempt"

    # 6. Brute force / Credential spray / Attempt
    if attempt_count >= 5:
        return "brute_force"

    if username and attempt_count >= 3:
        return "credential_spray"

    return "credential_attempt"