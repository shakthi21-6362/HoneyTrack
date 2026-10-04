def classify_attack(
    service=None,
    username=None,
    password=None,
    command=None,
    attempt_count=1
):
    """
    Classify an attack using simple rule-based logic.

    Returns:
        brute_force
        credential_spray
        recon
        exploit_attempt
        credential_attempt
    """

    # --------------------------------------------------
    # 1. Brute force
    # --------------------------------------------------

    if attempt_count >= 5:
        return "brute_force"

    # --------------------------------------------------
    # 2. Credential spray
    # --------------------------------------------------

    if username and attempt_count >= 3:
        return "credential_spray"

    # --------------------------------------------------
    # 3. Reconnaissance
    # --------------------------------------------------

    if command:

        command_lower = command.lower()

        recon_commands = {
            "whoami",
            "id",
            "uname",
            "hostname",
            "pwd",
            "ls",
            "ifconfig",
            "ip addr"
        }

        if command_lower in recon_commands:
            return "recon"

    # --------------------------------------------------
    # 4. Basic exploit indicators
    # --------------------------------------------------

    if command:

        command_lower = command.lower()

        exploit_indicators = {
            "wget",
            "curl",
            "nc",
            "netcat",
            "chmod",
            "bash -c"
        }

        for indicator in exploit_indicators:
            if indicator in command_lower:
                return "exploit_attempt"

    # --------------------------------------------------
    # 5. Default
    # --------------------------------------------------

    return "credential_attempt"