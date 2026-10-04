def calculate_risk_score(
    service=None,
    username=None,
    password=None,
    command=None,
    attempt_count=1,
    is_tor=False
):
    """
    Calculate a risk score between 0 and 100.

    This is a rule-based scoring system for HoneyTrack v1.
    """

    score = 0

    # --------------------------------------------------
    # 1. Base score
    # --------------------------------------------------

    score += 10

    # --------------------------------------------------
    # 2. Repeated login attempts
    # --------------------------------------------------

    if attempt_count >= 5:
        score += 15

    if attempt_count >= 10:
        score += 10

    # --------------------------------------------------
    # 3. Suspicious usernames
    # --------------------------------------------------

    suspicious_usernames = {
        "admin",
        "administrator",
        "root",
        "test",
        "user",
        "guest"
    }

    if username and username.lower() in suspicious_usernames:
        score += 10

    # --------------------------------------------------
    # 4. Suspicious/common passwords
    # --------------------------------------------------

    common_passwords = {
        "123456",
        "password",
        "admin",
        "admin123",
        "12345678",
        "qwerty",
        "root"
    }

    if password and password.lower() in common_passwords:
        score += 15

    # --------------------------------------------------
    # 5. Command analysis
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
            score += 15

    # --------------------------------------------------
    # 6. TOR
    # --------------------------------------------------

    if is_tor:
        score += 10

    # --------------------------------------------------
    # 7. Limit score
    # --------------------------------------------------

    score = min(score, 100)

    return score


def get_risk_level(score):
    """
    Convert a numeric risk score into a severity level.
    """

    if score <= 30:
        return "LOW"

    if score <= 60:
        return "MEDIUM"

    if score <= 80:
        return "HIGH"

    return "CRITICAL"