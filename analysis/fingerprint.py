from .risk import calculate_risk_score, get_risk_level
from .classifier import classify_attack
from .geolocation import get_geolocation
import threading
from datetime import datetime
from config import settings
from alerts.email_alerts import send_alert_email

def analyze_event(
    source_ip=None,
    service=None,
    username=None,
    password=None,
    command=None,
    attempt_count=1
):
    """
    Analyze a raw HoneyTrack event.

    Returns:
        attack_type
        risk_score
        risk_level
        geolocation information
    """

    # -----------------------------------------------
    # 1. Attack classification (ML Model + MITRE mapping)
    # -----------------------------------------------
    geo = get_geolocation(source_ip)
    is_tor_flag = bool(geo.get("is_tor", False))

    from .ml_classifier import classify_attack_ml
    ml_result = classify_attack_ml(
        service=service,
        username=username,
        password=password,
        command=command,
        attempt_count=attempt_count,
        is_tor=is_tor_flag
    )
    attack_type = ml_result.get("attack_type", "credential_attempt")

    # -----------------------------------------------
    # 3. Risk calculation
    # -----------------------------------------------

    risk_score = calculate_risk_score(
        service=service,
        username=username,
        password=password,
        command=command,
        attempt_count=attempt_count,
        is_tor=geo["is_tor"]
    )

    risk_level = get_risk_level(risk_score)

    # -----------------------------------------------
    # 4. Combine everything
    # -----------------------------------------------

    result = {
        "attack_type": attack_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "latitude": geo["latitude"],
        "longitude": geo["longitude"],
        "is_tor": geo["is_tor"],
        "ml_confidence": ml_result.get("confidence", 0.9),
        "anomaly_score": ml_result.get("anomaly_score", 0),
        "mitre_id": ml_result.get("mitre_id", "T1078"),
        "mitre_name": ml_result.get("mitre_name", "Valid Accounts")
    }

    if hasattr(settings, 'EMAIL_ALERTS_ENABLED') and settings.EMAIL_ALERTS_ENABLED and risk_score >= settings.ALERT_RISK_THRESHOLD:
        alert_data = result.copy()
        alert_data.update({
            "source_ip": source_ip,
            "service": service,
            "username": username,
            "password": password,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        threading.Thread(target=send_alert_email, args=(alert_data,), daemon=True).start()

    return result