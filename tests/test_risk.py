import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.risk import calculate_risk_score, get_risk_level


def test_low_risk():

    score = calculate_risk_score(
        service="HTTP",
        username="visitor",
        password="hello"
    )

    print("Low-risk test:")
    print("Score:", score)
    print("Level:", get_risk_level(score))


def test_high_risk():

    score = calculate_risk_score(
        service="SSH",
        username="root",
        password="123456",
        command="whoami",
        attempt_count=10,
        is_tor=True
    )

    print("High-risk test:")
    print("Score:", score)
    print("Level:", get_risk_level(score))


if __name__ == "__main__":
    test_low_risk()
    print()
    test_high_risk()