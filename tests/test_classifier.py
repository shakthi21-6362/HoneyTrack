import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.classifier import classify_attack


def test_classifier():

    print("Test 1:")
    print(
        classify_attack(
            service="SSH",
            username="root",
            password="123456",
            attempt_count=10
        )
    )

    print()

    print("Test 2:")
    print(
        classify_attack(
            service="SSH",
            command="whoami"
        )
    )

    print()

    print("Test 3:")
    print(
        classify_attack(
            service="HTTP",
            username="admin"
        )
    )


if __name__ == "__main__":
    test_classifier()