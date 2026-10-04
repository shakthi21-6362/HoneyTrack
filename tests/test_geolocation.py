import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.geolocation import get_geolocation


def test_private_ip():

    result = get_geolocation("127.0.0.1")

    print("Private IP test:")
    print(result)


def test_public_ip():

    # Public example IP used only for testing.
    result = get_geolocation("8.8.8.8")

    print()
    print("Public IP test:")
    print(result)


if __name__ == "__main__":
    test_private_ip()
    test_public_ip()