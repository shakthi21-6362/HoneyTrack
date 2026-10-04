import ipaddress
import requests
from analysis.tor_detector import is_tor_exit_node


API_URL = "http://ip-api.com/json"


# Simple in-memory cache.
# Key   = IP address
# Value = geolocation result
geo_cache = {}


def is_private_ip(ip):
    """
    Check whether an IP address is private,
    loopback, reserved, or otherwise not publicly routable.
    """

    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_unspecified
        )

    except ValueError:
        return True


def get_geolocation(ip):
    """
    Get geolocation information for a public IP address.

    Returns a dictionary containing:
        country
        city
        isp
        latitude
        longitude
        is_tor
    """

    # Ignore invalid/private addresses.
    if is_private_ip(ip):
        return {
            "country": None,
            "city": None,
            "isp": None,
            "latitude": None,
            "longitude": None,
            "is_tor": False
        }

    # Return cached result if available.
    if ip in geo_cache:
        return geo_cache[ip]

    fields = (
        "status,message,country,city,isp,"
        "lat,lon,proxy,hosting"
    )

    try:
        response = requests.get(
            f"{API_URL}/{ip}",
            params={"fields": fields},
            timeout=5
        )

        response.raise_for_status()

        data = response.json()

        if data.get("status") != "success":
            print(
                f"[GEO] Lookup failed for {ip}: "
                f"{data.get('message', 'Unknown error')}"
            )

            return {
                "country": None,
                "city": None,
                "isp": None,
                "latitude": None,
                "longitude": None,
                "is_tor": False
            }

        tor_detected = is_tor_exit_node(ip)
        is_tor = tor_detected or bool(data.get("proxy", False))
        isp = "Tor Exit Node" if tor_detected else (data.get("isp") or "Unknown ISP")

        result = {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": isp,
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "is_tor": is_tor
        }

        # Save result in cache.
        geo_cache[ip] = result

        return result

    except requests.RequestException as error:

        print(f"[GEO] Request error for {ip}: {error}")

        return {
            "country": None,
            "city": None,
            "isp": None,
            "latitude": None,
            "longitude": None,
            "is_tor": False
        }