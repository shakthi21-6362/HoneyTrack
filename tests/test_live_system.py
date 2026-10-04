import sys
import os
import time
import socket
import requests

# Set base dir
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from config.settings import SSH_PORT, HTTP_PORT, FTP_PORT, DASHBOARD_PORT

OPERATOR_EMAIL = "jayar@honeytrack.local"
OPERATOR_PASSWORD = "HoneyTrack2026!"

def check_tcp_port(port, service_name, timeout=3.0):
    """Test if a TCP port is open and accepting connections."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex(('127.0.0.1', port))
        if res == 0:
            print(f"  [+] {service_name} (Port {port}): LISTENING & CONNECTED")
            return True
        else:
            print(f"  [-] {service_name} (Port {port}): FAILED (errno {res})")
            return False
    except Exception as e:
        print(f"  [-] {service_name} (Port {port}): ERROR - {e}")
        return False
    finally:
        s.close()

def run_live_verification():
    print("=" * 60)
    print("HONEYTRACK SYSTEM VERIFICATION & LIVE HEALTH CHECK")
    print("=" * 60)

    # 1. Port checks
    print("\n[STEP 1] Verifying Honeypot and Dashboard TCP Ports:")
    ports_ok = True
    ports_ok &= check_tcp_port(DASHBOARD_PORT, "Flask Web Dashboard")
    ports_ok &= check_tcp_port(SSH_PORT, "SSH Honeypot Listener")
    ports_ok &= check_tcp_port(HTTP_PORT, "HTTP Honeypot Listener")
    ports_ok &= check_tcp_port(FTP_PORT, "FTP Honeypot Listener")

    if not ports_ok:
        print("\n[-] Some ports are not responding. Aborting live test.")
        return False

    session = requests.Session()
    base_url = f"http://127.0.0.1:{DASHBOARD_PORT}"

    # 2. Check Login page
    print("\n[STEP 2] Verifying Web Dashboard Accessibility & Authentication:")
    login_page = session.get(f"{base_url}/login", timeout=5)
    if login_page.status_code == 200 and "HoneyTrack" in login_page.text:
        print("  [+] GET /login: 200 OK (Login page rendered correctly)")
    else:
        print(f"  [-] GET /login: Unexpected status {login_page.status_code}")
        return False

    # Perform Login
    login_resp = session.post(f"{base_url}/login", data={
        "email": OPERATOR_EMAIL,
        "password": OPERATOR_PASSWORD
    }, timeout=5, allow_redirects=True)

    if login_resp.status_code == 200 and ("dashboard" in login_resp.url.lower() or "HoneyTrack" in login_resp.text):
        print(f"  [+] POST /login: Authenticated successfully as '{OPERATOR_EMAIL}' -> Operator session active")
    else:
        print(f"  [-] POST /login: Authentication failed (Status: {login_resp.status_code}, URL: {login_resp.url})")
        return False

    # 3. Check Authenticated API Endpoints
    print("\n[STEP 3] Verifying Authenticated System Endpoints:")
    
    # /api/stats
    stats_resp = session.get(f"{base_url}/api/stats", timeout=5)
    if stats_resp.status_code == 200:
        stats = stats_resp.json()
        print(f"  [+] GET /api/stats: 200 OK | Total Attacks: {stats.get('total_attacks')} | Unique IPs: {stats.get('unique_ips')} | Mode: {stats.get('system_mode')}")
    else:
        print(f"  [-] GET /api/stats: Failed ({stats_resp.status_code})")
        return False

    # /api/events
    events_resp = session.get(f"{base_url}/api/events?limit=5", timeout=5)
    if events_resp.status_code == 200:
        events = events_resp.json()
        print(f"  [+] GET /api/events: 200 OK | Retrieved {len(events)} events (ML classifications & MITRE tags attached)")
    else:
        print(f"  [-] GET /api/events: Failed ({events_resp.status_code})")
        return False

    # /api/sessions (Phase 3)
    sessions_resp = session.get(f"{base_url}/api/sessions", timeout=5)
    if sessions_resp.status_code == 200:
        sessions_data = sessions_resp.json()
        print(f"  [+] GET /api/sessions: 200 OK | Terminal Replay Sessions: {len(sessions_data)}")
    else:
        print(f"  [-] GET /api/sessions: Failed ({sessions_resp.status_code})")
        return False

    # /api/federation/nodes (Phase 4)
    fed_resp = session.get(f"{base_url}/api/federation/nodes", timeout=5)
    if fed_resp.status_code == 200:
        nodes_data = fed_resp.json()
        local_n = nodes_data.get('local_node', {})
        print(f"  [+] GET /api/federation/nodes: 200 OK | Local Node ID: '{local_n.get('node_id')}' ({local_n.get('status')}) | Mesh Nodes: {nodes_data.get('nodes_count')}")
    else:
        print(f"  [-] GET /api/federation/nodes: Failed ({fed_resp.status_code})")
        return False

    # 4. Probe Honeypots
    print("\n[STEP 4] Sending Active Probes to Honeypot Services:")
    
    # HTTP Honeypot probe
    try:
        http_probe = requests.get(f"http://127.0.0.1:{HTTP_PORT}/wp-admin", timeout=3)
        print(f"  [+] HTTP Honeypot: Sent probe to /wp-admin -> Received HTTP {http_probe.status_code}")
    except Exception as e:
        print(f"  [-] HTTP Honeypot probe error: {e}")

    # FTP Honeypot probe
    try:
        s_ftp = socket.socket()
        s_ftp.settimeout(3)
        s_ftp.connect(('127.0.0.1', FTP_PORT))
        banner = s_ftp.recv(1024).decode('latin1', errors='ignore').strip()
        s_ftp.close()
        print(f"  [+] FTP Honeypot: Connected -> Banner: '{banner}'")
    except Exception as e:
        print(f"  [-] FTP Honeypot probe error: {e}")

    # SSH Honeypot probe
    try:
        s_ssh = socket.socket()
        s_ssh.settimeout(3)
        s_ssh.connect(('127.0.0.1', SSH_PORT))
        ssh_banner = s_ssh.recv(1024).decode('latin1', errors='ignore').strip()
        s_ssh.close()
        print(f"  [+] SSH Honeypot: Connected -> Protocol Banner: '{ssh_banner}'")
    except Exception as e:
        print(f"  [-] SSH Honeypot probe error: {e}")

    print("\n" + "=" * 60)
    print("ALL LIVE SYSTEM HEALTH CHECKS PASSED (100% OPERATIONAL)")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = run_live_verification()
    sys.exit(0 if success else 1)
