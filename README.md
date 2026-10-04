# 🍯 HoneyTrack

**Real-Time Honeypot Intelligence System**

HoneyTrack is a defensive cybersecurity tool that deploys fake internet-facing services (SSH, HTTP, FTP) to attract and profile real-world attackers. Every connection attempt is logged, geolocated, fingerprinted, risk-scored, and displayed on a live dashboard with an interactive world map.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-green?logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Fake SSH Server** | Paramiko-based SSH honeypot with shell emulation (port 2222) |
| **Fake HTTP Server** | Admin login page that captures form submissions (port 8080) |
| **Fake FTP Server** | FTP server that logs all login attempts (port 2121) |
| **IP Geolocation** | Country, city, ISP, lat/lon via ip-api.com |
| **TOR Detection** | Identifies proxy/VPN/TOR connections |
| **Attack Classification** | Brute force, credential spray, exploit attempt, recon |
| **Risk Scoring** | 0–100 score based on credentials, commands, TOR usage |
| **Live Dashboard** | World map, attack feed, event table — auto-updates every 3s |
| **Demo Mode** | Generate realistic fake attacks for presentations |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd Honeytrack

# Create virtual environment
python -m venv .venv

# Activate it
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running

```bash
# Demo mode (recommended for first run / presentations)
python main.py --demo

# Demo-only mode (no listeners, just dashboard + fake events)
python main.py --demo-only

# Production mode (all listeners active)
python main.py

# Custom options
python main.py --demo --no-ftp --dashboard-port 8000
```

Then open **http://localhost:5000** in your browser.

---

## 📊 Dashboard

The dashboard provides real-time visibility into attack activity:

- **Stats Bar** — Total attacks, unique IPs, countries, last attack
- **World Map** — Leaflet.js with CartoDB Dark tiles, attack markers with pulse animation
- **Live Feed** — Scrolling attack feed with service badges and risk bars
- **Event Table** — Paginated table with all attack details and risk visualization

---

## 🏗️ Architecture

```
                     ┌──────────────┐
                     │   Attacker   │
                     └──────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
         Port 2222     Port 8080     Port 2121
              │             │             │
        ┌─────┴─────┐ ┌────┴────┐ ┌─────┴─────┐
        │ SSH Honey  │ │  HTTP   │ │ FTP Honey  │
        │   pot      │ │Honeypot │ │   pot      │
        └─────┬──────┘ └────┬────┘ └─────┬──────┘
              │             │             │
              └─────────────┼─────────────┘
                            │
                   ┌────────┴────────┐
                   │ Analysis Engine │
                   │  • Geolocation  │
                   │  • Risk Scoring │
                   │  • Classifier   │
                   └────────┬────────┘
                            │
                   ┌────────┴────────┐
                   │  SQLite / ORM   │
                   └────────┬────────┘
                            │
                   ┌────────┴────────┐
                   │   Dashboard     │
                   │   (Port 5000)   │
                   │  • REST API     │
                   │  • World Map    │
                   │  • Live Feed    │
                   └─────────────────┘
```

---

## 📁 Project Structure

```
Honeytrack/
├── main.py                         # Entry point (--demo flag)
├── demo.py                         # Demo mode attack generator
├── requirements.txt                # Python dependencies
├── config/
│   └── settings.py                 # Centralized configuration
├── analysis/
│   ├── classifier.py               # Attack classification engine
│   ├── fingerprint.py              # Attacker fingerprinting pipeline
│   ├── geolocation.py              # IP geolocation (ip-api.com)
│   └── risk.py                     # Risk scoring (0–100)
├── database/
│   ├── database.py                 # SQLAlchemy engine + sessions
│   ├── models.py                   # AttackEvent model
│   └── repositories.py            # Database CRUD operations
├── honeypot/
│   ├── ssh_listener.py             # Fake SSH server (Paramiko)
│   ├── http_listener.py            # Fake HTTP admin login (Flask)
│   └── ftp_listener.py            # Fake FTP server (pyftpdlib)
├── sessions/
│   └── session_manager.py          # Active session tracking
├── api/
│   ├── app.py                      # Flask dashboard application
│   └── routes.py                   # REST API endpoints
├── dashboard/
│   ├── templates/
│   │   └── dashboard.html          # Dashboard UI template
│   └── static/
│       ├── css/dashboard.css       # Dark theme styles
│       └── js/dashboard.js         # Real-time polling + map
└── tests/
    ├── test_classifier.py
    ├── test_database.py
    ├── test_geolocation.py
    └── test_risk.py
```

---

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard UI |
| `/api/events` | GET | Paginated events list (supports `limit`, `offset`, `service`, `min_risk` filters) |
| `/api/events/latest` | GET | Poll for new events since `since_id` |
| `/api/stats` | GET | Aggregate statistics (totals, top countries, risk distribution) |
| `/api/map-data` | GET | Geolocation data for map markers |

---

## ⚙️ Configuration

All configuration is centralized in [`config/settings.py`](config/settings.py):

| Setting | Default | Description |
|---------|---------|-------------|
| `SSH_PORT` | 2222 | SSH honeypot port |
| `HTTP_PORT` | 8080 | HTTP honeypot port |
| `FTP_PORT` | 2121 | FTP honeypot port |
| `DASHBOARD_PORT` | 5000 | Dashboard web UI port |
| `DATABASE_URL` | `sqlite:///honeytrack.db` | Database connection string |

---

## 🛡️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Fake SSH | Paramiko — RSA key, fake shell, auth capture |
| Fake HTTP | Flask — Login page, form capture |
| Fake FTP | pyftpdlib — FTP auth capture |
| Database | SQLAlchemy + SQLite (PostgreSQL ready) |
| Geolocation | ip-api.com (free tier) |
| Dashboard | Flask + Leaflet.js + CartoDB Dark |
| Frontend | JetBrains Mono, vanilla JS |

---

## ⚠️ Disclaimer

> This tool is intended for **academic and defensive security purposes only**. HoneyTrack does not facilitate offensive actions. Always deploy on isolated systems and comply with applicable laws.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
