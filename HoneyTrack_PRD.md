# 🍯 HoneyTrack — Product Requirements Document

**Version:** 1.0 | **Status:** In Development | **Team Size:** 2–3 People

---

## Table of Contents

1. [Product Overview](#1-product-overview)
2. [Goals & Non-Goals](#2-goals--non-goals)
3. [Target Users](#3-target-users)
4. [Feature Requirements](#4-feature-requirements)
5. [System Architecture](#5-system-architecture)
6. [Tech Stack](#6-tech-stack)
7. [Risks & Mitigations](#7-risks--mitigations)
8. [Roadmap](#8-roadmap)
9. [Setup & Deployment](#9-setup--deployment)
10. [Team Responsibilities](#10-team-responsibilities)

---

## 1. Product Overview

HoneyTrack is a defensive cybersecurity tool that deploys fake internet-facing services (SSH, HTTP, FTP) to attract and profile real-world attackers. Every connection attempt is logged, geolocated, fingerprinted, risk-scored, and displayed on a live dashboard with a world map.

Unlike traditional intrusion detection systems that only alert on known signatures, HoneyTrack collects rich attacker behavior data passively — with zero impact on real infrastructure.

### 1.1 Problem Statement

Organizations and students have no easy way to observe real-world attack patterns without expensive SIEM tools. There is no lightweight, deployable honeypot system that also provides attacker profiling and a visual dashboard out of the box.

### 1.2 Solution

| Component | What it does |
|---|---|
| **Honeypot Listeners** | Fake SSH, HTTP, and FTP services that mimic real servers |
| **Geolocation** | Country, city, ISP, latitude/longitude from attacker IP |
| **Attack Classification** | Brute force, credential spray, recon, exploit attempt |
| **Risk Scoring** | 0–100 score based on credentials, commands, TOR usage |
| **Real-time Dashboard** | Live world map, attack feed, and event table |
| **Demo Mode** | Generate realistic fake attacks for demos without a VPS |

---

## 2. Goals & Non-Goals

### 2.1 Goals

- Deploy in under 5 minutes on any Linux VPS or local machine
- Capture and store all attacker credential attempts with metadata
- Geolocate every attacker IP and display on an interactive world map
- Classify attack type and calculate a risk score automatically
- Provide a real-time dashboard with no page refresh needed
- Support demo mode for presentations without live internet exposure

### 2.2 Non-Goals

- HoneyTrack does **NOT** actively hack back or counterattack
- HoneyTrack does **NOT** replace enterprise SIEM tools
- HoneyTrack does **NOT** protect production servers — purely observational
- HoneyTrack does **NOT** store full session payloads or files uploaded by attackers

---

## 3. Target Users

| User Type | Description | Primary Use |
|---|---|---|
| CS Students | College students building security projects | Learning, demos, submissions |
| Security Researchers | Studying attack patterns and threat intel | Data collection, analysis |
| CTF Players | Capture The Flag participants | Understanding attacker mindset |
| Sysadmins | Admins wanting to observe threat landscape | Early warning, recon detection |

---

## 4. Feature Requirements

### 4.1 Honeypot Listeners

| Feature | Description | Port | Priority |
|---|---|---|---|
| Fake SSH Server | Accepts any password, logs credentials, emulates Ubuntu shell | 2222 | P0 |
| Fake HTTP Server | Admin login page that captures form submissions | 8080 | P0 |
| Fake FTP Server | FTP server that logs all login attempts | 2121 | P1 |
| Shell Emulation | SSH session stays open, logs commands attacker runs | 2222 | P1 |

### 4.2 Attacker Fingerprinting

| Feature | Description | Priority |
|---|---|---|
| IP Geolocation | Country, city, ISP, lat/lon via ip-api.com | P0 |
| TOR Detection | Cross-checks IP against TOR exit node list | P1 |
| Risk Scoring | 0–100 score based on credentials, commands, attempt count | P0 |
| Attack Classification | Labels: brute_force / recon / exploit_attempt / credential_spray | P0 |
| User Agent Capture | Captures browser/tool user agent for HTTP attacks | P1 |

### 4.3 Dashboard

| Feature | Description | Priority |
|---|---|---|
| Live World Map | Leaflet.js map with attack origin markers, auto-updates | P0 |
| Attack Feed | Scrolling live feed of newest attacks with service badge | P0 |
| Stats Bar | Total attacks, unique IPs, countries, last attack location | P0 |
| Event Table | Paginated table of all events with risk score bar | P1 |
| Auto Refresh | Polls `/api/events` every 3 seconds, no page reload | P0 |
| Dark UI | Hacker-aesthetic dark theme with green accents | P2 |

### 4.4 Demo Mode

Run with `--demo` flag to auto-generate realistic fake attacks every 1–4 seconds. Uses a pool of 15 real IP addresses from countries including Russia, China, Brazil, Romania, Nigeria, and others — with correct geolocation coordinates.

---

## 5. System Architecture

### 5.1 Components

HoneyTrack is composed of four independent layers communicating through a shared SQLite database:

- **Listeners Layer** — SSH, HTTP, FTP fake servers run as daemon threads
- **Analysis Layer** — `fingerprint.py` handles geo, risk scoring, classification
- **Storage Layer** — SQLAlchemy ORM with SQLite (upgradeable to PostgreSQL)
- **Dashboard Layer** — Flask + Leaflet.js + polling API

### 5.2 Data Flow

| Step | What happens |
|---|---|
| 1 | Attacker connects to port 2222 / 8080 / 2121 |
| 2 | Listener captures IP, credentials, commands |
| 3 | `fingerprint.py` geolocates IP, calculates risk, classifies attack |
| 4 | Event saved to SQLite via `save_event()` |
| 5 | Dashboard polls `/api/events` every 3s |
| 6 | New events appear on map + feed + table in real-time |

### 5.3 Project Structure

```
honeytrack/
├── main.py                  ← Entry point (--demo flag)
├── demo.py                  ← Demo mode attack generator
├── requirements.txt
├── honeytrack/
│   ├── listeners/
│   │   ├── ssh_listener.py  ← Fake SSH (paramiko)
│   │   ├── http_listener.py ← Fake HTTP (flask)
│   │   └── ftp_listener.py  ← Fake FTP (pyftpdlib)
│   ├── analysis/
│   │   └── fingerprint.py   ← Geo, risk, classification
│   └── db/
│       └── database.py      ← SQLAlchemy models
└── dashboard/
    ├── app.py               ← Flask API
    └── templates/
        └── dashboard.html   ← Live UI
```

---

## 6. Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Fake SSH | paramiko 3.4 | RSA key, fake shell, auth capture |
| Fake HTTP | Flask 3.0 | Login page, form capture |
| Fake FTP | pyftpdlib 1.5 | FTP auth capture |
| Packet Analysis | scapy 2.5 | Network-level fingerprinting |
| Database ORM | SQLAlchemy 2.0 | AttackEvent model, SQLite storage |
| Geolocation | ip-api.com (free) | Country, city, ISP, lat/lon |
| Dashboard API | Flask + flask-socketio | REST API + real-time events |
| Map | Leaflet.js + CartoDB Dark | Interactive attack world map |
| ML (future) | scikit-learn 1.4 | Attack pattern classification |
| Async | eventlet 0.36 | Non-blocking socket handling |

---

## 7. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Real attackers escalate beyond honeypot | High | Run in isolated VM/VPS, no real services on same host |
| ip-api.com rate limit (45 req/min) | Medium | Cache geolocation results per IP in database |
| SQLite not scalable for high traffic | Low | Swap to PostgreSQL via SQLAlchemy config change |
| Port conflicts on local machine | Low | Use non-standard ports 2222/8080/2121 by default |
| Demo mode data pollutes real data | Low | Use separate DB or clear DB before real deployment |

---

## 8. Roadmap

| Phase | Features | Timeline |
|---|---|---|
| **v1.0** (Current) | SSH + HTTP + FTP listeners, geolocation, risk scoring, live dashboard, demo mode | Week 1–2 |
| **v1.1** | Email alerts on high-risk attacks, PDF report export, TOR detection | Week 3 |
| **v1.2** | ML-based attack classification (scikit-learn), attacker session replay | Week 4 |
| **v2.0** | Multi-honeypot federation, shared threat intelligence feed, REST API | Future |

---

## 9. Setup & Deployment

### 9.1 Local (Demo Mode)

```bash
pip install -r requirements.txt
python main.py --demo
# Open http://localhost:5000
```

### 9.2 VPS (Real Attacks)

```bash
git clone <your-repo>
cd honeytrack
pip install -r requirements.txt
nohup python main.py &
ufw allow 2222 && ufw allow 8080 && ufw allow 2121 && ufw allow 5000
```

Deploy on DigitalOcean, AWS EC2 (free tier), or any Ubuntu VPS. Real bots will find the open ports within hours. 🔥

---

## 10. Team Responsibilities

| Person | Modules | Key Files |
|---|---|---|
| Person 1 | Honeypot Listeners | `ssh_listener.py`, `http_listener.py`, `ftp_listener.py` |
| Person 2 | Analysis & Fingerprinting | `fingerprint.py`, `demo.py`, `database.py` |
| Person 3 | Dashboard & UI | `app.py`, `dashboard.html` |

---

> *This document is intended for academic and defensive security purposes only. HoneyTrack does not facilitate offensive actions.*
