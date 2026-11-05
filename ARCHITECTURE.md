# 🍯 HoneyTrack — Architecture & Tech Stack Specification

This document details the complete technology stack, system architecture, and end-to-end data flow for **HoneyTrack: Real-Time Honeypot Intelligence & Active Defense Platform**.

---

## 🛠️ Technology Stack Breakdown

| Architectural Layer | Component | Technology / Library | Role & Functionality |
| :--- | :--- | :--- | :--- |
| **Decoy Honeypots** | SSH Decoy | `Paramiko (5.0.0)` | Emulated root shell, auth capture, keystroke session recorder (Port 2222) |
| | HTTP Decoy | `Flask (3.1.3)` | Fake admin login portal capturing credentials & user agents (Port 8080) |
| | FTP Decoy | `pyftpdlib (2.2.0)` | Fake file storage, credential interception, anonymous trap (Port 2121) |
| **Intelligence Engine** | Feature Pipeline | `NumPy`, `Regex`, Shannon Entropy | Obfuscation detection, command tokenization, frequency scoring |
| | Attack Classifier | `Scikit-Learn` (Random Forest) | Categorizes attacks into 8 classes + MITRE ATT&CK mapping |
| | Geolocation & Tor | `ip-api.com`, `Tor Project DNSEL` | Real-time country/city/ISP resolution & Tor Exit node cache |
| | Risk Scorer | Custom Heuristic Engine | Scores threat level from 0 to 100 based on adversary behavior |
| **Defensive Actions** | Active Firewall | `UFW`, `iptables`, `Windows netsh` | Automated threat dropping & copyable host firewall rules |
| | Email Alerts | `smtplib`, `email.mime` | Async executive incident dispatches with embedded forensic evidence |
| | Node Federation | `HMAC-SHA256`, `requests` | Cross-node IoC synchronization & collaborative mesh defense |
| **Data & Storage** | Primary Engine | **TimescaleDB / PostgreSQL 16** | High-throughput time-series hypertables with zero-lock concurrency |
| | Standalone Engine | **SQLite3** | Local zero-dependency database for fast test deployments |
| | ORM & Pooling | `SQLAlchemy (2.0.52)` + `psycopg 3` | Parameterized SQL queries, connection pooling, dynamic migrations |
| **Operator Console** | Web Framework | `Flask`, `Flask-Cors` | Authenticated management portal & REST API (Port 5000) |
| | Security Suite | In-memory sliding rate limiter | Brute-force protection, CSP, security headers, audit logging |
| | PDF Generator | `ReportLab (5.0.1)` | Tactical HackerOne-styled cybersecurity incident reports |
| | Frontend UI | `Vanilla JS`, `Leaflet.js`, `CartoDB` | Dark-mode interactive world map, real-time live attack feed |
| **DevOps & Deploy** | Containerization | `Docker (Multi-stage)`, `Compose` | 1-command deployment with profiles (`default`, `timescale`) |
| | Automation | `deploy.ps1`, `deploy.sh` | Cross-platform one-click automated bootstrap scripts |

---

## 🌊 System Architecture & Data Flow Diagram

```mermaid
flowchart TD
    classDef adversary fill:#2d0a10,stroke:#dc2626,stroke-width:2px,color:#ffffff;
    classDef decoys fill:#111827,stroke:#3b82f6,stroke-width:2px,color:#ffffff;
    classDef pipeline fill:#1e1b4b,stroke:#818cf8,stroke-width:2px,color:#ffffff;
    classDef storage fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#ffffff;
    classDef defense fill:#451a03,stroke:#f59e0b,stroke-width:2px,color:#ffffff;
    classDef operator fill:#0f172a,stroke:#06b6d4,stroke-width:2px,color:#ffffff;

    subgraph ATTACKERS ["Threat Actors & Ingress Traffic"]
        A1["Botnet / Automated Scanners"]:::adversary
        A2["Brute-Force Attackers"]:::adversary
        A3["Tor Anonymized Exit Nodes"]:::adversary
    end

    subgraph HONEYPOT_DECOYS ["Decoy Honeypot Layer"]
        D_SSH["SSH Decoy (Port 2222)<br/>Paramiko Fake Shell"]:::decoys
        D_HTTP["HTTP Decoy (Port 8080)<br/>Fake Admin Login"]:::decoys
        D_FTP["FTP Decoy (Port 2121)<br/>pyftpdlib Fake Storage"]:::decoys
        REC["Asciinema v2 Keystroke<br/>Session Recorder"]:::decoys
    end

    A1 -->|TCP 8080| D_HTTP
    A2 -->|TCP 2222| D_SSH
    A2 -->|TCP 2121| D_FTP
    A3 -->|Tor Relays| D_SSH
    D_SSH -->|Capture Keystrokes| REC

    subgraph ANALYSIS_PIPELINE ["Analysis & Machine Learning Pipeline"]
        GEO["GeoIP & Tor Detector<br/>(ip-api & Tor DNSEL)"]:::pipeline
        ML["Random Forest Classifier<br/>(Scikit-Learn & Feature Vectors)"]:::pipeline
        MITRE["MITRE ATT&CK Mapper<br/>(T1110, T1082, T1059)"]:::pipeline
        RISK["Heuristic Risk Scorer<br/>(Score 0 to 100)"]:::pipeline
    end

    D_HTTP -->|Payload & Headers| GEO
    D_SSH -->|Commands & Auth| GEO
    D_FTP -->|User & Password| GEO

    GEO --> ML
    ML --> MITRE
    MITRE --> RISK

    subgraph DEFENSE_ACTIONS ["Defensive Automation"]
        FW["Active Defense Firewall<br/>(UFW, iptables, netsh)"]:::defense
        MAIL["Executive Alert Dispatcher<br/>(SMTP Gmail + Evidence)"]:::defense
        FED["Federation Sync Mesh<br/>(HMAC-SHA256 Signed IoCs)"]:::defense
    end

    RISK -->|Risk >= 85 or Tor Block| FW
    RISK -->|Risk >= 70 or Tor| MAIL
    RISK -->|Share IoCs| FED

    subgraph STORAGE_LAYER ["Persistent Data Layer"]
        TS_DB[("TimescaleDB (Port 5432)<br/>PostgreSQL Hypertables")]:::storage
        SQLITE_DB[("SQLite3 Standalone<br/>honeytrack.db")]:::storage
    end

    RISK -->|Save Event Telemetry| TS_DB
    RISK -.->|Fallback Storage| SQLITE_DB
    REC -->|Save Terminal Sessions| TS_DB
    FW -->|Save Blacklisted IPs| TS_DB

    subgraph OPERATOR_CONSOLE ["Operator Management Console (Port 5000)"]
        SEC_GATE["Security Gateway<br/>(Rate Limiter + CSP + Auth Guard)"]:::operator
        API["Flask REST API Engine<br/>(/api/events, /api/stats)"]:::operator
        UI["Real-Time Dashboard<br/>(World Map + Live Attack Feed)"]:::operator
        PDF["ReportLab PDF Engine<br/>(HackerOne Security Advisories)"]:::operator
        AUDIT["Security Action Audit Log"]:::operator
    end

    USER["Security Operator"]:::operator
    USER -->|Port 5000 / HTTPS| SEC_GATE
    SEC_GATE --> API
    API --> UI
    API --> PDF
    API -->|Read Telemetry| TS_DB
    SEC_GATE --> AUDIT
```

---

## 🔁 Execution Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Adversary / Botnet
    participant Decoy as Honeypot Listeners (SSH/HTTP/FTP)
    participant Pipeline as Analysis & ML Classifier
    participant DB as TimescaleDB / SQLite
    participant Defense as Active Defense (Firewall & Alerts)
    participant Console as Operator Dashboard

    Attacker->>Decoy: Inbound connection & credential / command payload
    Decoy->>Pipeline: Raw telemetry (IP, Port, Payload, Headers)
    
    rect rgb(20, 25, 45)
        Note over Pipeline: Enrichment & Attribution
        Pipeline->>Pipeline: Resolve Country, City, ISP & Tor Relay Check
        Pipeline->>Pipeline: Extract Shannon Entropy & Numeric Features
        Pipeline->>Pipeline: Random Forest ML predicts attack type
        Pipeline->>Pipeline: Map to MITRE ATT&CK & Calculate 0-100 Risk Score
    end

    Pipeline->>DB: INSERT into attack_events (Time-Series Hypertable)
    
    alt Risk Score >= 85 (Critical Incursion)
        Pipeline->>Defense: Auto-Blacklist IP in active defense cache
        Defense->>Defense: Generate UFW / iptables / netsh drop rules
    end

    alt Risk Score >= 70 (Executive Alert)
        Pipeline->>Defense: Dispatch asynchronous HTML forensic alert email
    end

    Console->>DB: Poll /api/events/latest & /api/stats
    DB-->>Console: Stream enriched coordinates, risk scores, and attack types
    Console-->>Console: Pulse attack marker on Leaflet World Map & update live feed
```
