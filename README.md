# AI Cyber Fusion Platform

**Autonomous AI-Powered Threat Detection & SOC-style Behavioral Security Analysis**

> A lightweight AI SOC assistant that combines network scanning, packet analysis, anomaly detection, alert correlation, MITRE ATT&CK mapping, and SOC-style reporting.

---

## Architecture

```
Network Scan (Nmap)
      ↓
Packet Capture / PCAP (Scapy / PyShark)
      ↓
Traffic Analysis → Threat Detection
      ↓
ML Engine (Isolation Forest + Random Forest + DBSCAN)
      ↓
Correlation Engine → Attack Stories
      ↓
AI Risk Scoring + MITRE ATT&CK Mapping
      ↓
AI Explanation (SOC-style)
      ↓
Dashboard (Rich terminal) + Report (HTML/PDF/JSON) + SQLite History
```

---

## Project Structure

```
cyber/
├── backend/
│   ├── api/              FastAPI REST server
│   ├── analyst/          AI-powered SOC recommendations
│   ├── correlation/      Multi-signal alert correlation engine
│   ├── database/         SQLite persistence (scan sessions, alerts, stories)
│   ├── ml/               Isolation Forest, Random Forest, DBSCAN
│   ├── packet_analyzer/  PCAP parser + threat detection rules
│   ├── reports/          HTML + PDF + JSON report generator
│   ├── scanners/         Nmap XML parser
│   ├── threat_intel/     VirusTotal, AbuseIPDB, OTX lookups
│   ├── constants.py      All named constants
│   ├── models.py         Dataclasses for all data structures
│   └── risk_engine.py    Weighted risk scoring
├── frontend/
│   └── dashboard.py      Rich terminal dashboard
├── samples/
│   ├── nmap/             Sample Nmap XML scans
│   └── pcaps/            Place PCAP files here
├── models/               Saved ML models (.pkl)
├── reports/              Generated reports (HTML/JSON)
├── main.py               CLI entry point
├── config.yaml           Configuration
├── Dockerfile            Container image definition
├── docker-compose.yml    Compose stack
└── requirements.txt      Dependencies
```

---

## Installation

### Local (venv)

```bash
# Mac / Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

# Optional: configure API keys for threat intelligence
cp .env.example .env
# Edit .env and add: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY
```

### Docker

```bash
# Build and start
docker compose up --build

# With threat intel API keys
VIRUSTOTAL_API_KEY=xxx ABUSEIPDB_API_KEY=yyy docker compose up --build
```

The API is exposed on port `8000`. Reports and models are persisted via bind-mounted volumes (`./reports`, `./models`). The SQLite database is stored in a named Docker volume (`cyber_db`).

---

## Quick Start

The fastest way to see the platform in action — no files needed:

```bash
python main.py demo
```

This loads synthetic network data, runs the full detection pipeline, renders the terminal dashboard, generates HTML/JSON reports, and persists the session to the local database.

---

## CLI Commands

```bash
python main.py demo                                          # Synthetic attack scenario
python main.py nmap   <nmap_xml>            [--ioc]         # Analyze Nmap XML scan
python main.py pcap   <pcap_file>                           # Analyze packet capture
python main.py full   <nmap_xml> <pcap_file> [--ioc]        # Combined Nmap + PCAP
python main.py explain <nmap_xml> <ip_address>              # AI explanation for a host
python main.py history [--limit N]                          # Browse past sessions
python main.py api                                          # Start REST API on :8000
```

### Examples

```bash
# Demo (no input files required)
python main.py demo

# Analyze a saved Nmap scan, with IOC threat intel
python main.py nmap samples/nmap/sample_scan.xml --ioc

# Analyze a PCAP file
python main.py pcap samples/pcaps/capture.pcap

# Full combined analysis
python main.py full samples/nmap/sample_scan.xml samples/pcaps/capture.pcap

# AI explanation for a specific host
python main.py explain samples/nmap/sample_scan.xml 192.168.1.50

# View scan history
python main.py history --limit 20

# Start API server (docs at http://localhost:8000/docs)
python main.py api
```

---

## Threat Detection Capabilities

| Detection | Method | MITRE |
|---|---|---|
| Port Scan | SYN burst / unique-port analysis | T1046 |
| Beaconing / C2 | Interval CV + byte-size consistency (C2 indicator) | T1071 |
| DNS Tunneling | Long subdomain + Shannon entropy + query burst | T1071.004 |
| Data Exfiltration | Outbound volume + upload:download ratio | T1041 |
| Brute Force | SYN + RST spike pattern | T1110 |
| SMB Enumeration | SMB packet count + unique targets | T1021.002 |
| Lateral Movement | Internal remote-access fan-out | TA0008 |

---

## ML / AI Engine

| Model | Purpose |
|---|---|
| **Isolation Forest** | Unsupervised anomaly detection (hosts + traffic) |
| **Random Forest** | Host risk classification (Low / Medium / High / Critical) |
| **DBSCAN / KMeans** | Traffic behavior clustering |

---

## Correlation Engine

Individual alerts are correlated into **attack stories** — narrative chains describing the full attack sequence:

```
Port Scan → SMB Enumeration → Brute Force → Lateral Movement
     = Coordinated Lateral Movement Attack Campaign

Beaconing + Encrypted Outbound
     = Active C2 Communication

Port Scan + Lateral Movement + Large Outbound Transfer
     = Full APT Kill Chain Detected
```

---

## Risk Score Formula

```
Risk Score = (Port Risk          × 25%)
           + (Threat Intel       × 30%)
           + (ML Anomaly         × 20%)
           + (Traffic Behavior   × 15%)
           + (Correlation Score  × 10%)
```

| Score | Level |
|---|---|
| 80–100 | Critical |
| 60–79  | High |
| 40–59  | Medium |
| 0–39   | Low |

---

## Persistence

Every scan session is automatically saved to `cyber_platform.db` (SQLite, no extra server needed). The database stores:

- Scan sessions with summary metrics
- Host risk profiles (risk score, ML anomaly flag, MITRE techniques)
- Threat alerts with evidence
- Correlated attack stories with timelines

Browse history at any time:

```bash
python main.py history
# or via API: GET /sessions
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/analyze/nmap` | Analyze Nmap XML file |
| `POST` | `/analyze/pcap` | Analyze PCAP file |
| `POST` | `/analyze/full` | Analyze Nmap + PCAP combined |
| `POST` | `/explain/ip` | AI explanation for a host |
| `POST` | `/ioc/lookup` | IOC lookup (VirusTotal / AbuseIPDB) |
| `GET`  | `/session/{id}` | Full session result |
| `GET`  | `/report/{id}/html` | Download HTML report |
| `GET`  | `/report/{id}/json` | Download JSON report |
| `GET`  | `/sessions` | List all past sessions |
| `GET`  | `/sessions/{id}/hosts` | Host profiles for a session |
| `GET`  | `/sessions/{id}/alerts` | Alerts for a session |
| `GET`  | `/sessions/{id}/stories` | Attack stories for a session |
| `GET`  | `/hosts/{ip}/history` | All sessions containing an IP |
| `DELETE` | `/sessions/{id}` | Delete a session |
| `GET`  | `/health` | Health check |

Interactive API docs: `http://localhost:8000/docs`

---

## HTML Report

Generated reports include:

- **Executive summary** — session metrics and top-risk hosts
- **Host inventory** — risk scores, open ports, MITRE techniques per host
- **Attack stories** — correlated multi-stage attack narratives with timelines
- **MITRE ATT&CK heatmap** — visual 14-tactic coverage grid showing which tactics were detected
- **Threat alerts** — full evidence chains for each detection
- **Timeline** — chronological event log

The report uses a sticky sidebar for quick navigation between sections.

---

## Tech Stack

- **Backend**: Python 3.12 + FastAPI + Uvicorn
- **Packet Analysis**: Scapy + PyShark
- **Network Scan**: Nmap XML parser
- **ML / AI**: scikit-learn (Isolation Forest, Random Forest, DBSCAN, KMeans)
- **Threat Intel**: VirusTotal API v3, AbuseIPDB API v2, AlienVault OTX
- **Dashboard**: Rich (terminal)
- **Persistence**: SQLite (stdlib `sqlite3`, no extra server)
- **Reports**: HTML + JSON (WeasyPrint optional for PDF)
- **Container**: Docker + Docker Compose

---

## Code Quality

```bash
pip install ruff
ruff check .
```

---

## Ethical Use Notice

This platform is designed for **authorized security analysis** only:
- testing your own network infrastructure
- analyzing captures from environments you own or have permission to monitor
- academic and educational research

Do not use against networks or systems without explicit authorization.
