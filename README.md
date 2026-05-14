# AI Cyber Fusion Platform

**Autonomous AI-Powered Threat Detection & Behavioral Security Analysis System**

> Giống mini: Splunk + CrowdStrike + Microsoft Defender XDR + Darktrace + Security Onion

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
Dashboard (Rich terminal) + Report (HTML/JSON)
```

---

## Project Structure

```
cyber/
├── backend/
│   ├── api/              FastAPI REST server
│   ├── scanners/         Nmap XML parser
│   ├── packet_analyzer/  PCAP parser + threat detection
│   ├── ml/               Isolation Forest, Random Forest, DBSCAN
│   ├── correlation/      Multi-signal correlation engine
│   ├── threat_intel/     VirusTotal, AbuseIPDB, OTX lookups
│   ├── reports/          HTML + JSON report generator
│   ├── constants.py      All named constants (no magic numbers)
│   ├── models.py         Dataclasses for all data structures
│   └── risk_engine.py    Weighted risk scoring
├── frontend/
│   └── dashboard.py      Rich terminal dashboard
├── samples/
│   ├── nmap/             Sample Nmap XML scan
│   └── pcaps/            Place PCAP files here
├── models/               Saved ML models (.pkl)
├── reports/              Generated reports (HTML/JSON)
├── main.py               CLI entry point
├── config.yaml           Configuration
└── requirements.txt      Dependencies
```

---

## Installation

```bash
cd cyber

# Create virtual environment
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Configure API keys for threat intelligence
cp .env.example .env
# Edit .env and add: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY
```

---

## Usage

### Demo mode (no files needed)
```bash
python main.py demo
```

### Analyze Nmap scan
```bash
python main.py nmap samples/nmap/sample_scan.xml
python main.py nmap samples/nmap/sample_scan.xml --ioc    # with threat intel
```

### Analyze PCAP traffic
```bash
python main.py pcap samples/pcaps/capture.pcap
```

### Full analysis (Nmap + PCAP)
```bash
python main.py full samples/nmap/sample_scan.xml samples/pcaps/capture.pcap --ioc
```

### AI explanation for specific host
```bash
python main.py explain samples/nmap/sample_scan.xml 192.168.1.50
```

### Start REST API server
```bash
python main.py api
# API docs: http://localhost:8000/docs
```

---

## AI / ML Engine

| Model | Purpose |
|---|---|
| **Isolation Forest** | Anomaly detection (hosts + traffic) |
| **Random Forest** | Host risk classification (Low/Medium/High/Critical) |
| **DBSCAN / KMeans** | Traffic behavior clustering |

---

## Threat Detection Capabilities

| Detection | Technique | MITRE |
|---|---|---|
| Port Scan | SYN burst analysis | T1046 |
| Beaconing / C2 | Interval variance (CV) | T1071 |
| DNS Tunneling | Long subdomain + burst | T1071.004 |
| Data Exfiltration | Outbound byte threshold | T1041 |
| Brute Force | SYN + RST pattern | T1110 |
| SMB Enumeration | SMB packet count + targets | T1021.002 |
| Lateral Movement | Internal remote-access fan-out | TA0008 |

---

## Correlation Engine

The engine correlates individual alerts into **attack stories** — narrative chains that describe the full attack sequence:

```
Port Scan → SMB Enumeration → Brute Force → Lateral Movement
     = Coordinated Lateral Movement Attack Campaign
```

```
Beaconing + Encrypted Outbound
     = Active C2 Communication
```

```
Port Scan + Lateral Movement + Large Outbound Transfer
     = Full APT Kill Chain Detected
```

---

## Risk Score Formula

```
Risk Score = (Port Risk  × 25%)
           + (Threat Intel × 30%)
           + (ML Anomaly  × 20%)
           + (Traffic Behavior × 15%)
           + (Correlation Score × 10%)
```

| Score | Level |
|---|---|
| 80–100 | 🔴 Critical |
| 60–79  | 🟠 High |
| 40–59  | 🟡 Medium |
| 0–39   | 🟢 Low |

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/analyze/nmap` | Analyze Nmap XML file |
| `POST` | `/analyze/pcap` | Analyze PCAP file (upload) |
| `POST` | `/explain/ip` | AI explanation for host |
| `POST` | `/ioc/lookup` | IOC lookup (VirusTotal/AbuseIPDB) |
| `GET`  | `/session/{id}` | Session summary |
| `GET`  | `/report/{id}/html` | Download HTML report |
| `GET`  | `/report/{id}/json` | Download JSON report |
| `GET`  | `/health` | Health check |

---

## Tech Stack

- **Backend**: Python 3.12 + FastAPI + Uvicorn
- **Packet Analysis**: Scapy + PyShark
- **Network Scan**: Nmap XML parser
- **ML / AI**: scikit-learn (Isolation Forest, Random Forest, DBSCAN, KMeans)
- **Threat Intel**: VirusTotal API v3, AbuseIPDB API v2, AlienVault OTX
- **Dashboard**: Rich (terminal)
- **Reports**: HTML + JSON
- **Deployment**: Docker-ready

---

## Development Phases

- [x] **Phase 1** — Nmap parser, PCAP parser, inventory, basic risk scoring
- [x] **Phase 2** — Correlation engine, MITRE mapping, IOC extraction
- [x] **Phase 3** — ML anomaly detection, dashboard, AI explanations
- [ ] **Phase 4** — Real-time monitoring, live capture, autonomous detection
