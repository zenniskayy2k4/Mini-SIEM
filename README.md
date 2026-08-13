# 🛡️ Mini-SIEM Pro — AI-Powered Blue Team Agent

![Python](https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Dashboard-green?style=for-the-badge&logo=flask)
![AI](https://img.shields.io/badge/AI-4--Layer%20Detection-orange?style=for-the-badge&logo=openai)
![Groq](https://img.shields.io/badge/Groq-LLM%20Analyst-purple?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?style=for-the-badge&logo=docker)
![Security](https://img.shields.io/badge/Cybersecurity-Blue%20Team-red?style=for-the-badge)

A lightweight, modular, **AI-powered SIEM** agent for real-time threat detection, correlation, and automated incident triage. Built for SOC Analyst portfolios and educational cybersecurity labs.

> ⚠️ **Educational purposes only.** Do not deploy on production systems you do not own.

---

## ✨ Feature Highlights

| Area | v1 | v2 |
|---|---|---|
| ML feature vector | 3 features | **15 features** (cmd chains, hex sequences, attack keywords…) |
| AI Analyst | None | **Groq LLM** (async triage, FP scoring, auto playbook) |
| Correlation | Brute-force only | **3 types** — campaign, kill chain, cross-sensor |
| AE training | All data (including attacks) | **Normal-only** (drastically reduces false positives) |
| TF-IDF vocab | 500 unigrams | **1000 bigrams** with sublinear TF |

---

## 🚀 Key Features

### 🧠 4-Layer Detection Engine

```
Layer 0  Rule-based signatures    < 1ms    Zero false positives on known attacks
Layer 1  NLP (TF-IDF + IsoForest) ~ 2ms    Semantic anomaly detection
Layer 2  Autoencoder (15-feat)    ~ 3ms    Structural / byte-level anomalies
Layer 3  Groq LLM Analyst         async    False-positive triage + playbook gen
```

**Layer 3 — Groq AI Analyst** enriches every HIGH/CRITICAL alert in the background without blocking the detection pipeline. Output includes:
- False-positive probability (0–100%)
- Recommended response playbook (step-by-step)
- MITRE tactic/technique mapping
- IOC extraction (IPs, hashes, domains)
- Auto-downgrade to INFO if FP confidence ≥ 80%

### ⚡ Correlation Engine

Three distinct correlation mechanisms run on every alert:

1. **Volume Campaign** — N events of the same type from one IP within a sliding window (configurable threshold per tactic category)
2. **Kill Chain Detection** — Recognises multi-stage progressions: `RECON → CRED_ACCESS → PRIV_ESC → EXECUTION`
3. **Cross-Sensor Correlation** — Same IP detected across HIDS + NIDS + Honeypot simultaneously → instant CRITICAL

### 🎯 Rule-Based Detection (MITRE ATT&CK)

| Technique | Description |
|---|---|
| T1110 | Brute Force / Password Guessing |
| T1548 | Abuse Elevation Control (Sudo) |
| T1046 | Network Service Scanning |
| T1557.002 | ARP Cache Poisoning |
| T1136 | Create Account |

### 🌐 HIDS + NIDS + Honeypot

- **HIDS** — Watchdog-based real-time log file monitor (auth.log, syslog, custom)
- **NIDS** — Scapy packet sniffer: TCP SYN flood heuristic + ARP spoofing detection
- **Honeypot** — TCP trap on port 2222; any connection is a CRITICAL, high-fidelity alert

### 💻 SOC Dashboard

- Dark-mode, glassmorphism UI (Flask + Chart.js + Cytoscape)
- Paginated live event table with filtering (severity, IP, MITRE ID, time range)
- Interactive attack context graph (IP → MITRE → Campaign nodes)
- Runtime settings hot-reload (no restart needed)
- ELK/Elasticsearch forwarding support

### ⚔️ Red Team Simulator

Built-in attack simulator for testing detection coverage:

| Mode | Description |
|---|---|
| 1 | SSH Brute Force (log injection) |
| 2 | Sudo Privilege Escalation |
| 3 | High-entropy anomaly payload |
| 4 | Mixed attack chain |
| 5 | Real TCP SYN scan (requires root) |

---

## 📂 Project Structure

```
Mini-SIEM/
├── config/
│   └── config.py           # All settings — ports, thresholds, signatures
├── data/                   # Runtime data (hot-reload settings, alerts)
├── logs/                   # Monitored log file (auth.log)
├── models/                 # Trained ML artifacts (.pkl, .pth)
├── src/
│   ├── detector.py         # 4-layer detection engine
│   ├── ai_analyst.py       # Groq LLM Layer 3 (async)
│   ├── correlator.py       # Campaign + kill chain + cross-sensor correlation
│   ├── handler.py          # Watchdog HIDS handler
│   ├── network_monitor.py  # Scapy NIDS
│   ├── honeypot.py         # TCP honeypot trap
│   ├── response.py         # Incident responder & mitigation
│   ├── alert_store.py      # Thread-safe JSON lines writer
│   └── elk_forwarder.py    # Elasticsearch forwarder
├── static/                 # Frontend assets (CSS, JS)
├── templates/              # Jinja2 HTML templates
├── tools/
│   ├── train_ml.py         # ML training pipeline
│   └── attack_sim.py       # Red team simulator
├── main.py                 # SIEM agent entry point
├── dashboard.py            # Web dashboard entry point
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 🐳 Quick Start with Docker (Recommended)

Docker is the easiest way to run the full stack — no manual dependency installation required.

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/macOS) or Docker Engine (Linux)
- A free [Groq API key](https://console.groq.com) for AI Analyst (optional but recommended)

### Step 1 — Clone the repository
```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
```

### Step 2 — Configure environment
```bash
cp .env.example .env
# Edit .env and add your GROQ_API_KEY (optional — Layer 3 AI Analyst)
```

### Step 3 — Train ML models (one-time, ~2–3 min)
```bash
docker compose --profile train run --rm train
```
> Models are saved to `./models/` on your host machine and reused on subsequent runs.

### Step 4 — Start the full stack
```bash
docker compose up -d
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:5000 |

### Step 5 (Optional) — Run the attack simulator
```bash
docker compose run --rm agent python tools/attack_sim.py
```

### Stop all services
```bash
docker compose down
```

---

## 💻 Manual Installation (No Docker)

### Prerequisites
- Python **3.12+**
- Windows: [Npcap](https://npcap.com/) required for NIDS packet capture
- Linux/macOS: run with `sudo` for NIDS raw socket access

### Step 1 — Install dependencies
```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
pip install -r requirements.txt
```

### Step 2 — Set environment variables
```bash
# Linux/macOS
export GROQ_API_KEY="gsk_your_key_here"

# Windows (PowerShell)
$env:GROQ_API_KEY = "gsk_your_key_here"
```

### Step 3 — Train ML models 🧠
```bash
python tools/train_ml.py
```
Training output shows detection rate and false-positive rate — aim for FP rate < 5%.

### Step 4 — Start SIEM agent (Terminal 1)
```bash
python main.py
```

### Step 5 — Start dashboard (Terminal 2)
```bash
python tools/manage_dashboard_user.py admin admin
python dashboard.py
```
> Open **http://localhost:5000**

The user command prompts for a password and stores only its Werkzeug hash in
`data/dashboard_users.json`. Run it again with role `viewer`, `analyst`, or
`admin` to create or update an account. With Docker Compose, use:

```bash
docker compose run --rm dashboard python tools/manage_dashboard_user.py admin admin
```

### Step 6 (Optional) — Attack simulator (Terminal 3)
```bash
python tools/attack_sim.py
```

---

## ⚙️ Configuration

Edit `config/config.py` to customise behaviour:

| Key | Default | Description |
|---|---|---|
| `DASHBOARD_PORT` | `5000` | Web dashboard port |
| `NIDS_ENABLED` | `False` | Enable Scapy packet sniffer |
| `HONEYPOT_ENABLED` | `False` | Enable TCP honeypot trap |
| `HONEYPOT_PORT` | `2222` | Honeypot listener port |
| `CORRELATION_WINDOW_MINUTES` | `5` | Sliding window for campaign detection |
| `NIDS_SYN_THRESHOLD` | `20` | SYN packets/window to trigger alert |
| `ELK_ENABLED` | `False` | Forward alerts to Elasticsearch |
| `ELK_URL` | `http://localhost:9200/...` | Elasticsearch endpoint |

Runtime settings (NIDS, Honeypot toggles) can also be changed live from the **Settings** page without restarting.

---

## 🤖 Groq AI Analyst — Setup

The AI Analyst (Layer 3) uses **Llama 3.3 70B** via Groq's free API for real-time alert triage.

1. Create a free account at [console.groq.com](https://console.groq.com)
2. Generate an API key
3. Set `GROQ_API_KEY` in your environment or `.env` file

When active, every HIGH/CRITICAL alert is automatically enriched with:
```json
{
  "is_false_positive": false,
  "threat_confidence": 92,
  "mitre_technique": "T1110.001 - Password Guessing",
  "threat_summary": "Sustained SSH brute-force from external IP targeting root account.",
  "recommended_playbook": [
    "Block source IP: iptables -A INPUT -s 45.33.22.11 -j DROP",
    "Check for successful logins from this IP in the last 24h",
    "Enable fail2ban if not already active",
    "Disable PasswordAuthentication in /etc/ssh/sshd_config"
  ],
  "escalate_to_human": true
}
```

> **Without a Groq API key**, Layers 0–2 (rules + ML) continue working normally. Layer 3 is silently skipped.

---

## 🏗️ How Detection Works

```
Log line arrives
       │
       ▼
┌─────────────────────┐
│  Layer 0: Signatures│ ──hit──► Alert (rule-matched)
└──────────┬──────────┘
           │ no match
           ▼
┌─────────────────────┐
│  Layer 1: NLP       │
│  Layer 2: AE (15f)  │ ──both flag──► CRITICAL AI Anomaly
└──────────┬──────────┘ ──one flags──► HIGH Anomaly
           │ no anomaly
           ▼
          None (clean log)
           
       [Async, non-blocking]
┌─────────────────────┐
│  Layer 3: Groq LLM  │ ──enriches HIGH/CRITICAL alerts in background
└─────────────────────┘
```

---

## 📸 Screenshots

![Dashboard Overview](/assets/Dashboard.jpeg)

---

## 🔮 Roadmap

- [ ] Slack / PagerDuty / email webhook alerts  
- [ ] SQLite backend for efficient log querying  
- [ ] JWT authentication for dashboard  
- [ ] Windows Event Log support (via `pywin32`)  
- [ ] Fine-tuned small LLM on SOC playbooks  
- [ ] Auto-block via firewall API (not just command suggestion)  

---

## ⚠️ Disclaimer

This project is for **educational purposes only**.  
The attack simulator must only be used on systems you own or have explicit written permission to test.  
The author is not responsible for any misuse.
