# 🛡️ Pro Mini-SIEM (Host-Based IDS)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-green?style=for-the-badge&logo=flask)
![ML](https://img.shields.io/badge/AI-Isolation%20Forest-orange?style=for-the-badge)
![Security](https://img.shields.io/badge/Cybersecurity-Blue%20Team-red?style=for-the-badge)

A lightweight, modular, and **AI-powered Security Information and Event Management (SIEM)** agent designed for educational purposes and SOC Analyst portfolios.

This project simulates a Host-based Intrusion Detection System (HIDS) that monitors system logs in real-time, detects malicious patterns using **MITRE ATT&CK** mapped signatures, identifies behavioral anomalies using **Unsupervised Machine Learning**, and provides an interactive **Cyberpunk-style Dashboard**.

---

## 🚀 Key Features

### 1. 🧠 AI & Machine Learning Detection
-   **Algorithm:** Uses **Isolation Forest** (Unsupervised Learning) to detect unknown threats.
-   **Feature Extraction:** Analyzes log entry length and Shannon Entropy to detect anomalies like obfuscated commands, shellcode, or buffer overflow attempts.
-   **Statistical Augmentation:** Training tools included to generate synthetic datasets based on real Linux log profiles (Loghub).

### 2. ⚡ Real-Time Correlation Engine
-   **Stateful Inspection:** Doesn't just look at single logs. It tracks events over time windows.
-   **Campaign Detection:** Automatically correlates multiple failed login attempts into a single **"Brute Force Campaign"** alert to reduce alert fatigue.

### 3. 🎯 Rule-Based Detection (MITRE ATT&CK)
-   Pre-configured Regex signatures mapped to standard frameworks:
    -   **T1110:** Brute Force
    -   **T1548:** Abuse Elevation Control Mechanism (Sudo)
    -   **T1136:** Create Account

### 4. 💻 Modern SOC Dashboard
-   **Tech Stack:** Flask (Backend) + HTML/CSS/JS (Frontend).
-   **UI:** Dark-mode, Glassmorphism design suitable for modern SOC centers.
-   **Live Feed:** Auto-refreshing alerts via API polling.

### 5. ⚔️ Red Team Simulation
-   Includes a built-in **Attack Simulator** CLI tool.
-   Simulates various attack vectors (SSH Brute Force, Sudo Abuse, Anomaly Injection) to test the SIEM's detection capabilities.

---

## 📂 Project Structure

The project follows a modular **MVC-like architecture** for scalability:

```
Mini-SIEM/
├── config/                 # Configuration settings
│   └── config.py
├── data/                   # Storage for Alerts and Logs
│   ├── siem_alerts.json    # JSON output for the Dashboard
│   └── Linux_2k.log        # Raw dataset for training
├── logs/                   # Monitored Logs
│   └── auth.log            # Target log file (simulated)
├── models/                 # Trained ML Models
│   ├── iso_forest.pkl      # The "Brain" of the AI
│   └── scaler.pkl          # Data normalizer
├── src/                    # Core Source Code
│   ├── detector.py         # Hybrid Detection Engine (Rules + ML)
│   ├── correlator.py       # Event Correlation Logic
│   ├── response.py         # Incident Response & Mitigation
│   └── handler.py          # File System Watchdog Handler
├── static/                 # Frontend Assets
│   ├── css/                # Neon/Cyberpunk Styles
│   └── js/                 # Dashboard Logic
├── templates/              # HTML Templates
│   └── dashboard_view.html
├── tools/                  # Utility Scripts
│   ├── attack_sim.py       # Red Team Attack Simulator
│   └── train_real.py       # ML Training Script (Real Data + Augmentation)
├── main.py                 # Entry Point (SIEM Agent)
├── dashboard.py            # Entry Point (Web Server)
└── requirements.txt        # Python Dependencies
```

---

## 🛠️ Installation

### Prerequisites
-   Python 3.8+
-   Linux/WSL (Recommended) or Windows

### Step 1: Clone the repository
```bash
git clone https://github.com/zenniskayy2k4/Mini-SIEM.git
cd Mini-SIEM
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```
*(Required libs: `watchdog`, `flask`, `pandas`, `numpy`, `scikit-learn`, `joblib`, `rich`)*

---

## 🕹️ Usage Guide

To run the full system, you will need **3 separate terminal windows**.

### Terminal 1: Train the AI Model 🧠
Before running the detection agent, you must train the machine learning model. This script downloads real Linux logs, augments them to 50k+ samples, and trains the Isolation Forest.

```bash
python tools/train_real.py
```
*Output: `[SUCCESS] Enterprise-Grade Model saved to: models/iso_forest.pkl`*

### Terminal 2: Start the SIEM Agent 🛡️
This is the core engine that monitors logs and generates alerts.

```bash
python main.py
```

### Terminal 3: Start the Dashboard 📊
Launch the web interface to visualize alerts.

```bash
python dashboard.py
```
> **Access the Dashboard:** Open your browser and go to `http://localhost:5000`

### Terminal 4 (Optional): Attack Simulator ⚔️
Simulate attacks to see the system in action.

```bash
python tools/attack_sim.py
```
*Select option `1` for Brute Force or `3` for ML Anomaly Injection.*

---

## 📸 Screenshots

*(Place your dashboard screenshots here)*

> **Dashboard View:** Shows critical alerts and ML anomaly scores in real-time.

---

## 🔮 Future Roadmap

-   **Threat Intelligence Integration:** Enrich alerts with GeoIP and ISP data.
-   **ELK Stack Integration:** Forward logs to Elasticsearch/Kibana.
-   **Email Notifications:** SMTP integration for critical alerts.
-   **Internal Honeypot:** A fake port listener to catch scanners.

---

## ⚠️ Disclaimer

This project is for **Educational Purposes Only**. The attack simulator should only be used on systems you own or have explicit permission to test. The author is not responsible for any misuse.

---