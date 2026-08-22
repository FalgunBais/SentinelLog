# SentinelLog — Real-Time Security Log Analyzer & Threat Detection Engine

[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Framework](https://img.shields.io/badge/Architecture-Modular%20Defensive%20Security-emerald)](https://github.com/)
[![Tests](https://img.shields.io/badge/Tests-100%25%20Passing-brightgreen)](tests/)

**SentinelLog** is a lightweight, defensive cybersecurity monitoring platform designed to ingest system authentication logs in real time, correlate security events with sliding-window anomaly algorithms, assign deterministic risk scores, and present live threat intelligence through a high-performance Dark SOC Web Dashboard and an ANSI-colorized CLI.

---

## 📸 SOC Dashboard Preview

```
+----------------------------------------------------------------------------------------------------+
| 🛡️ SentinelLog v1.0.0      [⚡ DEMO MODE — SIMULATED SECURITY EVENTS]      🟢 SYSTEM MONITORING     |
+----------------------------------------------------------------------------------------------------+
| [ 2,285 Events ]    [ 613 Success ]    [ 1,672 Failures ]    [ 267 Active Threats ]   [ 16 IPs ]   |
+----------------------------------------------------------------------------------------------------+
|  📊 Auth Breakdown     | 📈 Velocity & Activity Timeline       | 🛡️ Severity Dist   | 🔥 Top Attacking IPs |
|  [===  Donut  ===]     | [~~~~~ Area Trendline ~~~~~]         | [||| Bar Chart ||] | [185.220.101.5   ] |
|                        |                                       |                    | [45.142.214.19   ] |
+----------------------------------------------------------------------------------------------------+
| 📡 REAL-TIME LIVE SECURITY EVENT FEED                 | 🚨 ACTIVE THREAT ALERTS & INCIDENT RESPONSE |
| ----------------------------------------------------- | ------------------------------------------- |
| 15:26:00 | 185.220.101.5 | root   | FAILED_LOGIN      | [CRITICAL] SUSPICIOUS_SUCCESS (Score: 90)   |
| 15:26:01 | 203.0.113.88  | oracle | INVALID_USER      | Source: 91.240.118.172  Target: root        |
| 15:26:02 | 192.168.1.50  | ubuntu | SUCCESSFUL_LOGIN  | Action: Terminate session & enforce MFA     |
+----------------------------------------------------------------------------------------------------+
```

---

## 🌟 Key Features

* **Real-Time File Tailing Pipeline**: Efficient non-blocking `seek`/`tell` file-tailing mechanism that dynamically monitors newly appended auth log lines without repeatedly reading the entire file, handling log rotation and truncation gracefully.
* **Multi-Format Log Parser**: Robust regex-based tokenizer supporting Debian/Ubuntu `/var/log/auth.log`, RHEL/CentOS `/var/log/secure`, OpenSSH `sshd`, PAM `pam_unix`, `sudo`, and generic structured timestamps.
* **Deterministic Threat Detection Engine**:
  * 💥 **SSH Brute-Force Detection**: Identifies sustained authentication attacks targeting individual accounts or single source IPs within a configurable sliding time window.
  * 🎯 **Horizontal Credential Spraying**: Detects multi-account dictionary attacks probing multiple distinct usernames from a single origin.
  * ⚠️ **Suspicious Compromise / Success Following Failures**: Flags critical anomalies where an account logs in successfully immediately following multiple failed attempts from the same IP (possible password cracking).
  * 📈 **Authentication Velocity Spikes**: Triggers on rapid-fire automated login bursts exceeding normal human velocity thresholds.
  * 🔍 **Invalid User Probing**: Detects enumeration scans targeting default or non-existent system accounts (`root`, `admin`, `guest`, `oracle`, `mysql`).
* **Additive Risk Scoring & Anomaly Engine**: Calculates explainable 0–100 threat scores mapped to severity tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), providing actionable SOC analyst remediation guidelines.
* **Dark SOC Web Dashboard**:
  * Dark obsidian aesthetic with glassmorphic cards and glowing status indicators.
  * Live status pill (🟢 `SYSTEM MONITORING` / 🟡 `WARNING` / 🔴 `THREATS DETECTED`).
  * Server-Sent Events (SSE) streaming for real-time live event insertions.
  * Four analytical Chart.js graphs (Authentication Donut, Timeline Trendline, Severity Distribution, Top Attacking IPs).
  * **IP Forensic Dossier Modal**: Instant deep dive into any IP, showing classifications (`Public`, `RFC1918`, `Loopback`), total vs failed attempts, targeted usernames list, timeline, and associated alerts.
  * Alert triage and acknowledgment workflow.
  * On-demand simulation scenario triggers.
* **Feature-Rich CLI**:
  * ANSI color-coded streaming feed.
  * Instant terminal stats tables (`--stats`).
  * IP forensic inspection tool (`--investigate <IP>`).
  * Structured exports to CSV, JSON, and Executive Markdown reports.
* **Dual Operating Modes**:
  * **Live Mode**: Continuously processes genuine operating system logs.
  * **Demo Mode**: Built-in realistic traffic generator simulating benign activity and attack sequences, clearly badged with `DEMO MODE — SIMULATED SECURITY EVENTS`.

---

## 🏗️ Architecture

```
sentinellog/
│
├── app.py                      # Application entry point (web + monitor launcher)
├── sentinel.py                 # Comprehensive CLI tool
├── config.json                 # System configuration & detection rule thresholds
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
│
├── core/
│   ├── __init__.py
│   ├── models.py               # LogEvent, ThreatAlert, IPProfile, Enums dataclasses
│   ├── parser.py               # Multi-format auth.log, secure, sshd, pam parser
│   ├── detector.py             # Sliding-window stateful threat detector
│   ├── analyzer.py             # Additive risk scoring & SOC recommendation engine
│   └── monitor.py              # File tailing engine & subscriber dispatch pipeline
│
├── database/
│   ├── __init__.py
│   └── database.py             # Thread-safe SQLite schema, queries & IP profiling
│
├── demo/
│   ├── __init__.py
│   └── generator.py            # Realistic authentication simulation generator
│
├── dashboard/
│   ├── __init__.py
│   ├── routes.py               # Flask REST API & SSE live stream endpoints
│   ├── templates/
│   │   └── index.html          # Dark SOC dashboard UI
│   └── static/
│       ├── css/
│       │   └── dashboard.css   # SOC dark theme, glassmorphism, responsive grid
│       └── js/
│           └── dashboard.js    # Real-time SSE listener & Chart.js controllers
│
├── exports/
│   ├── __init__.py
│   └── exporter.py             # CSV, JSON, and Markdown report export tools
│
└── tests/
    ├── __init__.py
    ├── sample_logs/
    │   ├── auth.log            # Sample Ubuntu/Debian log fixture
    │   └── secure.log          # Sample CentOS/RHEL log fixture
    ├── test_parser.py          # Unit tests for log parsing
    ├── test_detector.py        # Unit tests for threat detection rules
    ├── test_analyzer.py        # Unit tests for risk scoring
    └── test_database.py        # Integration tests for storage & IP profiling
```

---

## 🧠 Detection Methodology & Scoring

SentinelLog employs an explainable, deterministic rule engine that tracks per-IP and per-user activity over sliding time windows:

### Base Risk Weights

| Event / Behavioral Indicator | Risk Score Weight |
| :--- | :---: |
| Single Failed Login Attempt (`FAILED_LOGIN`) | `+10` |
| Invalid User Lookup (`INVALID_USER`) | `+15` |
| High-Value Target Bonus (`root`, `admin`, `oracle`, `guest`) | `+5` to `+10` |
| Rapid Velocity Burst (`RAPID_ATTEMPTS`) | `+20` |
| Horizontal User Spraying (`MULTIPLE_USERS`) | `+25` |
| Suspicious Success After Failures (`SUSPICIOUS_SUCCESS`) | `+30` |
| Brute Force Threshold Exceeded (`BRUTE_FORCE`) | `+40` |

### Severity Tier Classification

* 🟢 **LOW**: `0 – 29` (Routine authentications or isolated credential typos)
* 🟡 **MEDIUM**: `30 – 59` (Repeated invalid user lookups or elevated failures)
* 🟠 **HIGH**: `60 – 84` (Brute-force thresholds reached, high velocity spikes)
* 🔴 **CRITICAL**: `85 – 100` (Account compromise after brute force, massive spraying)

---

## 🚀 Installation & Quick Start

### 1. Prerequisites

* Python 3.9+ installed
* Standard Python environment

### 2. Clone and Install Dependencies

```bash
git clone https://github.com/yourusername/SentinelLog.git
cd SentinelLog

pip install -r requirements.txt
```

---

## 💻 Usage & CLI Reference

### 1. Launch the SOC Web Dashboard

```bash
# Default launch (runs on http://127.0.0.1:5000 in Demo Mode)
python sentinel.py --web

# Custom host and port
python sentinel.py --web --port 8080 --host 0.0.0.0
```

Open your browser and navigate to `http://127.0.0.1:5000` to view the live SOC dashboard.

### 2. Run in CLI Demo Mode

```bash
python sentinel.py --demo
```

### 3. Monitor a Live System Log File

```bash
# Monitor standard Linux auth log
sudo python sentinel.py --log /var/log/auth.log

# Monitor custom log file from beginning
python sentinel.py --log /path/to/server.log --tail-start
```

### 4. Adjust Detection Thresholds Dynamically

```bash
python sentinel.py --log /var/log/auth.log --threshold 3 --window 120
```

### 5. Inspect Database Security Intelligence & Stats

```bash
python sentinel.py --stats
```

### 6. Perform IP Forensic Investigation

```bash
python sentinel.py --investigate 198.51.100.42
```

### 7. Export Security Data & Reports

```bash
# Export processed events to CSV
python sentinel.py --export-events exports/events.csv

# Export active alerts to JSON
python sentinel.py --export-alerts exports/alerts.json

# Generate an Executive Cybersecurity Report in Markdown
python sentinel.py --report exports/incident_report.md
```

---

## ⚙️ Configuration (`config.json`)

All detection parameters, time windows, scoring weights, and application settings can be adjusted in `config.json`:

```json
{
  "app": {
    "name": "SentinelLog",
    "version": "1.0.0",
    "mode": "demo",
    "host": "127.0.0.1",
    "port": 5000
  },
  "detection": {
    "brute_force": {
      "failed_attempts_threshold": 5,
      "time_window_seconds": 300,
      "risk_score": 40,
      "severity": "HIGH"
    },
    "user_spraying": {
      "unique_users_threshold": 3,
      "time_window_seconds": 300,
      "risk_score": 25,
      "severity": "HIGH"
    },
    "rapid_spike": {
      "attempt_threshold": 8,
      "time_window_seconds": 30,
      "risk_score": 20,
      "severity": "HIGH"
    },
    "suspicious_success": {
      "prior_failures_threshold": 3,
      "time_window_seconds": 300,
      "risk_score": 30,
      "severity": "CRITICAL"
    }
  }
}
```

---

## 🧪 Testing Suite

SentinelLog includes an automated unit and integration test suite covering the parser, detection engine, risk analyzer, and database layer.

```bash
# Run all tests with Python unittest
python3 -m unittest discover -s tests -p "test_*.py" -v

# Or run via CLI flag
python sentinel.py --test
```

---

## 📘 What I Learned

Building **SentinelLog** provided deep hands-on experience in defensive cybersecurity engineering and systems architecture:

1. **Log Parsing & Normalization**:
   - Mastered regular expression engineering to handle variations in Linux authentication log syntaxes (`sshd`, `pam_unix`, `sudo`, `systemd-logind`).
   - Implemented ISO8601 normalization and legacy syslog timestamp reconstruction without external time dependencies.
2. **Real-Time Non-Blocking File Monitoring**:
   - Designed a robust `file-tail` engine utilizing file seek offsets and inode validation (`os.stat`) to gracefully survive log rotation (`logrotate`) and truncation without memory leaks or duplicate processing.
3. **Security Event Correlation & Sliding Windows**:
   - Engineered stateful in-memory sliding time-window tracking to correlate events across time, IP addresses, and user accounts.
   - Built defensive rules capable of detecting horizontal credential spraying, brute force, and credential compromise sequences.
4. **Explainable Risk Scoring**:
   - Developed a deterministic scoring model that provides auditable, transparent risk scores without "black box" claims.
   - Tied threat detections directly to actionable SOC analyst mitigation steps.
5. **Thread-Safe SQLite Architecture**:
   - Implemented WAL (Write-Ahead Logging) mode and connection lifecycle management to allow simultaneous reads from the web dashboard and concurrent writes from the log monitor.
6. **Modern SOC Dashboard Design**:
   - Built a dark-themed SOC interface with glassmorphism, responsive grid layouts, and Chart.js integration.
   - Used Server-Sent Events (SSE) for low-overhead real-time event streaming directly to the browser.
7. **CLI Architecture**:
   - Built an intuitive command-line interface with ANSI escape codes, structured tables, and deep forensic inspection capabilities.

---

## 🔮 Future Improvements

- [ ] **GeoIP & ASN Integration**: Optional offline MaxMind GeoLite2 enrichment for source IP geographic tracking.
- [ ] **Automated Firewall Response (Active Defense)**: Optional webhook / iptables integration to automatically drop IPs exceeding a risk score of 90.
- [ ] **Multi-Node Log Ingestion**: Syslog UDP/TCP socket listener (port 514) for aggregating logs from multiple remote servers.
- [ ] **Email & Slack / Discord Webhooks**: Instant notification dispatch for `CRITICAL` severity threat alerts.

---

## 🛡️ License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
