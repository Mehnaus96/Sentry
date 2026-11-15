# PacketSentry – Automated Network Traffic Analyzer & SOC Reporting System

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.14-blue.svg)](https://www.python.org/)
[![TShark](https://img.shields.io/badge/Wireshark%2FTShark-4.6%2B-007acc.svg)](https://www.wireshark.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.67-FF4B4B.svg)](https://streamlit.io/)
[![UiPath](https://img.shields.io/badge/UiPath-Studio%2023.4%2B-FA4616.svg)](https://www.uipath.com/)
[![Tests](https://img.shields.io/badge/tests-40%20passed-22c55e.svg)](tests/)
[![ReportLab](https://img.shields.io/badge/Reports-PDF%20ReportLab-2563eb.svg)](reporting/)

PacketSentry is an enterprise-grade, offline network traffic analysis and security operations (SOC) platform. Engineered for incident responders and SOC analysts, PacketSentry ingests raw packet captures (`.pcap`, `.pcapng`), performs deep protocol dissection via local TShark, computes network traffic metrics, executes transparent rule-based threat detections, facilitates case triage, compiles audit-ready PDF investigation reports, and orchestrates automated response pipelines via UiPath Studio.

---

## 🏛️ System Architecture

```
+-----------------------------------------------------------------------------------------+
|                                  PACKETSENTRY PLATFORM                                  |
+-----------------------------------------------------------------------------------------+
                                             │
      ┌──────────────────────────────────────┴──────────────────────────────────────┐
      ▼                                                                             ▼
[Ingestion: Web UI]                                                       [Ingestion: UiPath RPA]
  Streamlit Dashboard (app.py)                                              Folder Watcher / CLI (cli.py)
      │                                                                             │
      └──────────────────────────────────────┬──────────────────────────────────────┘
                                             ▼
                             [Module A: Extraction & Validation]
                                 pcap_parser.py (TShark)
                                 - Magic Byte Signature Check
                                 - TSV Extraction & Normalization
                                 - 5-Tuple Connection ID Synthesis
                                             │
                                             ▼
                             [Module B: Network Traffic Analytics]
                                 traffic_analyzer.py
                                 - Protocol Distribution
                                 - Top Talkers & Port Annotations
                                 - TCP Handshake Ratios (SYN/ACK/RST)
                                 - DNS Telemetry & Time Series
                                             │
                                             ▼
                             [Module C: SOC Detection Engine]
                                 rules.py & detection_engine.py
                                 - PS-SCAN-001 (Port Reconnaissance)
                                 - PS-CONN-002 (Repeated SYN / Brute Force)
                                 - PS-DNS-003 (DNS Tunneling / DGA)
                                 - PS-VOL-004 (Bandwidth Exfiltration)
                                 - PS-PROTO-005 (High-Risk Cleartext)
                                             │
                                             ▼
                             [Module D: SOC Alert Management]
                                 alert_manager.py
                                 - Multi-Dimensional Search & Filtering
                                 - Triage Lifecycle (New -> In Progress -> Escalated)
                                 - Case Notes & Investigator Assignment
                                             │
                                             ▼
                             [Module E: Investigation Reporting]
                                 report_generator.py (ReportLab)
                                 - Cryptographic Digests (SHA-256, MD5)
                                 - Executive KPIs & Telemetry Tables
                                 - Granular Evidence Dossiers & Timelines
                                 - Incident Response Playbooks & Sign-off
```

---

## 📂 Project Structure

```
PacketSentry/
├── app.py                     # Streamlit Interactive SOC Analyst Web Console
├── cli.py                     # Headless CLI Entrypoint for UiPath & Automation
├── requirements.txt           # Pinned Python Dependencies
├── README.md                  # Comprehensive Documentation & Architecture Guide
├── HANDBOOK.md                # SOC Analyst Operational Playbook & User Guide
├── analyzer/                  # Core Telemetry & Threat Detection Package
│   ├── __init__.py
│   ├── environment.py         # System Diagnostics & TShark Binary Detection
│   ├── pcap_parser.py         # Capture Validation & TShark Extraction Pipeline
│   ├── traffic_analyzer.py    # Statistical Engine & Flow Aggregations
│   ├── rules.py               # Threat Catalog, Thresholds & MITRE Mappings
│   ├── detection_engine.py    # Vectorized Rule Evaluator & Alert Builder
│   └── alert_manager.py       # Triage Lifecycle & Multi-Dimensional Search
├── reporting/                 # SOC Incident Reporting Engine
│   ├── __init__.py
│   └── report_generator.py    # Publication-Grade ReportLab PDF Compiler
├── data/                      # Data Pipeline Buffers
│   ├── uploads/               # Staged Raw Captures (sample_capture.pcap)
│   ├── processed/             # Extracted JSON/CSV Telemetry & Alerts
│   └── reports/               # Compiled Formal PDF Reports
├── output/                    # Headless Investigation Records
│   └── investigations/        # Structured Case Artifacts & Audit Logs
├── uipath/                    # UiPath Studio RPA Assets
│   ├── project.json           # Native UiPath Project Configuration
│   ├── Main.xaml              # UiPath Workflow Sequence Definition
│   ├── workflow_documentation.md # Enterprise UiPath Studio Implementation Guide
│   └── run_uipath_mock_orchestrator.ps1 # Standalone RPA Simulation Runner
└── tests/                     # Automated Test Suite (40 Tests Passed)
    ├── __init__.py
    ├── SAMPLE_PCAP_TESTING.md # Ground-Truth Test Scenario Specifications
    ├── generate_test_pcaps.py # Raw Socket/Struct Synthetic PCAP Generator
    ├── test_environment.py    # Environment & Binary Path Unit Tests
    ├── test_pcap_parser.py    # Extraction & Signature Validation Tests
    ├── test_traffic_analyzer.py # Statistical Aggregation Unit Tests
    ├── test_detection_engine.py # Rule Evaluation & Sensitivity Tuning Tests
    ├── test_alert_manager.py  # Triage Lifecycle & Filtering Tests
    ├── test_report_generator.py # PDF Compilation & Hashing Tests
    ├── test_dashboard.py      # End-to-End Dashboard Pipeline Integration
    └── test_uipath_cli.py     # Headless Automation Return Code Tests
```

---

## ⚡ Quickstart & Installation

### 1. Prerequisites
- **Python 3.10+** (Tested on Python 3.14)
- **Wireshark / TShark:** Installed locally (PacketSentry automatically detects `C:\Program Files\Wireshark\tshark.exe` or system `PATH`).

### 2. Setup Environment
```powershell
cd C:\Users\mehna\.gemini\antigravity\scratch\PacketSentry

# Install dependencies
pip install -r requirements.txt
```

### 3. Verify Environment Readiness
```powershell
python analyzer/environment.py
```
Output confirms `READY` status, local TShark version, and analytical packages.

---

## 🚀 Running PacketSentry

### Mode A: Interactive Streamlit Web Console
Launch the dark navy analyst console:
```powershell
streamlit run app.py
```
Open your browser at `http://localhost:8501`:
1. **Overview Dashboard:** Review macro metrics, protocol distributions, and threat severity charts.
2. **PCAP Analyzer:** Click **"Load Staged Sample Capture"** or upload custom `.pcap` files to inspect packet frames.
3. **Security Alerts:** Filter alerts by severity or keyword, view granular evidence, update triage statuses, and write analyst notes.
4. **Investigation Reports:** Generate and download publication-grade PDF incident dossiers.
5. **Settings & Thresholds:** Dynamically calibrate port scan thresholds or domain length limits.

---

### Mode B: Headless CLI & Automation Pipeline
Execute analysis via the command line for script integration or RPA:
```powershell
python cli.py --pcap data/uploads/sample_capture.pcap --output-dir output/investigations --analyst "SOC Tier-1 Analyst"
```
- **Exit Code 10:** Alerts detected (triggers high-priority RPA escalation).
- **Exit Code 0:** Clean capture.
- Generates `investigation_summary.json`, parsed CSV, telemetry JSON, alerts JSON, and PDF report into `output/investigations/<INV_ID>/`.

---

### Mode C: UiPath RPA Orchestration
1. Open the `uipath/` directory in **UiPath Studio**.
2. Run `Main.xaml` to execute unattended folder monitoring, file validation, CLI dispatch, alert evaluation, artifact filing, and audit trail generation.
3. Alternatively, test the RPA workflow directly in PowerShell:
   ```powershell
   powershell -ExecutionPolicy Bypass -File uipath/run_uipath_mock_orchestrator.ps1
   ```

---

## 🎯 Detection Rules & MITRE ATT&CK Matrix

| Rule ID | Detection Name | Severity | MITRE ATT&CK | Default Threshold | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PS-SCAN-001** | Potential Port Scanning | **HIGH** | `T1046` | $\ge 10$ distinct ports in 60s | Identifies single source IPs probing numerous distinct ports on a target host. |
| **PS-CONN-002** | Repeated Failed Connections | **MEDIUM** | `T1110` / `T1498` | $\ge 8$ unacknowledged SYNs | Flags rapid TCP SYN attempts without completing 3-way handshakes (brute force or SYN flood). |
| **PS-DNS-003** | DNS Anomalies / Tunneling | **HIGH** | `T1071.004` / `T1568` | $\ge 45$ chars FQDN length | Identifies abnormally long domain queries indicative of base64 exfiltration or C2 beaconing. |
| **PS-VOL-004** | Unusual Traffic Volume Spike | **MEDIUM** | `T1048` | $\ge 5$ MB or $\ge 75\%$ capture share | Detects single endpoints transferring disproportionate volumes outside typical baselines. |
| **PS-PROTO-005** | Suspicious / Cleartext Ports | **LOW** | `T1040` / `T1571` | Ports: 21, 23, 69, 5900, 4444, 31337 | Flags unencrypted legacy administration (Telnet, FTP) or common backdoor listener ports. |

---

## 🧪 Automated Testing Suite

PacketSentry includes 40 comprehensive unit and integration tests covering all modules:

```powershell
python -m unittest discover tests
```

```text
........................................
----------------------------------------------------------------------
Ran 40 tests in 17.517s

OK
```

---

## 💼 SOC Analyst Interview Talking Points

When presenting PacketSentry during a SOC Analyst internship interview:

1. **Deterministic Forensics vs. Black-Box ML:** Explain that PacketSentry links every alert directly to hard wire evidence (frame numbers, exact port lists, and domain lengths) and maintains an explicit distinction between *Observed Evidence* and *Analytical Interpretation*.
2. **Defending Against Alert Fatigue:** Highlight the configurable threshold architecture in `rules.py`—demonstrating understanding that an enterprise backup server or vulnerability scanner requires calibrated baselines to prevent noise.
3. **SOAR & Workflow Automation:** Explain how the UiPath integration bridges detection with automated response—monitoring intake directories, isolating suspect captures, routing high-priority incidents, and maintaining an immutable audit log.
4. **Data Sovereignty & Local Processing:** Emphasize that all extraction and analysis runs locally via TShark and Python, guaranteeing sensitive packet payloads and internal network topologies are never exposed to external cloud APIs.
