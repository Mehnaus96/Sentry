# Sentry

# 🛡️ PacketSentry — Automated Network Traffic Analyzer & SOC Reporting System

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%20%7C%203.14-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Wireshark / TShark](https://img.shields.io/badge/Wireshark%2FTShark-4.6%2B-007acc.svg?logo=wireshark&logoColor=white)](https://www.wireshark.org/)
[![UiPath Studio](https://img.shields.io/badge/UiPath-RPA%20Automation-FA4616.svg?logo=uipath&logoColor=white)](https://www.uipath.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B.svg?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Unit Tests](https://img.shields.io/badge/Tests-40%20Passed-22c55e.svg)](tests/)
[![ReportLab](https://img.shields.io/badge/Reports-Executive%20PDF-2563eb.svg)](reporting/)

> **A beginner-friendly, enterprise-grade cybersecurity tool that scans computer network traffic, catches hackers in the act, automatically generates professional PDF security reports, and uses software robots (RPA) to handle the busywork 24/7.**

---

## 💡 What is PacketSentry? (In Plain English)

Imagine an **airport luggage scanner**, but for the internet:

Every time computers talk to each other — whether you're browsing a website, sending an email, or an ATM is contacting a bank — they send little bundles of data called **packets**. Cybersecurity specialists record these packets into files called **PCAP** files (short for *Packet Capture*). It is essentially **CCTV footage of computer network activity**.

### The Problem
In real companies (Security Operations Centers or **SOCs**), human security analysts receive dozens of giant capture files every day. Manually opening these files and sifting through millions of lines of data in tools like Wireshark takes hours, strains human eyes, and leads to fatigue where real attacks can slip past unnoticed.

### The Solution: PacketSentry
**PacketSentry does all that heavy lifting in seconds:**
1. It reads the raw network recording.
2. It looks for known attack patterns (like a burglar testing every locked door or a hacker sneaking stolen data out in secret messages).
3. It explains *why* something is dangerous in plain English.
4. It compiles a clean, court-ready **PDF Incident Report** automatically.
5. Best of all: it can run **100% on autopilot using a UiPath digital robot** that watches an inbox folder and does the work while you sleep.

---

## 🛠️ What Tech Stack Was Used?

| Technology | What it is | Why we chose it for PacketSentry |
| :--- | :--- | :--- |
| **Python (3.10 / 3.14)** | Core Programming Language | Fast, reliable, and the gold standard for cybersecurity analysis and data processing. |
| **Wireshark & TShark** | Network Dissection Engine | The world's #1 network protocol analyzer. PacketSentry runs it headlessly in the background. |
| **UiPath Studio** | Robotic Process Automation (RPA) | Acts as a "digital worker" that watches folders, triggers analysis, and routes security alerts automatically. |
| **Streamlit** | Web Application Dashboard | Gives analysts a sleek, dark-navy interactive UI with buttons, filters, and live charts without complex web code. |
| **Plotly & Pandas** | Data Analytics & Visuals | Turns millions of raw packet numbers into intuitive pie charts, bar graphs, and traffic timelines. |
| **ReportLab** | PDF Publishing Engine | Compiles publication-grade, two-pass ("Page X of Y") executive security dossiers with SHA-256 digital fingerprints. |

---

## 🤖 The Automation Part: How Does the Robot Work?

One of the coolest features of PacketSentry is its **Robotic Process Automation (RPA)** integration built with **UiPath Studio**.

### Think of UiPath as a 24/7 Digital Security Assistant:
Instead of a human sitting at a desk waiting for network files to arrive:

```text
[Network Recording Dropped in Folder]
                 │
                 ▼
     [UiPath Robot Wakes Up]
                 │
                 ├── 1. Validates the file (ensures it's not corrupt or empty)
                 ├── 2. Launches PacketSentry's brain in the background
                 ├── 3. Reads the security findings
                 │
                 ▼
       [Did the Robot Find Threats?]
        /                         \
    YES (High/Critical)          NO (Clean)
      │                            │
      ▼                            ▼
 [EMERGENCY PATH]              [ARCHIVE PATH]
 • Flags as High Priority      • Marks as Clean & Normal
 • Assembles PDF Report        • Generates Audit Record
 • Prepares alert for team     • Moves to finished folder
                 │                         │
                 └────────────┬────────────┘
                              ▼
           [Logs everything to an audit trail]
```

### Key Highlights of the Automation:
- **Zero Human Intervention Needed**: Just drop any `.pcap` or `.cap` file into the `data/uploads/` folder.
- **Smart Exit Codes**: If threats are found, the system exits with code `10` (telling the robot: *Sound the alarm!*). If clean, it exits with code `0` (*All clear!*).
- **Immutable Audit Trail**: Every action taken by the robot is stamped with UTC time, packet counts, alert counts, and filenames inside `output/investigations/execution_audit.log`.

---

## 🔍 What Attacks Can It Detect?

PacketSentry comes with built-in security rules mapped to the global **MITRE ATT&CK** cybersecurity framework:

| Rule Name | Real-World Analogy | What the Attacker is Doing | Severity |
| :--- | :--- | :--- | :---: |
| **Port Scanning** (`PS-SCAN-001`) | A burglar walking down a hallway rattling every doorknob to see which room is unlocked. | A computer probing 10+ different network ports in seconds to find a weak entry point. | **HIGH** |
| **Failed Connections / Brute Force** (`PS-CONN-002`) | Someone rapidly ringing your doorbell 50 times without ever saying hello. | Rapid TCP connection attempts that never complete, often seen in password guessing or denial-of-service attempts. | **MEDIUM** |
| **DNS Tunneling** (`PS-DNS-003`) | Writing secret, scrambled spy messages inside the return address of regular mail letters. | Smuggling stolen company data inside unusually long, encoded web domain queries (e.g. 80+ character domains). | **HIGH** |
| **Traffic Spike / Exfiltration** (`PS-VOL-004`) | Someone sneaking giant unmarked crates out the company back door at 2:00 AM. | A single computer sending or downloading massive, abnormal amounts of data in a short window. | **MEDIUM** |
| **Insecure / Cleartext Ports** (`PS-PROTO-005`) | Mailing your credit card number on an open postcard where anyone can read it. | Using old, unencrypted communication protocols (like Telnet or cleartext FTP) where passwords travel in plain sight. | **LOW** |

---

## 📁 What Files Do You Get? (The Output)

Whenever PacketSentry analyzes a file, it creates an organized case folder under `output/investigations/INV_<filename>_<timestamp>/` containing:

1. **`incident_report_<name>.pdf`**: A clean, printable PDF report complete with executive summaries, threat severity breakdowns, packet charts, and remediation steps.
2. **`investigation_summary.json`**: A high-level scorecard showing total packets, execution time, and whether emergency escalation was needed.
3. **`alerts.json`**: Granular details on every single alert triggered, including exact packet frame numbers and evidence.
4. **`telemetry.json`**: Breakdown of IP addresses, top talkers, and protocols used.
5. **`<name>_extracted.csv`**: The raw data converted into a clean spreadsheet ready for Excel or SIEM tools.

---

## 🚀 How to Run PacketSentry (Step-by-Step)

### 1. Prerequisites (What you need on your computer)
- **Python 3.10 or newer** (Check with `python --version`)
- **Wireshark / TShark** (Free from [wireshark.org](https://www.wireshark.org/))
- **Windows, Mac, or Linux** (Commands below use Windows PowerShell)

### 2. Download and Setup
```powershell
# 1. Open your terminal and go to the project folder
cd C:\Users\mehna\.gemini\antigravity\scratch\PacketSentry

# 2. Install the required Python packages (one-time setup)
pip install -r requirements.txt

# 3. Test that your system is ready
python analyzer/environment.py
```
*(You will see a green `[SYSTEM STATUS: READY]` message confirming TShark and Python are connected!)*

---

### Option A: The Visual Way (Interactive Web Dashboard)
*Best for exploring data, clicking charts, and viewing reports in your browser.*

```powershell
streamlit run app.py
```
1. Your browser will automatically open to `http://localhost:8501`.
2. Select any capture file from the dropdown (or upload your own).
3. Explore the **Overview Dashboard**, inspect packets in the **PCAP Analyzer**, manage alerts in the **Alert Triage Console**, and download your **PDF Report** with one click!

---

### Option B: The Automated Robot Way (UiPath RPA)
*Best for enterprise hands-off automation.*

#### Method 1: Using UiPath Studio
1. Open **UiPath Studio**.
2. Click **Open Project** and navigate to:
   ```text
   PacketSentry\uipath\project.json
   ```
3. Open `Main.xaml` and click **Run** (or press <kbd>F5</kbd>).
4. UiPath will scan `data/uploads/`, process every file found, check for security breaches, build PDF reports, and log the results!

#### Method 2: Running the RPA Orchestrator via Terminal
You don't even need UiPath Studio open to test the robot's logic! Run the native orchestrator script:
```powershell
cd uipath
powershell -ExecutionPolicy Bypass -File .\run_uipath_mock_orchestrator.ps1
```
To run it on a specific file only (for example, `atm_capture1.cap`):
```powershell
powershell -ExecutionPolicy Bypass -File .\run_uipath_mock_orchestrator.ps1 -TargetFile atm_capture1.cap
```

---

### Option C: The Fast Terminal Way (Command Line / CLI)
*Best for programmers, scripts, and server cron jobs.*

```powershell
python cli.py --pcap data/uploads/atm_capture1.cap --output-dir output/investigations --analyst "SOC Analyst"
```

---

## 🧪 Sample Captures Included for Testing

Two sample files are included in `data/uploads/` so you can test both scenarios immediately:

1. **`sample_capture.pcap` (The Attacker Scenario)**:
   - Contains simulated port scans, SMB brute-forcing, and long DNS tunneling queries.
   - **Result**: Triggers 5 security alerts (High & Medium risk).
   - **Robot Verdict**: `ESCALATED_HIGH_PRIORITY` (Exit Code 10).

2. **`atm_capture1.cap` (The Normal Traffic Scenario)**:
   - Contains real-world ICMP network connectivity checks between ATM banking terminals.
   - **Result**: 0 alerts triggered (100% clean benign traffic).
   - **Robot Verdict**: `STANDARD_ARCHIVE` (Exit Code 0).

---

## 🏆 Project Structure

```text
PacketSentry/
├── app.py                     # Interactive Streamlit Web Dashboard
├── cli.py                     # Command-line interface for automation
├── requirements.txt           # Required Python libraries
├── README.md                  # This guide!
├── HANDBOOK.md                # In-depth SOC Analyst operations guide
├── analyzer/                  # The Detection & Analytics Engine
│   ├── environment.py         # System health & TShark path detector
│   ├── pcap_parser.py         # Reads & decodes raw packet captures
│   ├── traffic_analyzer.py    # Computes network statistics & metrics
│   ├── rules.py               # Security rules & MITRE ATT&CK definitions
│   ├── detection_engine.py    # Evaluates packets against threat rules
│   └── alert_manager.py       # Triage lifecycle (New, Investigating, Resolved)
├── reporting/                 # Report Generator
│   └── report_generator.py    # Builds executive PDF incident reports
├── data/
│   └── uploads/               # Drop new .pcap / .cap files here
├── output/
│   └── investigations/        # Finished investigation folders and audit logs
├── uipath/                    # UiPath RPA Automation Assets
│   ├── project.json           # UiPath project configuration
│   ├── Main.xaml              # UiPath visual workflow
│   ├── workflow_documentation.md # Technical RPA architecture specs
│   └── run_uipath_mock_orchestrator.ps1 # Standalone automation test runner
└── tests/                     # 40 Automated unit & integration tests
```

---

## 🎯 Verification & Quality Assurance

PacketSentry is built with robust test coverage. To run all 40 automated tests:

```powershell
python -m unittest discover tests
```

```text
........................................
----------------------------------------------------------------------
Ran 40 tests in 24.099s

OK
```

---

## 💼 Why This Matters for a SOC Analyst Role

- **No Black Boxes**: Every single alert points to concrete, un-forgeable evidence (exact packet frame numbers, bytes, and timestamps).
- **Prevents Alarm Fatigue**: All detection thresholds are fully customizable in `rules.py` to adapt to different network baselines.
- **Enterprise-Ready RPA**: Demonstrates hands-on knowledge of how modern Security Orchestration, Automation, and Response (**SOAR**) systems operate in real enterprise environments.
- **100% Privacy & Data Sovereignty**: Everything runs locally on your machine. Sensitive company network data is never uploaded to third-party cloud APIs.
