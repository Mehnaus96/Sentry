# PacketSentry – SOC Analyst Operational Handbook & User Guide

> **Document Version:** 1.0.0  
> **Classification:** CONFIDENTIAL // SOC INTERNAL USE ONLY  
> **Target Audience:** Tier-1 / Tier-2 SOC Analysts, Incident Responders, Cybersecurity Interns  
> **System:** PacketSentry Automated Network Traffic Analyzer & SOC Reporting System  

---

## 📑 Table of Contents

1. [Introduction & Operational Purpose](#1-introduction--operational-purpose)
2. [Prerequisites & Environment Setup](#2-prerequisites--environment-setup)
3. [Day-to-Day SOC Analyst Workflows](#3-day-to-day-soc-analyst-workflows)
   - [Workflow A: Ingesting & Dissecting a PCAP](#workflow-a-ingesting--dissecting-a-pcap)
   - [Workflow B: Triaging Dashboard Threat Indicators](#workflow-b-triaging-dashboard-threat-indicators)
   - [Workflow C: Deep-Dive Alert Investigation](#workflow-c-deep-dive-alert-investigation)
   - [Workflow D: Case Triage & Updating Investigation States](#workflow-d-case-triage--updating-investigation-states)
   - [Workflow E: Compiling & Distributing the SOC Incident Report](#workflow-e-compiling--distributing-the-soc-incident-report)
   - [Workflow F: Calibrating Detection Thresholds](#workflow-f-calibrating-detection-thresholds)
4. [Threat Detection Playbooks & Triage Reference](#4-threat-detection-playbooks--triage-reference)
   - [Playbook PS-SCAN-001: Port Scanning & Reconnaissance](#playbook-ps-scan-001-port-scanning--reconnaissance)
   - [Playbook PS-CONN-002: Repeated Failed Connections (SYN Flood / Brute Force)](#playbook-ps-conn-002-repeated-failed-connections-syn-flood--brute-force)
   - [Playbook PS-DNS-003: DNS Tunneling & DGA Anomalies](#playbook-ps-dns-003-dns-tunneling--dga-anomalies)
   - [Playbook PS-VOL-004: Anomalous Bandwidth Spikes & Exfiltration](#playbook-ps-vol-004-anomalous-bandwidth-spikes--exfiltration)
   - [Playbook PS-PROTO-005: High-Risk Cleartext Protocol Usage](#playbook-ps-proto-005-high-risk-cleartext-protocol-usage)
5. [UiPath Robotic Process Automation (SOAR) Guide](#5-uipath-robotic-process-automation-soar-guide)
6. [Forensic Principles: Evidence vs. Interpretation](#6-forensic-principles-evidence-vs-interpretation)
7. [Troubleshooting & FAQs](#7-troubleshooting--faqs)
8. [Internship Interview Live Demonstration Script](#8-internship-interview-live-demonstration-script)

---

## 1. Introduction & Operational Purpose

**PacketSentry** is an automated network security monitoring and forensic investigation platform. It transforms offline packet captures (`.pcap`, `.pcapng`) into structured telemetry, detects adversarial behavior through deterministic rules mapped to **MITRE ATT&CK**, facilitates case management, and publishes executive-ready PDF reports.

### The Problem PacketSentry Solves in the SOC
- **Manual Wireshark Fatigue:** Opening a 500 MB capture in Wireshark and manually typing display filters (`tcp.flags.syn==1 && tcp.flags.ack==0`) is slow, error-prone, and unscalable.
- **Black-Box Confusion:** Generic machine-learning tools flag "anomaly scores" without explaining which packet or byte caused the alert. PacketSentry provides **transparent, evidence-backed findings** linking directly to packet frame numbers.
- **Reporting Bottlenecks:** Compiling an incident report by copying and pasting screenshots into Word wastes hours. PacketSentry generates audit-ready PDF reports in seconds.
- **Unattended SOAR Automation:** Through UiPath Studio, incoming firewall and sandbox captures are triaged automatically without human intervention.

---

## 2. Prerequisites & Environment Setup

### System Requirements
- **Operating System:** Windows 10/11 (or Linux / macOS)
- **Python:** Version 3.10 to 3.14
- **Wireshark / TShark:** Installed locally (PacketSentry auto-discovers `C:\Program Files\Wireshark\tshark.exe` or system `PATH`).

### Starting the Web Console
Open PowerShell, navigate to the project directory, and launch the Streamlit server:
```powershell
cd C:\Users\mehna\.gemini\antigravity\scratch\PacketSentry
streamlit run app.py
```
Your browser will open automatically at `http://localhost:8501`.

### Verifying System Status
Upon launch, inspect the sidebar indicator:
- **`ENGINE ONLINE` (Green):** Local TShark binary detected, analytical dependencies active.
- **`DEGRADED` (Red):** TShark is missing or inaccessible. Check the **Settings & Thresholds** page for diagnostic logs.

---

## 3. Day-to-Day SOC Analyst Workflows

### Workflow A: Ingesting & Dissecting a PCAP

1. Navigate to **🔍 PCAP Analyzer** in the sidebar.
2. In the **Upload PCAP / PCAPNG File** box:
   - Drag and drop your `.pcap`, `.pcapng`, or `.cap` file.
   - *Or:* Click **"📁 Load Staged Sample Capture"** to explore the built-in multi-flow test capture.
3. Click **"⚡ Process Uploaded File"**.
4. The extraction pipeline will:
   - Validate magic bytes (rejecting non-capture or corrupt files).
   - Invoke headless TShark to extract timestamps, IPs, ports, protocols, TCP flags, and DNS queries.
   - Synthesize a 5-tuple flow identifier (`connection_id`).
   - Automatically export raw results to `data/processed/<filename>_extracted.csv` and `.json`.
5. Use the **Extracted Packet Telemetry Explorer** to filter by protocol, search by IP address, or inspect specific frame numbers.

---

### Workflow B: Triaging Dashboard Threat Indicators

1. Navigate to **📊 Dashboard** in the sidebar.
2. Review the top KPI bar:
   - **Total Packets & Volume:** Is the file size consistent with the incident window?
   - **Unique Hosts:** Does the capture involve local subnets (`192.168.x.x`, `10.x.x.x`) or external IPs?
   - **High/Crit Alerts:** Number of priority detections requiring immediate escalation.
3. Inspect the visualization charts:
   - **Protocol Donut:** Look for unexpected protocol dominance (e.g. DNS exceeding 20% indicates potential tunneling).
   - **Alerts by Severity:** Quick view of the threat distribution.
   - **Network Traffic Timeline:** Identify traffic spikes or sustained bursts.
   - **Top Destination Ports:** Look for non-standard ports (e.g., port 445 SMB across WAN, or port 4444 Metasploit).

---

### Workflow C: Deep-Dive Alert Investigation

1. Navigate to **🚨 Security Alerts** in the sidebar.
2. Use the **Filter Bar** to prioritize:
   - Set **Severity** to `["High", "Critical"]`.
   - Set **Triage Status** to `["New"]`.
3. Locate the alert in the table and expand its **Alert Forensic Dossier**:
   - **📌 Detection Reasoning & Hypothesis:** Read the plain-language explanation of why this was flagged.
   - **🔎 Observed Forensic Evidence:** Inspect the hard wire evidence (e.g., list of probed ports `[21, 22, 23, ...]`, FQDN character length `83`, unacknowledged SYN count `12`).
   - **Frame Numbers:** Note the packet frame numbers (e.g., `Frames: [5, 6, 7, 8, 9]`). You can verify these identical frames in Wireshark or in the PCAP Analyzer table!
   - **MITRE ATT&CK Mapping:** Identifies the adversary tactic (e.g., `T1046 - Network Service Discovery`).

---

### Workflow D: Case Triage & Updating Investigation States

1. Inside the expanded Alert Dossier:
2. Under **✍️ SOC Triage Action & Case Notes**:
   - **Update Triage Status:**
     - Change from `New` to `Under Investigation` while actively researching.
     - Change to `Escalated` if malicious activity is confirmed and incident response team (CIRT) intervention is required.
     - Change to `False Positive` if verified as an authorized vulnerability scanner or benign administrative script.
     - Change to `Resolved` after containment or verification.
   - **Assigned Analyst:** Enter your name or analyst handle.
   - **Analyst Investigation Notes:** Record defensible, objective notes detailing your findings (e.g., *"Host 10.0.0.99 confirmed scanning internal DMZ subnet. Firewall logs verify 15 ports rejected. Escalated to Tier 2."*).
3. Click **"💾 Save Triage Update"**. The state persists immediately to session memory and JSON disk records.

---

### Workflow E: Compiling & Distributing the SOC Incident Report

1. Navigate to **📑 Investigation Reports** in the sidebar.
2. Enter the **Lead Investigating Analyst** name (e.g., *"Alex Rivera, SOC Analyst"*).
3. Select the appropriate **Information Classification Banner**:
   - `CONFIDENTIAL // TLP:AMBER` (Standard internal SOC sharing)
   - `RESTRICTED // SOC INTERNAL` (High-sensitivity incidents)
   - `PUBLIC RELEASE // UNCLASSIFIED` (Sanitized reports)
4. Click **"📄 Generate PDF Investigation Report"**.
5. Once compiled, click **"⬇️ Download PDF Investigation Report"**.
6. The resulting PDF includes:
   - Unique Report ID (e.g. `IR-20261115-4672`)
   - Cryptographic SHA-256 and MD5 hashes of the PCAP file.
   - Macro KPIs, protocol breakdown table, and top talkers table.
   - Security detection register and detailed evidence dossiers.
   - Chronological incident reconstruction timeline.
   - Deduplicated incident response playbook checklist.
   - Analyst conclusion and formal sign-off signature block.

---

### Workflow F: Calibrating Detection Thresholds

1. Navigate to **⚙️ Settings & Thresholds** in the sidebar.
2. When analyzing traffic from specific environments (e.g., a penetration testing engagement or network backup window), adjust the sliders:
   - **Port Scan Distinct Ports Threshold:** Raise from `10` to `30` if analyzing authorized vulnerability scanners.
   - **Repeated SYN Threshold:** Adjust for high-latency or packet-loss WAN links.
   - **DNS Maximum Domain Length:** Adjust for enterprise environments with deep subdomains (e.g., AWS service endpoints).
   - **Volume Spike (MB):** Adjust for bulk database replication links.
3. Click **"💾 Apply Thresholds & Re-evaluate Detections"**.
4. The detection engine will immediately re-run across the active capture with the new thresholds without needing to reload the PCAP file.

---

## 4. Threat Detection Playbooks & Triage Reference

### Playbook PS-SCAN-001: Port Scanning & Reconnaissance
- **Severity:** High  
- **MITRE ATT&CK:** `T1046 - Network Service Discovery`  
- **Detection Logic:** A single source IP initiates connections to $\ge 10$ distinct destination ports on a target host within a 60-second window.
- **Investigative Steps:**
  1. Determine host role: Is the source IP an authorized internal vulnerability scanner (e.g. Nessus, Qualys)?
  2. Inspect target responses: Did any probed ports answer with TCP `SYN-ACK` (port open) or `RST` (port closed/firewalled)?
  3. Correlate with perimeter firewall / IPS logs for blocked port sweep attempts.
  4. If unauthorized, isolate the source host from the network switch/VLAN and initiate endpoint forensics.

---

### Playbook PS-CONN-002: Repeated Failed Connections (SYN Flood / Brute Force)
- **Severity:** Medium  
- **MITRE ATT&CK:** `T1110 - Brute Force` / `T1498 - Network Denial of Service`  
- **Detection Logic:** A source IP sends $\ge 8$ TCP SYN packets to the same destination port without completing handshakes (0 SYN-ACK responses received).
- **Investigative Steps:**
  1. Identify targeted service: Common targets include SMB (445), RDP (3389), SSH (22), and database listeners (1433, 3306).
  2. Check target host logs: Are there corresponding failed Windows Event ID 4625 (failed login) entries?
  3. Differentiate between an active brute-force attack vs. a network misconfiguration (e.g., an application trying to connect to a service that is down).
  4. Implement temporary firewall drop rules for the offending IP if brute-force attack is confirmed.

---

### Playbook PS-DNS-003: DNS Tunneling & DGA Anomalies
- **Severity:** High  
- **MITRE ATT&CK:** `T1071.004 - Application Layer Protocol: DNS` / `T1568 - Dynamic Resolution`  
- **Detection Logic:** DNS query featuring a domain name $\ge 45$ characters in length, or burst query volume surges.
- **Investigative Steps:**
  1. Inspect the queried FQDN: Look for encoded strings (Base64, hex) in subdomains (e.g. `v1-exfil-secret-data...`).
  2. Query external threat intelligence (VirusTotal, AlienVault OTX, Quad9) for the parent domain reputation.
  3. Inspect the requesting client endpoint: Check running processes, PowerShell executions, or scheduled tasks active at the time of the query.
  4. Sinkhole or block the parent domain at enterprise recursive resolvers (e.g., Infoblox, Cisco Umbrella).

---

### Playbook PS-VOL-004: Anomalous Bandwidth Spikes & Exfiltration
- **Severity:** Medium  
- **MITRE ATT&CK:** `T1048 - Exfiltration Over Alternative Protocol`  
- **Detection Logic:** A single host transmits $\ge 5$ MB of data or accounts for $\ge 75\%$ of total capture volume.
- **Investigative Steps:**
  1. Resolve destination IP: Is it an authorized enterprise cloud repository (OneDrive, AWS S3, Google Cloud) or an unknown foreign IP?
  2. Check business hours: Did the massive transfer take place during off-hours or maintenance windows?
  3. Correlate with Endpoint Data Loss Prevention (DLP) alerts for sensitive file reads or archive creation (`.zip`, `.7z`).
  4. If unauthorized data exfiltration is suspected, immediately revoke user credentials and quarantine the host.

---

### Playbook PS-PROTO-005: High-Risk Cleartext Protocol Usage
- **Severity:** Low  
- **MITRE ATT&CK:** `T1040 - Network Sniffing` / `T1571 - Non-Standard Port`  
- **Detection Logic:** Traffic targeting unencrypted legacy management ports (Telnet 23, cleartext FTP 21, VNC 5900, or backdoor listeners 4444, 31337).
- **Investigative Steps:**
  1. Determine if credentials or sensitive session data are exposed in cleartext.
  2. Check enterprise policy: Cleartext administrative protocols typically violate PCI-DSS, HIPAA, and CIS Benchmarks.
  3. Notify the system owner to migrate to encrypted protocols (Telnet $\to$ SSH, FTP $\to$ SFTP/SCP).
  4. Ensure administrative access is restricted via network access control lists (ACLs) or management jump hosts.

---

## 5. UiPath Robotic Process Automation (SOAR) Guide

In an automated SOC environment, PacketSentry operates unattended via **UiPath Studio**.

### Architecture Overview
1. **Intake Directory:** The UiPath Robot monitors `data/uploads/` for new `.pcap` or `.pcapng` files.
2. **Execution:** The robot launches the headless analysis engine:
   ```powershell
   python cli.py --pcap data/uploads/new_capture.pcap --output-dir output/investigations
   ```
3. **Exit Code Decision Node:**
   - **`Exit Code 10` (High/Critical Threats Found):** The robot immediately routes the incident to the high-priority triage queue and sends the generated PDF report to the on-call analyst via Outlook.
   - **`Exit Code 0` (Clean Capture):** The robot logs the event as benign and archives the files into `output/investigations/`.
   - **`Exit Code 1/2` (Error):** The robot moves corrupt files to quarantine and alerts engineering.
4. **Audit Trail:** Every run appends an entry to `output/investigations/execution_audit.log`.

### Running the RPA Simulation
To test the entire 9-step UiPath workflow locally without opening UiPath Studio:
```powershell
powershell -ExecutionPolicy Bypass -File uipath/run_uipath_mock_orchestrator.ps1
```

---

## 6. Forensic Principles: Evidence vs. Interpretation

A core differentiator of PacketSentry is its strict adherence to digital forensic integrity:

| Observed Forensic Evidence (Deterministic) | Security Interpretation (Threat Hypothesis) |
| :--- | :--- |
| Host `10.0.0.99` sent 15 TCP SYN packets to ports 21, 22, 23, 80, 443 on host `192.168.1.50`. | Pattern strongly indicates automated port reconnaissance or vulnerability scanning. |
| Host `10.0.0.77` sent 12 TCP SYN packets to port 445; 0 SYN-ACK responses were received. | Pattern indicates SMB authentication brute force or connection attempts to a filtered port. |
| Host `192.168.1.200` queried a domain name of 83 characters. | Pattern indicates possible DNS tunneling exfiltration or DGA malware beaconing. |

> [!IMPORTANT]
> **Analyst Golden Rule:** Never label an IP address "malicious" based solely on an unusual pattern. Always verify whether the activity corresponds to scheduled vulnerability scans, administrative maintenance, or approved cloud synchronization before initiating host quarantine.

---

## 7. Troubleshooting & FAQs

### Q1: The sidebar shows "SYSTEM STATUS: DEGRADED (TSHARK MISSING)". How do I fix this?
- Ensure Wireshark is installed on your machine.
- PacketSentry looks for `tshark.exe` in `C:\Program Files\Wireshark\tshark.exe` and `C:\Program Files (x86)\Wireshark\tshark.exe`.
- If Wireshark is installed in a non-standard location, add its folder to your Windows system `PATH` environment variable and restart the application.

### Q2: What happens if an analyst uploads a corrupted or non-PCAP file?
- PacketSentry inspects binary **magic bytes** before passing files to TShark.
- Non-PCAP files (e.g. renamed `.exe` or `.txt` files) or 0-byte captures will be caught immediately by `validate_pcap_file()` and display a clean error message without crashing the application.

### Q3: How do I export data for Splunk, Elastic, or Microsoft Sentinel?
- For packet-level data: In **PCAP Analyzer**, click **"Export Filtered Packets (JSON)"**.
- For alerts: In the CLI or UiPath pipeline, `alerts.json` and `investigation_summary.json` are generated in standard key-value format, ready for direct ingestion by SIEM forwarders.

---

## 8. Internship Interview Live Demonstration Script

Use this structured 3-minute walkthrough when presenting PacketSentry during an interview:

### Minute 1: The Problem & The Solution
> *"Hi! For my portfolio, I built **PacketSentry**—an automated network traffic analyzer and SOC reporting system. In a typical SOC, tier-1 analysts spend hours manually filtering PCAP files in Wireshark and copying tables into incident reports. PacketSentry automates this entire pipeline: it ingests raw packet captures, extracts protocol telemetry via local TShark, runs deterministic threat detection rules, facilitates case triage, and compiles formal PDF incident reports."*

### Minute 2: Live Demonstration
> *(Open the Streamlit app)*  
> *"Here on the **Dashboard**, we see real-time KPIs and Plotly charts showing protocol distribution and threat severity. Under the **PCAP Analyzer**, we validate capture magic bytes and explore extracted frames down to the 5-tuple flow level.*  
> *Under **Security Alerts**, our rule engine flagged three distinct threat vectors in our sample capture: a 15-port reconnaissance scan from `10.0.0.99`, an SMB brute-force attempt from `10.0.0.77`, and an 83-character DNS exfiltration tunnel from `192.168.1.200`. Each alert displays hard wire evidence—down to the exact packet frame numbers—and an actionable incident response playbook."*

### Minute 3: Architecture, SOAR & DFIR Rigor
> *(Show the generated PDF report and UiPath files)*  
> *"Two key design principles make this enterprise-ready:  
> First, **Forensic Rigor**: our PDF report explicitly separates deterministic wire evidence from analytical interpretation, and includes cryptographic SHA-256 digests for chain of custody.  
> Second, **SOAR Automation**: we integrated UiPath Studio to monitor intake folders, automatically dispatch headless analyses via `cli.py`, evaluate decision return codes (`Exit 10` for High threats), file incident artifacts, and write immutable audit logs.*  
> *This demonstrates my practical understanding of network protocols, detection engineering, incident investigation, and automation."*
