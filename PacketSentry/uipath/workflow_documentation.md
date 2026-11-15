# PacketSentry – UiPath Studio Automation & Orchestration Specification

This document details the enterprise Robotic Process Automation (RPA) workflow built in **UiPath Studio** to automate the intake, validation, analysis dispatch, alert verification, artifact filing, and incident escalation for network packet captures.

---

## 1. High-Level Automation Architecture

The UiPath Robot acts as the **Security Orchestrator**:

```
+-----------------------------------------------------------------------------------+
|                           UiPath Orchestration Robot                              |
|                                                                                   |
|  [Step 1] File Trigger / Folder Watcher (data/uploads/*.pcap, *.pcapng)           |
|         │                                                                         |
|  [Step 2] File Validation (Extension, Size, Non-Zero Bytes Check)                |
|         │                                                                         |
|  [Step 3] Invoke PacketSentry Engine (cli.py --pcap <Path> --output-dir <Dest>)   |
|         │                                                                         |
|  [Step 4] Process Wait & Exit Code Evaluation (Sync on CLI completion)            |
|         │                                                                         |
|  [Step 5] Read & Deserialize 'investigation_summary.json'                         |
|         │                                                                         |
|  [Step 6] Evaluate Alert Threshold (Exit Code == 10 or High/Critical Alerts > 0) |
|         ├── High/Critical Alerts Detected ──> [Alert Branch: High Priority]       |
|         └── Low / Clean Capture ────────────> [Standard Archive Branch]           |
|         │                                                                         |
|  [Step 7] Artifact Filing & Investigation Directory Organization                  |
|         │                                                                         |
|  [Step 8] Trigger & Verify PDF Investigation Report Compilation                   |
|         │                                                                         |
|  [Step 9] Audit Logging, Execution Status Recording & Escalation Dispatch         |
+-----------------------------------------------------------------------------------+
```

---

## 2. UiPath Project Dependencies

To open and run the workflow in **UiPath Studio**:
- `UiPath.System.Activities` (>= 23.4.0) — Process execution, file management, error handling.
- `UiPath.WebAPI.Activities` (>= 1.18.0) — `Deserialize JSON` for parsing `investigation_summary.json`.
- `UiPath.Mail.Activities` (Optional) — Emailing PDF reports to SOC distribution lists.

---

## 3. Workflow Arguments & Variables Schema

### Workflow Arguments (In/Out)

| Name | Direction | Type | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `in_WatchFolder` | In | `String` | `"data/uploads"` | Directory monitored for incoming `.pcap` files. |
| `in_OutputRoot` | In | `String` | `"output/investigations"` | Directory where investigation folders are created. |
| `in_PythonPath` | In | `String` | `"C:\Python314\python.exe"` | Path to Python runtime executable. |
| `in_ScriptPath` | In | `String` | `"cli.py"` | Path to PacketSentry CLI orchestration script. |
| `in_AnalystName` | In | `String` | `"UiPath Automated SOC Bot"` | Agent identity stamped on forensic reports. |
| `out_InvestigationId` | Out | `String` | `""` | Generated Unique Investigation ID. |
| `out_AlertCount` | Out | `Int32` | `0` | Total number of security alerts detected. |
| `out_ReportPdfPath` | Out | `String` | `""` | Absolute file path to the compiled PDF report. |
| `out_ExecutionStatus` | Out | `String` | `""` | Final status (`SUCCESS_ALERTS_DETECTED`, `SUCCESS_CLEAN`, `FAILED`). |

### Internal Workflow Variables

| Variable Name | Type | Scope | Description |
| :--- | :--- | :--- | :--- |
| `pcapFile` | `FileInfo` | Sequence | File object representing the captured PCAP. |
| `cliExitCode` | `Int32` | Sequence | Return code from `cli.py` (`0`=Clean, `10`=Threats Found). |
| `cliOutput` | `String` | Sequence | Raw standard output captured from Python subprocess. |
| `jsonSummaryContent`| `String` | Sequence | Content of `investigation_summary.json`. |
| `jsonSummaryObj` | `JObject` | Sequence | Parsed JSON object containing investigation telemetry. |
| `hasHighRiskAlerts` | `Boolean` | Sequence | Flag indicating presence of Critical or High alerts. |
| `auditLogEntry` | `String` | Sequence | Timestamped audit record written to `audit_trail.log`. |

---

## 4. Step-by-Step UiPath Studio Activity Sequence

### Step 1: Ingestion & Trigger
- **Activity:** `Directory.GetFiles` or `File Change Trigger` (using `System.IO`).
- **Filter:** `"*.pcap;*.pcapng;*.cap"`.
- **Logic:** Identifies unprocessed PCAP files in `in_WatchFolder`.

### Step 2: File Validation
- **Activity:** `If (File.Exists(pcapPath) And New FileInfo(pcapPath).Length > 24)`
- **True Branch:** Proceed to Step 3.
- **False Branch:** `Throw New BusinessRuleException("Input file is empty or missing.")`

### Step 3: Invoke Python Analysis Engine
- **Activity:** `Run PowerShell Script` or `Start Process`
  - **FileName:** `in_PythonPath`
  - **Arguments:** `String.Format("cli.py --pcap ""{0}"" --output-dir ""{1}"" --analyst ""{2}""", pcapPath, in_OutputRoot, in_AnalystName)`
  - **Result:** `cliExitCode`
  - **Output:** `cliOutput`

### Step 4: Process Synchronization & Exit Code Inspection
- **Activity:** `Switch (cliExitCode)`
  - **Case 10:** High/Critical threat detections identified.
  - **Case 0:** Capture analyzed successfully; low/no threat detections.
  - **Case 1:** File signature / validation failed (`PCAPValidationError`).
  - **Case 2:** Packet extraction failed (`PCAPExtractionError`).
  - **Default:** General execution failure.

### Step 5: Read & Deserialize Investigation Results
- **Activity:** `Read Text File` reading `investigation_summary.json` from the output directory.
- **Activity:** `Deserialize JSON` (using `UiPath.WebAPI.Activities.DeserializeJson<JObject>`).
  - Extracted fields:
    - `out_InvestigationId = jsonSummaryObj("investigation_id").ToString`
    - `out_AlertCount = CInt(jsonSummaryObj("total_alerts_count"))`
    - `hasHighRiskAlerts = CBool(jsonSummaryObj("high_or_critical_alerts_detected"))`
    - `out_ReportPdfPath = jsonSummaryObj("artifacts")("pdf_report").ToString`

### Step 6: Security Alert Routing & Conditional Branching
- **Activity:** `If (hasHighRiskAlerts = True)`
  - **Then (High Priority Escalation):**
    - `Log Message [Warn]:` `"High/Critical security alerts detected! Initiating immediate SOC escalation."`
    - (Optional) `Send Outlook Mail Message` attaching `out_ReportPdfPath` with subject `[CRITICAL ALERT] Threat Detections in PCAP: " + pcapFile.Name`.
  - **Else (Standard Review):**
    - `Log Message [Info]:` `"Analysis completed. No critical threat detections identified."`

### Step 7: Artifact Organization & Filing
- The Python engine structures all telemetry, JSON alerts, CSV records, and PDF documents within:
  `output/investigations/<INV_NAME_TIMESTAMP>/`
- The UiPath workflow verifies that all 5 artifact files exist using `Path Exists`.

### Step 8: PDF Report Verification
- **Activity:** `Path Exists` targeting `out_ReportPdfPath`.
- **Validation:** Ensures file size > 5,000 bytes, verifying complete compilation.

### Step 9: Audit Logging & Status Recording
- **Activity:** `Append Line` writing to `output/investigations/execution_audit.log`:
  ```
  [2026-11-15 12:40:40 UTC] [SUCCESS] Investigation INV_sample_capture_20261115_071038 | Packets: 32 | Alerts: 5 | PDF: incident_report_sample_capture.pdf | Status: ESCALATED_HIGH_RISK
  ```

---

## 5. Error Handling & Resilience Strategy

1. **Global Try-Catch:**
   - Wraps the entire execution sequence.
   - Catches `BusinessRuleException` (invalid captures, empty files) and marks capture as `FAILED_VALIDATION`.
   - Catches general `System.Exception` (TShark crashes, disk space limits) and logs full stack trace to `audit_error.log`.
2. **Subprocess Timeout:**
   - UiPath process invocation sets a 180-second timeout to prevent runaway executions on massive captures.
3. **Quarantine Directory:**
   - If an uploaded file fails validation magic bytes, UiPath moves it to `data/quarantine/` to prevent reprocessing loops.
