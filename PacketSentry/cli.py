"""
PacketSentry Command-Line Interface (CLI) Entrypoint
Enables headless execution for UiPath automation bots, SIEM pipelines, and scheduled scripts.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from analyzer.alert_manager import AlertManager
from analyzer.detection_engine import DetectionEngine
from analyzer.environment import validate_environment
from analyzer.pcap_parser import (
    PCAPExtractionError,
    PCAPParser,
    PCAPValidationError,
    validate_pcap_file,
)
from analyzer.rules import get_default_thresholds
from analyzer.traffic_analyzer import TrafficAnalyzer
from reporting.report_generator import SOCReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [PacketSentry.CLI] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("PacketSentry.CLI")


def run_cli_pipeline(
    pcap_path: str,
    output_dir: str,
    generate_pdf: bool = True,
    analyst_name: str = "PacketSentry Automation Bot",
    classification: str = "CONFIDENTIAL // TLP:AMBER",
    thresholds_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes end-to-end extraction, analytics, detection, and reporting.

    Returns:
        Structured execution summary dictionary for UiPath consumption.
    """
    start_time = datetime.now(timezone.utc)
    in_file = Path(pcap_path)

    # 1. Validation
    meta = validate_pcap_file(in_file)
    logger.info(f"Validated capture: {meta['filename']} ({meta['file_size_mb']} MB, Format: {meta['format']})")

    # 2. Output directory preparation
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    investigation_id = f"INV_{in_file.stem}_{timestamp_slug}"
    out_path = Path(output_dir) / investigation_id
    out_path.mkdir(parents=True, exist_ok=True)

    # 3. Extraction
    parser = PCAPParser()
    df = parser.parse(in_file)
    logger.info(f"Extracted {len(df):,} packet frames")

    # Export extracted CSV and JSON
    exported_paths = parser.export_processed_data(df, out_path, in_file.stem)

    # 4. Traffic Analytics
    analyzer = TrafficAnalyzer(df)
    telemetry = analyzer.generate_full_telemetry()
    telemetry_path = out_path / "telemetry.json"
    with open(telemetry_path, "w", encoding="utf-8") as f:
        json.dump(telemetry, f, indent=2)

    # 5. Detection Engine
    thresholds = get_default_thresholds()
    if thresholds_file and os.path.exists(thresholds_file):
        with open(thresholds_file, "r", encoding="utf-8") as tf:
            custom_thresh = json.load(tf)
            thresholds.update(custom_thresh)

    engine = DetectionEngine(thresholds=thresholds)
    alerts = engine.evaluate(df, telemetry)
    alerts_path = out_path / "alerts.json"
    engine.export_alerts_json(alerts, alerts_path)

    # 6. Report Generation
    pdf_path = None
    if generate_pdf:
        pdf_target = out_path / f"incident_report_{in_file.stem}.pdf"
        generator = SOCReportGenerator(
            pcap_path=in_file,
            telemetry=telemetry,
            alerts=alerts,
            analyst_name=analyst_name,
            classification=classification,
        )
        pdf_path = generator.generate(pdf_target)
        logger.info(f"Generated PDF Investigation Report: {pdf_path}")

    end_time = datetime.now(timezone.utc)
    duration_sec = round((end_time - start_time).total_seconds(), 2)

    # 7. Summary Artifact
    manager = AlertManager(alerts)
    sev_counts = manager.get_severity_counts()
    has_high_or_crit = (sev_counts["Critical"] + sev_counts["High"]) > 0

    summary_payload = {
        "investigation_id": investigation_id,
        "status": "COMPLETED",
        "input_pcap": str(in_file.resolve()),
        "investigation_folder": str(out_path.resolve()),
        "execution_start": start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "execution_end": end_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "processing_time_sec": duration_sec,
        "packets_processed": len(df),
        "total_alerts_count": len(alerts),
        "alerts_by_severity": sev_counts,
        "high_or_critical_alerts_detected": has_high_or_crit,
        "artifacts": {
            "extracted_csv": exported_paths["csv"],
            "extracted_json": exported_paths["json"],
            "telemetry_json": str(telemetry_path.resolve()),
            "alerts_json": str(alerts_path.resolve()),
            "pdf_report": str(Path(pdf_path).resolve()) if pdf_path else None,
        },
    }

    summary_file = out_path / "investigation_summary.json"
    with open(summary_file, "w", encoding="utf-8") as sf:
        json.dump(summary_payload, sf, indent=2)

    return summary_payload


def main():
    parser = argparse.ArgumentParser(
        description="PacketSentry CLI – Headless Network Traffic Analyzer & SOC Automation Engine"
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to input .pcap or .pcapng packet capture file.",
    )
    parser.add_argument(
        "--output-dir",
        default="output/investigations",
        help="Root directory where investigation artifacts and reports will be filed.",
    )
    parser.add_argument(
        "--no-pdf",
        action="store_true",
        help="Disable automatic PDF investigation report generation.",
    )
    parser.add_argument(
        "--analyst",
        default="UiPath Automated SOC Bot",
        help="Lead analyst / agent identity recorded on reports.",
    )
    parser.add_argument(
        "--classification",
        default="CONFIDENTIAL // TLP:AMBER",
        help="Information classification marking.",
    )
    parser.add_argument(
        "--thresholds",
        default=None,
        help="Path to optional JSON file with custom detection thresholds.",
    )

    args = parser.parse_args()

    try:
        summary = run_cli_pipeline(
            pcap_path=args.pcap,
            output_dir=args.output_dir,
            generate_pdf=not args.no_pdf,
            analyst_name=args.analyst,
            classification=args.classification,
            thresholds_file=args.thresholds,
        )

        # Output JSON result to stdout for UiPath process capture
        print("\n=== PACKETSENTRY_EXECUTION_RESULT_JSON ===")
        print(json.dumps(summary, indent=2))
        print("=== END_RESULT ===\n")

        # Exit code convention:
        # Exit 10: Successful run with High/Critical alerts detected
        # Exit 0: Successful run with clean or low-severity findings
        if summary.get("high_or_critical_alerts_detected"):
            sys.exit(10)
        else:
            sys.exit(0)

    except PCAPValidationError as ve:
        logger.error(f"Validation Failure: {str(ve)}")
        err_out = {"status": "VALIDATION_FAILED", "error": str(ve)}
        print(json.dumps(err_out))
        sys.exit(1)
    except PCAPExtractionError as ee:
        logger.error(f"Extraction Failure: {str(ee)}")
        err_out = {"status": "EXTRACTION_FAILED", "error": str(ee)}
        print(json.dumps(err_out))
        sys.exit(2)
    except Exception as e:
        logger.exception(f"Unexpected Execution Error: {str(e)}")
        err_out = {"status": "EXECUTION_ERROR", "error": str(e)}
        print(json.dumps(err_out))
        sys.exit(3)


if __name__ == "__main__":
    main()
