"""
Unit & Integration Tests for PacketSentry Detection Engine Module.
"""

import json
import tempfile
import unittest
from pathlib import Path
import pandas as pd

from analyzer.detection_engine import DetectionEngine
from analyzer.pcap_parser import PCAPParser
from analyzer.rules import AlertSeverity
from analyzer.traffic_analyzer import TrafficAnalyzer
from tests.generate_test_pcaps import generate_sample_pcap


class TestDetectionEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap_path = Path("data/uploads/sample_capture.pcap")
        if not cls.pcap_path.exists():
            generate_sample_pcap(cls.pcap_path)

        parser = PCAPParser()
        cls.df = parser.parse(cls.pcap_path)
        cls.analyzer = TrafficAnalyzer(cls.df)
        cls.telemetry = cls.analyzer.generate_full_telemetry()

    def test_empty_dataframe(self):
        engine = DetectionEngine()
        alerts = engine.evaluate(pd.DataFrame())
        self.assertEqual(len(alerts), 0)

    def test_sample_capture_detections(self):
        engine = DetectionEngine()
        alerts = engine.evaluate(self.df, self.telemetry)

        self.assertGreater(len(alerts), 0, "Detection engine should identify suspicious activities in sample capture")

        rule_ids = [a["rule_id"] for a in alerts]

        # 1. Port scan rule
        self.assertIn("PS-SCAN-001", rule_ids)
        scan_alert = next(a for a in alerts if a["rule_id"] == "PS-SCAN-001")
        self.assertEqual(scan_alert["src_ip"], "10.0.0.99")
        self.assertEqual(scan_alert["dst_ip"], "192.168.1.50")
        self.assertGreaterEqual(scan_alert["evidence"]["distinct_ports_contacted"], 10)
        self.assertIn("T1046", scan_alert["mitre_attack"])

        # 2. Repeated SYN rule
        self.assertIn("PS-CONN-002", rule_ids)
        syn_alert = next(a for a in alerts if a["rule_id"] == "PS-CONN-002")
        self.assertEqual(syn_alert["src_ip"], "10.0.0.77")
        self.assertEqual(syn_alert["dst_ip"], "192.168.1.50")
        self.assertEqual(syn_alert["dst_port"], 445)
        self.assertGreaterEqual(syn_alert["evidence"]["unacknowledged_syn_count"], 8)

        # 3. DNS anomaly rule
        self.assertIn("PS-DNS-003", rule_ids)
        dns_alert = next(a for a in alerts if a["rule_id"] == "PS-DNS-003")
        self.assertIn("c2-command-and-control-server", dns_alert["evidence"]["queried_domain"])
        self.assertGreaterEqual(dns_alert["evidence"]["domain_length_chars"], 45)

        # 4. Suspicious protocol / high-risk port
        self.assertIn("PS-PROTO-005", rule_ids)

    def test_configurable_thresholds(self):
        # Setting threshold higher than 15 should suppress port scan alert
        high_threshold_engine = DetectionEngine({"port_scan_distinct_ports": 50})
        alerts = high_threshold_engine.evaluate(self.df, self.telemetry)
        scan_alerts = [a for a in alerts if a["rule_id"] == "PS-SCAN-001"]
        self.assertEqual(len(scan_alerts), 0)

        # Setting threshold to 5 should trigger it
        low_threshold_engine = DetectionEngine({"port_scan_distinct_ports": 5})
        alerts_low = low_threshold_engine.evaluate(self.df, self.telemetry)
        scan_alerts_low = [a for a in alerts_low if a["rule_id"] == "PS-SCAN-001"]
        self.assertEqual(len(scan_alerts_low), 1)

    def test_alert_structure_and_reasoning(self):
        engine = DetectionEngine()
        alerts = engine.evaluate(self.df, self.telemetry)
        for alert in alerts:
            self.assertIn("alert_id", alert)
            self.assertIn("rule_id", alert)
            self.assertIn("severity", alert)
            self.assertIn("detection_reasoning", alert)
            self.assertIn("recommended_steps", alert)
            self.assertIn("mitre_attack", alert)
            self.assertGreater(len(alert["recommended_steps"]), 0)
            self.assertTrue(len(alert["detection_reasoning"]) > 10)

    def test_export_alerts_json(self):
        engine = DetectionEngine()
        alerts = engine.evaluate(self.df, self.telemetry)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name

        exported_path = engine.export_alerts_json(alerts, temp_path)
        with open(exported_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), len(alerts))
        Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
