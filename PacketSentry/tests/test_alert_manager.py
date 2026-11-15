"""
Unit & Integration Tests for PacketSentry Alert Management Module.
"""

import json
import tempfile
import unittest
from pathlib import Path

from analyzer.alert_manager import AlertManager, TriageStatus
from analyzer.detection_engine import DetectionEngine
from analyzer.pcap_parser import PCAPParser
from analyzer.traffic_analyzer import TrafficAnalyzer
from tests.generate_test_pcaps import generate_sample_pcap


class TestAlertManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap_path = Path("data/uploads/sample_capture.pcap")
        if not cls.pcap_path.exists():
            generate_sample_pcap(cls.pcap_path)

        parser = PCAPParser()
        cls.df = parser.parse(cls.pcap_path)
        analyzer = TrafficAnalyzer(cls.df)
        telemetry = analyzer.generate_full_telemetry()

        engine = DetectionEngine()
        cls.raw_alerts = engine.evaluate(cls.df, telemetry)

    def setUp(self):
        self.manager = AlertManager(self.raw_alerts)

    def test_initial_load_and_counts(self):
        all_alerts = self.manager.get_all_alerts()
        self.assertEqual(len(all_alerts), len(self.raw_alerts))

        sev_counts = self.manager.get_severity_counts()
        self.assertEqual(sev_counts["High"], 2)
        self.assertEqual(sev_counts["Medium"], 1)
        self.assertEqual(sev_counts["Low"], 2)

        stat_counts = self.manager.get_status_counts()
        self.assertEqual(stat_counts[TriageStatus.NEW.value], len(all_alerts))

    def test_alert_ordering(self):
        alerts = self.manager.get_all_alerts()
        severities = [a["severity"] for a in alerts]
        # High must precede Medium and Low
        self.assertEqual(severities[0], "High")
        self.assertEqual(severities[1], "High")
        self.assertEqual(severities[2], "Medium")

    def test_update_triage_status(self):
        alerts = self.manager.get_all_alerts()
        first_id = alerts[0]["alert_id"]

        success = self.manager.update_triage_status(
            first_id,
            TriageStatus.UNDER_INVESTIGATION,
            analyst_notes="Identified external scanning IP. Correlating with firewall logs.",
            assigned_to="SOC-Analyst-1",
        )
        self.assertTrue(success)

        updated = self.manager.get_alert_by_id(first_id)
        self.assertEqual(updated["status"], TriageStatus.UNDER_INVESTIGATION.value)
        self.assertEqual(updated["assigned_to"], "SOC-Analyst-1")
        self.assertIn("Correlating with firewall", updated["analyst_notes"])

    def test_filter_by_severity(self):
        high_alerts = self.manager.filter_alerts(severities=["High"])
        self.assertEqual(len(high_alerts), 2)
        for a in high_alerts:
            self.assertEqual(a["severity"], "High")

    def test_filter_by_category(self):
        recon_alerts = self.manager.filter_alerts(categories=["Reconnaissance"])
        self.assertEqual(len(recon_alerts), 1)
        self.assertEqual(recon_alerts[0]["rule_id"], "PS-SCAN-001")

    def test_filter_by_ip(self):
        alerts_99 = self.manager.filter_alerts(ip_address="10.0.0.99")
        self.assertGreater(len(alerts_99), 0)
        for a in alerts_99:
            self.assertTrue(a["src_ip"] == "10.0.0.99" or a["dst_ip"] == "10.0.0.99")

    def test_filter_by_search_query(self):
        # Search by domain substring
        dns_results = self.manager.filter_alerts(search_query="c2-command")
        self.assertEqual(len(dns_results), 1)
        self.assertEqual(dns_results[0]["rule_id"], "PS-DNS-003")

        # Search by specific targeted service name in evidence
        smb_results = self.manager.filter_alerts(search_query="Microsoft-DS")
        self.assertEqual(len(smb_results), 1)
        self.assertEqual(smb_results[0]["rule_id"], "PS-CONN-002")

        # Search by port number in evidence matches both scanning and brute force alerts
        port_results = self.manager.filter_alerts(search_query="445")
        self.assertEqual(len(port_results), 2)

    def test_top_flagged_ips(self):
        top_ips = self.manager.get_top_flagged_ips(limit=3)
        self.assertTrue(len(top_ips) > 0)
        self.assertEqual(top_ips[0]["ip"], "10.0.0.99")
        self.assertGreaterEqual(top_ips[0]["alert_count"], 2)

    def test_to_dataframe_and_exports(self):
        df = self.manager.to_dataframe()
        self.assertEqual(len(df), len(self.raw_alerts))
        self.assertIn("alert_id", df.columns)
        self.assertIn("severity", df.columns)
        self.assertIn("status", df.columns)

        with tempfile.TemporaryDirectory() as td:
            csv_path = Path(td) / "alerts.csv"
            json_path = Path(td) / "alerts.json"

            self.manager.export_to_csv(csv_path)
            self.manager.export_to_json(json_path)

            self.assertTrue(csv_path.exists())
            self.assertTrue(json_path.exists())
            self.assertGreater(csv_path.stat().st_size, 0)
            self.assertGreater(json_path.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
