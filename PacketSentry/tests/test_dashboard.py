"""
Unit test verifying PacketSentry Streamlit dashboard components and pipeline integration.
"""

import unittest
from pathlib import Path

from analyzer.pcap_parser import PCAPParser
from analyzer.traffic_analyzer import TrafficAnalyzer
from analyzer.detection_engine import DetectionEngine
from analyzer.alert_manager import AlertManager
from reporting.report_generator import SOCReportGenerator
from tests.generate_test_pcaps import generate_sample_pcap


class TestDashboardPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap_path = Path("data/uploads/sample_capture.pcap")
        if not cls.pcap_path.exists():
            generate_sample_pcap(cls.pcap_path)

    def test_full_pipeline_execution(self):
        # 1. Parse
        parser = PCAPParser()
        df = parser.parse(self.pcap_path)
        self.assertFalse(df.empty)

        # 2. Telemetry
        analyzer = TrafficAnalyzer(df)
        telemetry = analyzer.generate_full_telemetry()
        self.assertIn("summary", telemetry)
        self.assertIn("protocol_distribution", telemetry)

        # 3. Detection
        engine = DetectionEngine()
        alerts = engine.evaluate(df, telemetry)
        self.assertGreater(len(alerts), 0)

        # 4. Alert Manager
        manager = AlertManager(alerts)
        self.assertEqual(len(manager.get_all_alerts()), len(alerts))

        # 5. Report Generator
        out_pdf = Path("data/reports/test_pipeline_report.pdf")
        generator = SOCReportGenerator(
            pcap_path=self.pcap_path,
            telemetry=telemetry,
            alerts=alerts,
        )
        report_path = generator.generate(out_pdf)
        self.assertTrue(Path(report_path).exists())
        self.assertGreater(Path(report_path).stat().st_size, 5000)


if __name__ == "__main__":
    unittest.main()
