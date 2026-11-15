"""
Unit & Integration Tests for PacketSentry PDF Investigation Reporting Module.
"""

import tempfile
import unittest
from pathlib import Path

from analyzer.detection_engine import DetectionEngine
from analyzer.pcap_parser import PCAPParser
from analyzer.traffic_analyzer import TrafficAnalyzer
from reporting.report_generator import SOCReportGenerator
from tests.generate_test_pcaps import generate_sample_pcap


class TestReportGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap_path = Path("data/uploads/sample_capture.pcap")
        if not cls.pcap_path.exists():
            generate_sample_pcap(cls.pcap_path)

        parser = PCAPParser()
        cls.df = parser.parse(cls.pcap_path)
        cls.analyzer = TrafficAnalyzer(cls.df)
        cls.telemetry = cls.analyzer.generate_full_telemetry()

        cls.engine = DetectionEngine()
        cls.alerts = cls.engine.evaluate(cls.df, cls.telemetry)

    def test_pdf_generation_with_alerts(self):
        with tempfile.TemporaryDirectory() as td:
            out_pdf = Path(td) / "investigation_report.pdf"
            generator = SOCReportGenerator(
                pcap_path=self.pcap_path,
                telemetry=self.telemetry,
                alerts=self.alerts,
                analyst_name="Intern Analyst John Doe",
            )
            report_path = generator.generate(out_pdf)

            self.assertTrue(Path(report_path).exists())
            file_size = Path(report_path).stat().st_size
            self.assertGreater(file_size, 5000, "Generated PDF should be at least 5 KB")

    def test_pdf_generation_clean_capture(self):
        with tempfile.TemporaryDirectory() as td:
            out_pdf = Path(td) / "clean_report.pdf"
            generator = SOCReportGenerator(
                pcap_path=self.pcap_path,
                telemetry=self.telemetry,
                alerts=[],  # Zero alerts
                analyst_name="Intern Analyst John Doe",
            )
            report_path = generator.generate(out_pdf)

            self.assertTrue(Path(report_path).exists())
            self.assertGreater(Path(report_path).stat().st_size, 3000)

    def test_cryptographic_hashes(self):
        generator = SOCReportGenerator(
            pcap_path=self.pcap_path,
            telemetry=self.telemetry,
            alerts=self.alerts,
        )
        hashes = generator._compute_hashes()
        self.assertEqual(len(hashes["sha256"]), 64)
        self.assertEqual(len(hashes["md5"]), 32)


if __name__ == "__main__":
    unittest.main()
