"""
Unit & Integration Tests for PacketSentry CLI / UiPath Automation Entrypoint.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from tests.generate_test_pcaps import generate_sample_pcap


class TestUiPathCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap_path = Path("data/uploads/sample_capture.pcap")
        if not cls.pcap_path.exists():
            generate_sample_pcap(cls.pcap_path)

    def test_cli_execution_with_threats(self):
        cmd = [
            sys.executable,
            "cli.py",
            "--pcap", str(self.pcap_path.resolve()),
            "--output-dir", "output/investigations",
            "--analyst", "Test UiPath Bot",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        # Exit code 10 denotes successful execution with High/Critical threats detected
        self.assertEqual(res.returncode, 10, f"Expected return code 10 for threat detection, got {res.returncode}. Stderr: {res.stderr}")
        self.assertIn("=== PACKETSENTRY_EXECUTION_RESULT_JSON ===", res.stdout)
        self.assertIn("high_or_critical_alerts_detected", res.stdout)

    def test_cli_validation_failure(self):
        cmd = [
            sys.executable,
            "cli.py",
            "--pcap", "data/uploads/non_existent_file.pcap",
            "--output-dir", "output/investigations",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(res.returncode, 1, "Non-existent file should exit with code 1 (validation failure)")


if __name__ == "__main__":
    unittest.main()
