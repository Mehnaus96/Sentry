"""
Unit & Integration Tests for PacketSentry PCAP Extraction Module.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from analyzer.pcap_parser import (
    PCAPExtractionError,
    PCAPParser,
    PCAPValidationError,
    validate_pcap_file,
)
from tests.generate_test_pcaps import generate_sample_pcap


class TestPCAPParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="packetsentry_test_"))
        cls.valid_pcap = cls.temp_dir / "valid_sample.pcap"
        generate_sample_pcap(cls.valid_pcap)

    @classmethod
    def tearDownClass(cls):
        if cls.temp_dir.exists():
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_validation_nonexistent_file(self):
        with self.assertRaises(PCAPValidationError):
            validate_pcap_file(self.temp_dir / "does_not_exist.pcap")

    def test_validation_invalid_extension(self):
        bad_ext = self.temp_dir / "malicious.exe"
        bad_ext.write_bytes(b"MZ12345678")
        with self.assertRaises(PCAPValidationError) as ctx:
            validate_pcap_file(bad_ext)
        self.assertIn("Unsupported file extension", str(ctx.exception))

    def test_validation_empty_file(self):
        empty_file = self.temp_dir / "empty.pcap"
        empty_file.write_bytes(b"")
        with self.assertRaises(PCAPValidationError) as ctx:
            validate_pcap_file(empty_file)
        self.assertIn("empty", str(ctx.exception).lower())

    def test_validation_corrupt_magic_bytes(self):
        corrupt_file = self.temp_dir / "corrupt.pcap"
        corrupt_file.write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 40)
        with self.assertRaises(PCAPValidationError) as ctx:
            validate_pcap_file(corrupt_file)
        self.assertIn("Invalid file signature", str(ctx.exception))

    def test_validation_valid_file(self):
        meta = validate_pcap_file(self.valid_pcap)
        self.assertEqual(meta["format"], "pcap")
        self.assertEqual(meta["extension"], ".pcap")
        self.assertGreater(meta["file_size_bytes"], 0)

    def test_tshark_extraction_and_normalization(self):
        parser = PCAPParser()
        df = parser.parse(self.valid_pcap)

        self.assertFalse(df.empty, "DataFrame should contain parsed packet rows")
        expected_cols = [
            "frame_number",
            "timestamp_epoch",
            "length",
            "src_ip",
            "dst_ip",
            "protocol",
            "src_port",
            "dst_port",
            "tcp_syn",
            "tcp_ack",
            "dns_query_name",
            "connection_id",
        ]
        for col in expected_cols:
            self.assertIn(col, df.columns, f"DataFrame must contain column '{col}'")

        # Verify specific traffic patterns from sample capture
        # 1. Attacker 10.0.0.99
        self.assertIn("10.0.0.99", df["src_ip"].values)
        # 2. Scanned Victim 192.168.1.50
        self.assertIn("192.168.1.50", df["dst_ip"].values)
        # 3. DNS query captured
        dns_queries = df[df["dns_query_name"] != ""]["dns_query_name"].tolist()
        self.assertTrue(any("google.com" in q for q in dns_queries))
        self.assertTrue(any("c2-command-and-control-server" in q for q in dns_queries))

    def test_export_processed_data(self):
        parser = PCAPParser()
        df = parser.parse(self.valid_pcap)
        export_out = self.temp_dir / "processed"
        paths = parser.export_processed_data(df, export_out, "test_session")

        self.assertTrue(os.path.exists(paths["csv"]))
        self.assertTrue(os.path.exists(paths["json"]))
        self.assertGreater(os.path.getsize(paths["csv"]), 0)
        self.assertGreater(os.path.getsize(paths["json"]), 0)


if __name__ == "__main__":
    unittest.main()
