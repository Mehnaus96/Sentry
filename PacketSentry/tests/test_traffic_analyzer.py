"""
Unit & Integration Tests for PacketSentry Traffic Analytics Module.
"""

import unittest
from pathlib import Path
import pandas as pd

from analyzer.pcap_parser import PCAPParser
from analyzer.traffic_analyzer import TrafficAnalyzer, get_service_name
from tests.generate_test_pcaps import generate_sample_pcap


class TestTrafficAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pcap_path = Path("data/uploads/sample_capture.pcap")
        if not cls.pcap_path.exists():
            generate_sample_pcap(cls.pcap_path)

        parser = PCAPParser()
        cls.df = parser.parse(cls.pcap_path)
        cls.analyzer = TrafficAnalyzer(cls.df)

    def test_get_service_name(self):
        self.assertEqual(get_service_name(80), "HTTP")
        self.assertEqual(get_service_name(443), "HTTPS")
        self.assertEqual(get_service_name(53), "DNS")
        self.assertEqual(get_service_name(445), "Microsoft-DS (SMB)")
        self.assertEqual(get_service_name(50000), "Dynamic/Private")

    def test_empty_dataframe(self):
        empty_analyzer = TrafficAnalyzer(pd.DataFrame())
        summary = empty_analyzer.compute_summary_statistics()
        self.assertEqual(summary["total_packets"], 0)
        self.assertEqual(summary["total_bytes"], 0)
        self.assertEqual(empty_analyzer.compute_protocol_distribution(), [])
        self.assertEqual(empty_analyzer.compute_top_source_ips(), [])
        self.assertEqual(empty_analyzer.compute_top_destination_ports(), [])
        self.assertEqual(empty_analyzer.compute_traffic_timeline(), [])

    def test_summary_statistics(self):
        summary = self.analyzer.compute_summary_statistics()
        self.assertGreater(summary["total_packets"], 0)
        self.assertGreater(summary["total_bytes"], 0)
        self.assertGreater(summary["unique_source_ips"], 0)
        self.assertGreater(summary["unique_destination_ips"], 0)
        self.assertIsNotNone(summary["start_time"])
        self.assertIsNotNone(summary["end_time"])

    def test_protocol_distribution(self):
        protos = self.analyzer.compute_protocol_distribution()
        self.assertTrue(len(protos) >= 2)
        proto_names = [p["protocol"] for p in protos]
        self.assertIn("TCP", proto_names)
        self.assertIn("DNS", proto_names)
        total_pct = sum(p["percentage"] for p in protos)
        self.assertAlmostEqual(total_pct, 100.0, delta=0.5)

    def test_top_source_ips(self):
        top_src = self.analyzer.compute_top_source_ips(limit=5)
        self.assertTrue(len(top_src) > 0)
        src_ips = [s["src_ip"] for s in top_src]
        # Attacker 10.0.0.99 probed 15 ports
        self.assertIn("10.0.0.99", src_ips)
        scanner = next(s for s in top_src if s["src_ip"] == "10.0.0.99")
        self.assertEqual(scanner["distinct_dst_ports"], 15)

    def test_top_destination_ports(self):
        ports = self.analyzer.compute_top_destination_ports(limit=10)
        self.assertTrue(len(ports) > 0)
        port_numbers = [p["port"] for p in ports]
        # 445 (repeated SYNs), 53 (DNS), 80 (HTTP)
        self.assertIn(445, port_numbers)
        smb_entry = next(p for p in ports if p["port"] == 445)
        self.assertEqual(smb_entry["service"], "Microsoft-DS (SMB)")

    def test_dns_statistics(self):
        dns_stats = self.analyzer.compute_dns_statistics()
        self.assertEqual(dns_stats["total_queries"], 2)
        self.assertEqual(dns_stats["unique_domains_count"], 2)
        top_domains = [d["domain"] for d in dns_stats["top_queried_domains"]]
        self.assertIn("google.com", top_domains)
        self.assertTrue(any("c2-command-and-control-server" in d for d in top_domains))

    def test_tcp_connection_statistics(self):
        tcp_stats = self.analyzer.compute_tcp_connection_statistics()
        self.assertGreater(tcp_stats["total_tcp_packets"], 0)
        self.assertGreater(tcp_stats["syn_count"], 0)
        self.assertGreater(tcp_stats["syn_to_synack_ratio"], 1.0)

    def test_traffic_timeline(self):
        timeline = self.analyzer.compute_traffic_timeline()
        self.assertTrue(len(timeline) > 0)
        for point in timeline:
            self.assertIn("time_bin", point)
            self.assertIn("packet_count", point)
            self.assertIn("byte_count", point)
            self.assertIn("time_label", point)

    def test_generate_full_telemetry(self):
        telemetry = self.analyzer.generate_full_telemetry()
        required_keys = [
            "summary",
            "protocol_distribution",
            "top_source_ips",
            "top_destination_ips",
            "top_destination_ports",
            "top_conversations",
            "dns_statistics",
            "tcp_statistics",
            "timeline",
        ]
        for k in required_keys:
            self.assertIn(k, telemetry)


if __name__ == "__main__":
    unittest.main()
