"""
PacketSentry Network Traffic Analytics Module
Computes statistical distributions, top talkers, flow metrics, and temporal telemetry.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "Microsoft-DS (SMB)",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy/Alt",
    8443: "HTTPS-Alt",
}


def get_service_name(port: Optional[Union[int, float]]) -> str:
    """Returns well-known service name for a given port, or 'Custom/Ephemeral'."""
    if port is None or pd.isna(port):
        return "Unknown"
    try:
        p = int(port)
        return WELL_KNOWN_PORTS.get(p, "Dynamic/Private" if p >= 49152 else f"Port-{p}")
    except (ValueError, TypeError):
        return "Unknown"


class TrafficAnalyzer:
    """
    Computes statistical summaries, protocol breakdowns, top communicating hosts,
    DNS telemetry, connection metrics, and time-series traffic distributions.
    """

    def __init__(self, df: pd.DataFrame):
        self.df = df.copy() if not df.empty else pd.DataFrame()
        self._ensure_columns()

    def _ensure_columns(self):
        """Ensures expected columns exist with valid types to prevent KeyErrors."""
        defaults = {
            "frame_number": 0,
            "timestamp_epoch": 0.0,
            "length": 0,
            "src_ip": "",
            "dst_ip": "",
            "src_port": np.nan,
            "dst_port": np.nan,
            "protocol": "UNKNOWN",
            "tcp_syn": False,
            "tcp_ack": False,
            "tcp_rst": False,
            "tcp_fin": False,
            "dns_query_name": "",
            "dns_is_response": False,
            "connection_id": "",
        }
        for col, default_val in defaults.items():
            if col not in self.df.columns:
                self.df[col] = default_val

    def compute_summary_statistics(self) -> Dict[str, Any]:
        """Calculates macro-level traffic statistics."""
        if self.df.empty:
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "total_mb": 0.0,
                "duration_seconds": 0.0,
                "avg_packet_size_bytes": 0.0,
                "avg_data_rate_kbps": 0.0,
                "unique_source_ips": 0,
                "unique_destination_ips": 0,
                "unique_total_ips": 0,
                "start_time": None,
                "end_time": None,
            }

        total_packets = len(self.df)
        total_bytes = int(self.df["length"].sum())
        total_mb = round(total_bytes / (1024 * 1024), 3)

        min_epoch = self.df["timestamp_epoch"].min()
        max_epoch = self.df["timestamp_epoch"].max()
        duration = round(max(0.0, float(max_epoch - min_epoch)), 3)

        avg_packet_size = round(total_bytes / total_packets, 1) if total_packets > 0 else 0.0
        avg_rate_kbps = round((total_bytes * 8) / (duration * 1000), 2) if duration > 0 else 0.0

        # Unique IPs
        src_ips = set(self.df["src_ip"][self.df["src_ip"] != ""])
        dst_ips = set(self.df["dst_ip"][self.df["dst_ip"] != ""])
        total_unique_ips = len(src_ips.union(dst_ips))

        start_time = datetime.fromtimestamp(min_epoch).strftime("%Y-%m-%d %H:%M:%S UTC") if min_epoch > 0 else None
        end_time = datetime.fromtimestamp(max_epoch).strftime("%Y-%m-%d %H:%M:%S UTC") if max_epoch > 0 else None

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_mb": total_mb,
            "duration_seconds": duration,
            "avg_packet_size_bytes": avg_packet_size,
            "avg_data_rate_kbps": avg_rate_kbps,
            "unique_source_ips": len(src_ips),
            "unique_destination_ips": len(dst_ips),
            "unique_total_ips": total_unique_ips,
            "start_time": start_time,
            "end_time": end_time,
        }

    def compute_protocol_distribution(self) -> List[Dict[str, Any]]:
        """Returns protocol distribution ranked by packet volume."""
        if self.df.empty:
            return []

        proto_grouped = self.df.groupby("protocol").agg(
            packet_count=("length", "count"),
            total_bytes=("length", "sum"),
        ).reset_index()

        total_pkts = len(self.df)
        proto_grouped["percentage"] = (proto_grouped["packet_count"] / total_pkts * 100).round(2)
        proto_grouped = proto_grouped.sort_values(by="packet_count", ascending=False)

        return proto_grouped.to_dict(orient="records")

    def compute_top_source_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Calculates top source IP addresses and their transmission profiles."""
        if self.df.empty:
            return []

        valid_src = self.df[self.df["src_ip"] != ""]
        if valid_src.empty:
            return []

        grouped = valid_src.groupby("src_ip").agg(
            packets_sent=("length", "count"),
            bytes_sent=("length", "sum"),
            distinct_dst_ips=("dst_ip", lambda s: s[s != ""].nunique()),
            distinct_dst_ports=("dst_port", lambda s: s.dropna().nunique()),
        ).reset_index()

        grouped = grouped.sort_values(by="packets_sent", ascending=False).head(limit)
        return grouped.to_dict(orient="records")

    def compute_top_destination_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Calculates top destination IP addresses and their inbound traffic."""
        if self.df.empty:
            return []

        valid_dst = self.df[self.df["dst_ip"] != ""]
        if valid_dst.empty:
            return []

        grouped = valid_dst.groupby("dst_ip").agg(
            packets_received=("length", "count"),
            bytes_received=("length", "sum"),
            distinct_src_ips=("src_ip", lambda s: s[s != ""].nunique()),
        ).reset_index()

        grouped = grouped.sort_values(by="packets_received", ascending=False).head(limit)
        return grouped.to_dict(orient="records")

    def compute_top_destination_ports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Calculates most targeted destination ports with service annotations."""
        if self.df.empty:
            return []

        valid_ports = self.df[self.df["dst_port"].notna()]
        if valid_ports.empty:
            return []

        grouped = valid_ports.groupby("dst_port").agg(
            packet_count=("length", "count"),
            total_bytes=("length", "sum"),
        ).reset_index()

        total_port_pkts = len(valid_ports)
        grouped["port"] = grouped["dst_port"].astype(int)
        grouped["service"] = grouped["port"].apply(get_service_name)
        grouped["percentage"] = (grouped["packet_count"] / total_port_pkts * 100).round(2)

        grouped = grouped.sort_values(by="packet_count", ascending=False).head(limit)
        return grouped[["port", "service", "packet_count", "percentage", "total_bytes"]].to_dict(orient="records")

    def compute_top_conversations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Computes top communicating bidirectional host pairs."""
        if self.df.empty:
            return []

        valid_ips = self.df[(self.df["src_ip"] != "") & (self.df["dst_ip"] != "")].copy()
        if valid_ips.empty:
            return []

        # Sort IP pairs so A-B and B-A are unified
        def sort_pair(row):
            return tuple(sorted([row["src_ip"], row["dst_ip"]]))

        valid_ips["pair"] = valid_ips.apply(sort_pair, axis=1)

        grouped = valid_ips.groupby("pair").agg(
            total_packets=("length", "count"),
            total_bytes=("length", "sum"),
            protocols=("protocol", lambda s: list(s.unique())),
        ).reset_index()

        grouped["host_a"] = grouped["pair"].apply(lambda p: p[0])
        grouped["host_b"] = grouped["pair"].apply(lambda p: p[1])
        grouped = grouped.sort_values(by="total_packets", ascending=False).head(limit)

        return grouped[["host_a", "host_b", "total_packets", "total_bytes", "protocols"]].to_dict(orient="records")

    def compute_dns_statistics(self, top_domains_limit: int = 10) -> Dict[str, Any]:
        """Analyzes DNS query frequency, domain lengths, and query types."""
        dns_packets = self.df[self.df["dns_query_name"] != ""]
        if dns_packets.empty:
            return {
                "total_queries": 0,
                "total_responses": int(self.df["dns_is_response"].sum()),
                "unique_domains_count": 0,
                "avg_query_length": 0.0,
                "top_queried_domains": [],
            }

        total_queries = len(dns_packets)
        total_responses = int(self.df["dns_is_response"].sum())
        unique_domains = dns_packets["dns_query_name"].nunique()

        # Domain frequency and lengths
        domain_summary = dns_packets.groupby("dns_query_name").agg(
            query_count=("frame_number", "count"),
            domain_length=("dns_query_name", lambda s: len(s.iloc[0])),
        ).reset_index()

        avg_len = round(float(domain_summary["domain_length"].mean()), 1)
        domain_summary = domain_summary.sort_values(by="query_count", ascending=False).head(top_domains_limit)

        return {
            "total_queries": total_queries,
            "total_responses": total_responses,
            "unique_domains_count": unique_domains,
            "avg_query_length": avg_len,
            "top_queried_domains": domain_summary.rename(columns={"dns_query_name": "domain"}).to_dict(orient="records"),
        }

    def compute_tcp_connection_statistics(self) -> Dict[str, Any]:
        """
        Analyzes TCP handshake and termination flags.
        High SYN without ACK or high RST indicates scanning or denial-of-service.
        """
        tcp_packets = self.df[self.df["protocol"] == "TCP"]
        if tcp_packets.empty:
            return {
                "total_tcp_packets": 0,
                "syn_count": 0,
                "syn_ack_count": 0,
                "ack_count": 0,
                "rst_count": 0,
                "fin_count": 0,
                "syn_to_synack_ratio": 0.0,
                "rst_percentage": 0.0,
            }

        total_tcp = len(tcp_packets)
        # SYN-only (connection requests): SYN is True and ACK is False
        syn_only = ((tcp_packets["tcp_syn"] == True) & (tcp_packets["tcp_ack"] == False)).sum()
        # SYN-ACK (handshake responses): SYN is True and ACK is True
        syn_ack = ((tcp_packets["tcp_syn"] == True) & (tcp_packets["tcp_ack"] == True)).sum()
        # Pure ACK: SYN is False and ACK is True
        ack_only = ((tcp_packets["tcp_syn"] == False) & (tcp_packets["tcp_ack"] == True)).sum()
        rst_count = (tcp_packets["tcp_rst"] == True).sum()
        fin_count = (tcp_packets["tcp_fin"] == True).sum()

        syn_synack_ratio = round(float(syn_only) / float(syn_ack), 2) if syn_ack > 0 else float(syn_only)
        rst_pct = round(float(rst_count) / float(total_tcp) * 100, 2) if total_tcp > 0 else 0.0

        return {
            "total_tcp_packets": total_tcp,
            "syn_count": int(syn_only),
            "syn_ack_count": int(syn_ack),
            "ack_count": int(ack_only),
            "rst_count": int(rst_count),
            "fin_count": int(fin_count),
            "syn_to_synack_ratio": syn_synack_ratio,
            "rst_percentage": rst_pct,
        }

    def compute_traffic_timeline(self, interval_sec: int = 1) -> List[Dict[str, Any]]:
        """
        Aggregates traffic volume into time-series buckets for visualization.
        """
        if self.df.empty or "timestamp_epoch" not in self.df.columns:
            return []

        min_time = self.df["timestamp_epoch"].min()
        max_time = self.df["timestamp_epoch"].max()
        if min_time <= 0 or max_time <= 0:
            return []

        span = max_time - min_time
        # Adjust bin size dynamically for very long captures
        if span > 3600:
            interval_sec = 60
        elif span > 600:
            interval_sec = 10
        elif span > 60:
            interval_sec = 2

        df_time = self.df.copy()
        df_time["time_bin"] = ((df_time["timestamp_epoch"] - min_time) // interval_sec) * interval_sec + min_time

        binned = df_time.groupby("time_bin").agg(
            packet_count=("length", "count"),
            byte_count=("length", "sum"),
        ).reset_index()

        binned["time_label"] = binned["time_bin"].apply(
            lambda t: datetime.fromtimestamp(t).strftime("%H:%M:%S")
        )

        return binned.to_dict(orient="records")

    def generate_full_telemetry(self) -> Dict[str, Any]:
        """
        Consolidates all statistical modules into a single telemetry payload.
        """
        return {
            "summary": self.compute_summary_statistics(),
            "protocol_distribution": self.compute_protocol_distribution(),
            "top_source_ips": self.compute_top_source_ips(),
            "top_destination_ips": self.compute_top_destination_ips(),
            "top_destination_ports": self.compute_top_destination_ports(),
            "top_conversations": self.compute_top_conversations(),
            "dns_statistics": self.compute_dns_statistics(),
            "tcp_statistics": self.compute_tcp_connection_statistics(),
            "timeline": self.compute_traffic_timeline(),
        }
