"""
PacketSentry Detection Engine Module
Evaluates network telemetry against configurable rules to generate evidence-backed SOC alerts.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import pandas as pd

from analyzer.rules import RULES_CATALOG, AlertSeverity, get_default_thresholds
from analyzer.traffic_analyzer import TrafficAnalyzer, get_service_name


class DetectionAlert:
    """Represents a structured, auditable security finding."""

    def __init__(
        self,
        alert_id: str,
        rule_id: str,
        rule_name: str,
        category: str,
        severity: AlertSeverity,
        src_ip: str,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        timestamp_start: Optional[str] = None,
        timestamp_end: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        detection_reasoning: str = "",
        recommended_steps: Optional[List[str]] = None,
        mitre_attack: str = "",
    ):
        self.alert_id = alert_id
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.category = category
        self.severity = severity
        self.src_ip = src_ip
        self.dst_ip = dst_ip or "N/A"
        self.dst_port = dst_port
        self.timestamp_start = timestamp_start or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.timestamp_end = timestamp_end or self.timestamp_start
        self.evidence = evidence or {}
        self.detection_reasoning = detection_reasoning
        self.recommended_steps = recommended_steps or []
        self.mitre_attack = mitre_attack

    def to_dict(self) -> Dict[str, Any]:
        """Converts alert to a serializable dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity.value if isinstance(self.severity, AlertSeverity) else str(self.severity),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": self.timestamp_end,
            "evidence": self.evidence,
            "detection_reasoning": self.detection_reasoning,
            "recommended_steps": self.recommended_steps,
            "mitre_attack": self.mitre_attack,
        }


class DetectionEngine:
    """
    Transparent rule-based detection engine with configurable thresholds.
    Evaluates packet capture DataFrames and extracts evidence-backed alerts.
    """

    def __init__(self, thresholds: Optional[Dict[str, Any]] = None):
        self.thresholds = get_default_thresholds()
        if thresholds:
            self.thresholds.update(thresholds)
        self.alert_counter = 1

    def _next_alert_id(self) -> str:
        aid = f"ALT-{self.alert_counter:04d}"
        self.alert_counter += 1
        return aid

    def evaluate(
        self, df: pd.DataFrame, telemetry: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Executes all active detection rules across the parsed packet dataset.

        Args:
            df: Normalized pandas DataFrame of extracted packets.
            telemetry: Optional precomputed TrafficAnalyzer telemetry.

        Returns:
            List of structured alert dictionaries sorted by severity.
        """
        if df.empty:
            return []

        self.alert_counter = 1
        alerts: List[DetectionAlert] = []

        # Execute rule pipelines
        alerts.extend(self._detect_port_scanning(df))
        alerts.extend(self._detect_repeated_syn(df))
        alerts.extend(self._detect_dns_anomalies(df))
        alerts.extend(self._detect_unusual_traffic_volume(df, telemetry))
        alerts.extend(self._detect_suspicious_protocols(df))

        # Sort alerts: Critical -> High -> Medium -> Low -> Informational
        severity_rank = {
            AlertSeverity.CRITICAL.value: 0,
            AlertSeverity.HIGH.value: 1,
            AlertSeverity.MEDIUM.value: 2,
            AlertSeverity.LOW.value: 3,
            AlertSeverity.INFORMATIONAL.value: 4,
        }

        alerts_dicts = [a.to_dict() for a in alerts]
        alerts_dicts.sort(key=lambda a: severity_rank.get(a["severity"], 99))
        return alerts_dicts

    def _detect_port_scanning(self, df: pd.DataFrame) -> List[DetectionAlert]:
        """
        Rule PS-SCAN-001: Potential Port Scanning
        Identifies source IPs contacting an unusually high number of distinct ports.
        """
        alerts = []
        rule_meta = RULES_CATALOG["PS-SCAN-001"]
        threshold = int(self.thresholds.get("port_scan_distinct_ports", 10))

        valid_tcp = df[(df["src_ip"] != "") & (df["dst_port"].notna()) & (df["protocol"] == "TCP")]
        if valid_tcp.empty:
            return alerts

        # Group by (src_ip, dst_ip)
        grouped = valid_tcp.groupby(["src_ip", "dst_ip"]).agg(
            distinct_ports=("dst_port", lambda p: sorted([int(x) for x in p.dropna().unique()])),
            total_probes=("length", "count"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            frame_sample=("frame_number", lambda f: [int(x) for x in f.head(5)]),
        ).reset_index()

        for _, row in grouped.iterrows():
            ports = row["distinct_ports"]
            if len(ports) >= threshold:
                evidence = {
                    "distinct_ports_contacted": len(ports),
                    "probed_ports_list": ports[:30],  # cap display at 30 ports
                    "total_packets_sent": int(row["total_probes"]),
                    "sample_frame_numbers": row["frame_sample"],
                }
                reasoning = (
                    f"Host {row['src_ip']} contacted {len(ports)} distinct destination ports on "
                    f"target {row['dst_ip']} (Threshold: >= {threshold} ports). "
                    f"This broad multi-port probing pattern indicates automated network reconnaissance or port scanning."
                )

                alerts.append(
                    DetectionAlert(
                        alert_id=self._next_alert_id(),
                        rule_id=rule_meta.rule_id,
                        rule_name=rule_meta.name,
                        category=rule_meta.category,
                        severity=rule_meta.severity,
                        src_ip=row["src_ip"],
                        dst_ip=row["dst_ip"],
                        timestamp_start=row["first_seen"],
                        timestamp_end=row["last_seen"],
                        evidence=evidence,
                        detection_reasoning=reasoning,
                        recommended_steps=rule_meta.recommended_steps,
                        mitre_attack=rule_meta.mitre_attack,
                    )
                )

        return alerts

    def _detect_repeated_syn(self, df: pd.DataFrame) -> List[DetectionAlert]:
        """
        Rule PS-CONN-002: Repeated Unsuccessful Connection Attempts
        Identifies excessive TCP SYN packets without completed handshakes.
        """
        alerts = []
        rule_meta = RULES_CATALOG["PS-CONN-002"]
        threshold = int(self.thresholds.get("syn_unanswered_count", 8))

        # Filter pure SYN packets (SYN=True, ACK=False)
        syn_packets = df[(df["protocol"] == "TCP") & (df["tcp_syn"] == True) & (df["tcp_ack"] == False)]
        if syn_packets.empty:
            return alerts

        grouped = syn_packets.groupby(["src_ip", "dst_ip", "dst_port"]).agg(
            syn_count=("frame_number", "count"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            sample_frames=("frame_number", lambda f: [int(x) for x in f.head(5)]),
        ).reset_index()

        for _, row in grouped.iterrows():
            if row["syn_count"] >= threshold:
                port = int(row["dst_port"]) if pd.notna(row["dst_port"]) else 0
                service = get_service_name(port)

                # Check if target host ever answered with SYN-ACK or ACK
                target_answers = df[
                    (df["src_ip"] == row["dst_ip"])
                    & (df["dst_ip"] == row["src_ip"])
                    & (df["src_port"] == port)
                    & (df["tcp_syn"] == True)
                    & (df["tcp_ack"] == True)
                ]
                completed_handshakes = len(target_answers)

                evidence = {
                    "unacknowledged_syn_count": int(row["syn_count"]),
                    "targeted_port": port,
                    "targeted_service": service,
                    "completed_handshakes_observed": completed_handshakes,
                    "sample_frame_numbers": row["sample_frames"],
                }
                reasoning = (
                    f"Host {row['src_ip']} initiated {row['syn_count']} unacknowledged TCP SYN connection attempts "
                    f"to {row['dst_ip']}:{port} ({service}) (Threshold: >= {threshold} attempts). "
                    f"Only {completed_handshakes} handshake completions observed, suggesting brute force, service denial, or filtered endpoint probing."
                )

                alerts.append(
                    DetectionAlert(
                        alert_id=self._next_alert_id(),
                        rule_id=rule_meta.rule_id,
                        rule_name=rule_meta.name,
                        category=rule_meta.category,
                        severity=rule_meta.severity,
                        src_ip=row["src_ip"],
                        dst_ip=row["dst_ip"],
                        dst_port=port,
                        timestamp_start=row["first_seen"],
                        timestamp_end=row["last_seen"],
                        evidence=evidence,
                        detection_reasoning=reasoning,
                        recommended_steps=rule_meta.recommended_steps,
                        mitre_attack=rule_meta.mitre_attack,
                    )
                )

        return alerts

    def _detect_dns_anomalies(self, df: pd.DataFrame) -> List[DetectionAlert]:
        """
        Rule PS-DNS-003: Suspicious DNS Query Anomalies
        Identifies unusually long domain queries or excessive query bursts.
        """
        alerts = []
        rule_meta = RULES_CATALOG["PS-DNS-003"]
        max_len = int(self.thresholds.get("dns_max_domain_length", 45))
        freq_thresh = int(self.thresholds.get("dns_high_frequency_count", 25))

        dns_queries = df[df["dns_query_name"] != ""]
        if dns_queries.empty:
            return alerts

        # Sub-check A: Abnormally long domain names (DNS Tunneling / Data Exfiltration / DGA)
        seen_domains = set()
        for _, row in dns_queries.iterrows():
            domain = str(row["dns_query_name"]).strip()
            if len(domain) >= max_len and domain not in seen_domains:
                seen_domains.add(domain)
                evidence = {
                    "queried_domain": domain,
                    "domain_length_chars": len(domain),
                    "length_threshold": max_len,
                    "frame_number": int(row["frame_number"]),
                    "resolved_response_ip": row.get("dns_response_ip", "None"),
                }
                reasoning = (
                    f"Host {row['src_ip']} submitted a DNS query for '{domain}' with character length "
                    f"{len(domain)} (Threshold: >= {max_len} chars). "
                    f"Abnormally long FQDNs frequently conceal encoded payload exfiltration, covert C2 channels, or algorithmic domain generation (DGA)."
                )

                alerts.append(
                    DetectionAlert(
                        alert_id=self._next_alert_id(),
                        rule_id=rule_meta.rule_id,
                        rule_name=rule_meta.name,
                        category=rule_meta.category,
                        severity=rule_meta.severity,
                        src_ip=row["src_ip"],
                        dst_ip=row.get("dst_ip", "DNS-Resolver"),
                        dst_port=53,
                        timestamp_start=row.get("timestamp"),
                        timestamp_end=row.get("timestamp"),
                        evidence=evidence,
                        detection_reasoning=reasoning,
                        recommended_steps=rule_meta.recommended_steps,
                        mitre_attack=rule_meta.mitre_attack,
                    )
                )

        # Sub-check B: Excessive DNS query frequency per source IP
        freq_grouped = dns_queries.groupby("src_ip").agg(
            total_queries=("frame_number", "count"),
            unique_domains=("dns_query_name", "nunique"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        ).reset_index()

        for _, row in freq_grouped.iterrows():
            if row["total_queries"] >= freq_thresh:
                evidence = {
                    "total_dns_queries": int(row["total_queries"]),
                    "unique_domains_queried": int(row["unique_domains"]),
                    "frequency_threshold": freq_thresh,
                }
                reasoning = (
                    f"Host {row['src_ip']} generated {row['total_queries']} DNS requests "
                    f"(Threshold: >= {freq_thresh}) querying {row['unique_domains']} distinct domains, "
                    f"indicating potential high-rate beaconing or scanning."
                )
                alerts.append(
                    DetectionAlert(
                        alert_id=self._next_alert_id(),
                        rule_id=rule_meta.rule_id,
                        rule_name="High-Frequency DNS Query Surge",
                        category=rule_meta.category,
                        severity=AlertSeverity.MEDIUM,
                        src_ip=row["src_ip"],
                        timestamp_start=row["first_seen"],
                        timestamp_end=row["last_seen"],
                        evidence=evidence,
                        detection_reasoning=reasoning,
                        recommended_steps=rule_meta.recommended_steps,
                        mitre_attack=rule_meta.mitre_attack,
                    )
                )

        return alerts

    def _detect_unusual_traffic_volume(
        self, df: pd.DataFrame, telemetry: Optional[Dict[str, Any]]
    ) -> List[DetectionAlert]:
        """
        Rule PS-VOL-004: Unusual Traffic Volume Spike
        Identifies single endpoints transmitting disproportionate byte volume.
        """
        alerts = []
        rule_meta = RULES_CATALOG["PS-VOL-004"]
        byte_threshold = int(self.thresholds.get("volume_spike_bytes", 5 * 1024 * 1024))
        pct_threshold = float(self.thresholds.get("volume_spike_pct", 75.0))

        total_capture_bytes = df["length"].sum()
        if total_capture_bytes == 0:
            return alerts

        valid_src = df[df["src_ip"] != ""]
        if valid_src.empty:
            return alerts

        grouped = valid_src.groupby("src_ip").agg(
            bytes_sent=("length", "sum"),
            packets_sent=("length", "count"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        ).reset_index()

        for _, row in grouped.iterrows():
            b_sent = row["bytes_sent"]
            pct = (b_sent / total_capture_bytes) * 100

            # Trigger if exceeds byte ceiling, or accounts for disproportionate traffic in captures >= 1MB
            if b_sent >= byte_threshold or (total_capture_bytes >= 1024 * 1024 and pct >= pct_threshold):
                evidence = {
                    "bytes_transmitted": int(b_sent),
                    "megabytes_transmitted": round(b_sent / (1024 * 1024), 2),
                    "percentage_of_total_traffic": round(pct, 1),
                    "total_packets": int(row["packets_sent"]),
                }
                reasoning = (
                    f"Host {row['src_ip']} generated {round(b_sent / (1024 * 1024), 2)} MB "
                    f"({round(pct, 1)}% of total capture traffic). "
                    f"Exceeds volume anomaly threshold ({round(byte_threshold / (1024 * 1024), 2)} MB / {pct_threshold}%)."
                )

                alerts.append(
                    DetectionAlert(
                        alert_id=self._next_alert_id(),
                        rule_id=rule_meta.rule_id,
                        rule_name=rule_meta.name,
                        category=rule_meta.category,
                        severity=rule_meta.severity,
                        src_ip=row["src_ip"],
                        timestamp_start=row["first_seen"],
                        timestamp_end=row["last_seen"],
                        evidence=evidence,
                        detection_reasoning=reasoning,
                        recommended_steps=rule_meta.recommended_steps,
                        mitre_attack=rule_meta.mitre_attack,
                    )
                )

        return alerts

    def _detect_suspicious_protocols(self, df: pd.DataFrame) -> List[DetectionAlert]:
        """
        Rule PS-PROTO-005: Suspicious Protocol / Port Behavior
        Identifies legacy cleartext, high-risk, or non-standard management ports.
        """
        alerts = []
        rule_meta = RULES_CATALOG["PS-PROTO-005"]
        high_risk_ports = self.thresholds.get("high_risk_ports", [21, 23, 69, 5900, 4444, 31337, 6667])

        valid_ports = df[df["dst_port"].isin(high_risk_ports)]
        if valid_ports.empty:
            return alerts

        grouped = valid_ports.groupby(["src_ip", "dst_ip", "dst_port", "protocol"]).agg(
            packet_count=("length", "count"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            sample_frames=("frame_number", lambda f: [int(x) for x in f.head(3)]),
        ).reset_index()

        for _, row in grouped.iterrows():
            port = int(row["dst_port"])
            service = get_service_name(port)
            evidence = {
                "targeted_port": port,
                "service_name": service,
                "packet_count": int(row["packet_count"]),
                "protocol": row["protocol"],
                "sample_frame_numbers": row["sample_frames"],
            }
            reasoning = (
                f"Communication observed between {row['src_ip']} and {row['dst_ip']} over "
                f"port {port} ({service}) using {row['protocol']}. "
                f"This port is classified as high-risk or legacy unencrypted management protocol."
            )

            alerts.append(
                DetectionAlert(
                    alert_id=self._next_alert_id(),
                    rule_id=rule_meta.rule_id,
                    rule_name=f"High-Risk / Cleartext Service Activity ({service})",
                    category=rule_meta.category,
                    severity=rule_meta.severity,
                    src_ip=row["src_ip"],
                    dst_ip=row["dst_ip"],
                    dst_port=port,
                    timestamp_start=row["first_seen"],
                    timestamp_end=row["last_seen"],
                    evidence=evidence,
                    detection_reasoning=reasoning,
                    recommended_steps=rule_meta.recommended_steps,
                    mitre_attack=rule_meta.mitre_attack,
                )
            )

        return alerts

    def export_alerts_json(
        self, alerts: List[Dict[str, Any]], output_path: Union[str, Path]
    ) -> str:
        """Serializes alert records to a formatted JSON file."""
        def json_default(obj):
            if hasattr(obj, "item"):
                return obj.item()
            return str(obj)

        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, default=json_default)
        return str(p.resolve())
