"""
PacketSentry Detection Rules & Configuration Module
Defines threat detection rules, MITRE ATT&CK mappings, and configurable threshold profiles.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AlertSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


@dataclass
class RuleDefinition:
    rule_id: str
    name: str
    category: str
    severity: AlertSeverity
    description: str
    mitre_attack: str
    recommended_steps: List[str]
    default_thresholds: Dict[str, Any] = field(default_factory=dict)


# Default Detection Rules Catalog
RULES_CATALOG: Dict[str, RuleDefinition] = {
    "PS-SCAN-001": RuleDefinition(
        rule_id="PS-SCAN-001",
        name="Potential Port Scanning / Host Reconnaissance",
        category="Reconnaissance",
        severity=AlertSeverity.HIGH,
        description="A source IP contacted an unusually high number of distinct destination ports on a single host or across the network within a short time window.",
        mitre_attack="T1046 - Network Service Discovery",
        recommended_steps=[
            "Identify the source host role (authorized vulnerability scanner vs. unauthorized endpoint).",
            "Review firewall and intrusion prevention system (IPS) logs for blocked attempts from the source IP.",
            "Inspect victim host logs to confirm whether any probed ports accepted connections or responded with SYN-ACK.",
            "If unauthorized, isolate the source host from the network and initiate endpoint forensics.",
        ],
        default_thresholds={
            "distinct_ports_threshold": 10,
            "window_seconds": 60.0,
        },
    ),
    "PS-CONN-002": RuleDefinition(
        rule_id="PS-CONN-002",
        name="Repeated Unsuccessful Connection Attempts",
        category="Lateral Movement / DoS",
        severity=AlertSeverity.MEDIUM,
        description="A source host initiated repeated TCP SYN attempts without completing handshakes or received an excessive ratio of TCP RST responses.",
        mitre_attack="T1110 - Brute Force / T1498 - Network Denial of Service",
        recommended_steps=[
            "Determine if the targeted port hosts a known service (e.g., SMB 445, RDP 3389, SSH 22).",
            "Correlate with endpoint authentication logs for failed login attempts or service crashes.",
            "Check for misconfigured internal applications or automated synchronization scripts.",
            "Block source IP at perimeter/internal firewall if brute-force attack or SYN flood is verified.",
        ],
        default_thresholds={
            "syn_without_ack_threshold": 8,
            "rst_ratio_threshold": 0.40,
        },
    ),
    "PS-DNS-003": RuleDefinition(
        rule_id="PS-DNS-003",
        name="Suspicious DNS Query Anomalies (DGA / Tunneling)",
        category="Command and Control",
        severity=AlertSeverity.HIGH,
        description="Identified DNS requests featuring unusually long domain names, high entropy, or anomalous query volumes consistent with DNS tunneling or DGA malware.",
        mitre_attack="T1071.004 - Application Layer Protocol: DNS / T1568 - Dynamic Resolution",
        recommended_steps=[
            "Check queried domain against threat intelligence feeds (VirusTotal, AlienVault OTX, Quad9).",
            "Analyze subdomain structure for encoded data (Base64, hex-encoded exfiltration).",
            "Examine requesting endpoint for recently executed processes, PowerShell scripts, or scheduled tasks.",
            "Sinkhole or block the parent domain at enterprise DNS resolvers.",
        ],
        default_thresholds={
            "max_domain_length": 45,
            "high_query_frequency_threshold": 25,
        },
    ),
    "PS-VOL-004": RuleDefinition(
        rule_id="PS-VOL-004",
        name="Unusual Traffic Volume Spike",
        category="Exfiltration / Anomaly",
        severity=AlertSeverity.MEDIUM,
        description="A single host transmitted traffic significantly above typical baseline thresholds, representing potential data exfiltration or massive transfers.",
        mitre_attack="T1048 - Exfiltration Over Alternative Protocol",
        recommended_steps=[
            "Identify the destination IP and classify its ownership (cloud storage provider, foreign IP, internal server).",
            "Confirm whether this host has scheduled backup, replication, or software update activities.",
            "Inspect endpoint data loss prevention (DLP) logs to verify transferred file contents.",
            "Check if large transfers occurred outside of normal business operating hours.",
        ],
        default_thresholds={
            "volume_bytes_threshold": 5 * 1024 * 1024,  # 5 MB in capture
            "volume_percentage_threshold": 75.0,        # or 75% of total capture bytes
        },
    ),
    "PS-PROTO-005": RuleDefinition(
        rule_id="PS-PROTO-005",
        name="Suspicious Protocol / Port Behavior",
        category="Security Policy Violation",
        severity=AlertSeverity.LOW,
        description="Detected cleartext, deprecated, or high-risk protocol ports (e.g. Telnet, cleartext FTP, VNC, or known backdoor ports) active on the network.",
        mitre_attack="T1040 - Network Sniffing / T1571 - Non-Standard Port",
        recommended_steps=[
            "Verify whether the communication contains credentials or sensitive data in cleartext.",
            "Verify compliance with enterprise network security policies prohibiting cleartext administration.",
            "Recommend transitioning from legacy protocols to encrypted equivalents (e.g., Telnet -> SSH, FTP -> SFTP).",
            "Ensure access to administrative ports is restricted via network segmentation or VPN.",
        ],
        default_thresholds={
            "high_risk_ports": [21, 23, 69, 5900, 4444, 31337, 6667],
        },
    ),
}


def get_default_thresholds() -> Dict[str, Any]:
    """Returns a flat dictionary of configurable thresholds for detection tuning."""
    return {
        "port_scan_distinct_ports": 10,
        "port_scan_window_sec": 60.0,
        "syn_unanswered_count": 8,
        "dns_max_domain_length": 45,
        "dns_high_frequency_count": 25,
        "volume_spike_bytes": 5 * 1024 * 1024,  # 5 MB
        "volume_spike_pct": 75.0,
        "high_risk_ports": [21, 23, 69, 5900, 4444, 31337, 6667],
    }
