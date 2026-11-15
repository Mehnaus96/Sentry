"""
PacketSentry SOC Alert Management Module
Provides querying, filtering, state tracking (triage lifecycle), and SIEM export for security alerts.
"""

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import pandas as pd

from analyzer.rules import AlertSeverity


class TriageStatus(str, Enum):
    NEW = "New"
    UNDER_INVESTIGATION = "Under Investigation"
    ESCALATED = "Escalated"
    FALSE_POSITIVE = "False Positive"
    RESOLVED = "Resolved"


class AlertManager:
    """
    Manages the lifecycle, filtering, querying, and triage status of generated alerts.
    Provides structured data models for dashboard displays and SIEM ingestion.
    """

    def __init__(self, alerts: Optional[List[Dict[str, Any]]] = None):
        self._alerts: Dict[str, Dict[str, Any]] = {}
        if alerts:
            self.load_alerts(alerts)

    def load_alerts(self, alerts: List[Dict[str, Any]]) -> None:
        """Loads alert dictionaries into the management index with default triage state."""
        for alert in alerts:
            aid = alert.get("alert_id")
            if not aid:
                continue
            alert_copy = dict(alert)
            # Assign default triage state if not already set
            if "status" not in alert_copy:
                alert_copy["status"] = TriageStatus.NEW.value
            if "analyst_notes" not in alert_copy:
                alert_copy["analyst_notes"] = ""
            if "updated_at" not in alert_copy:
                alert_copy["updated_at"] = alert_copy.get("timestamp_start", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
            if "assigned_to" not in alert_copy:
                alert_copy["assigned_to"] = "Unassigned"

            self._alerts[aid] = alert_copy

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Returns all alerts ordered by severity and timestamp."""
        severity_rank = {
            AlertSeverity.CRITICAL.value: 0,
            AlertSeverity.HIGH.value: 1,
            AlertSeverity.MEDIUM.value: 2,
            AlertSeverity.LOW.value: 3,
            AlertSeverity.INFORMATIONAL.value: 4,
        }
        all_alerts = list(self._alerts.values())
        all_alerts.sort(key=lambda a: (severity_rank.get(a.get("severity"), 99), a.get("alert_id")))
        return all_alerts

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single alert record by its unique identifier."""
        return self._alerts.get(alert_id)

    def update_triage_status(
        self,
        alert_id: str,
        status: Union[TriageStatus, str],
        analyst_notes: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> bool:
        """
        Updates an alert's investigation lifecycle state, notes, and assignee.
        """
        if alert_id not in self._alerts:
            return False

        status_val = status.value if isinstance(status, TriageStatus) else str(status)
        self._alerts[alert_id]["status"] = status_val
        self._alerts[alert_id]["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if analyst_notes is not None:
            self._alerts[alert_id]["analyst_notes"] = analyst_notes
        if assigned_to is not None:
            self._alerts[alert_id]["assigned_to"] = assigned_to

        return True

    def filter_alerts(
        self,
        severities: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        statuses: Optional[List[str]] = None,
        search_query: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Filters the alerts collection based on multi-dimensional criteria.

        Args:
            severities: Filter by list of severity strings (e.g. ['High', 'Critical']).
            categories: Filter by detection categories.
            statuses: Filter by triage status.
            search_query: Substring match across rule name, reasoning, IPs, and evidence.
            ip_address: Exact match on source or destination IP.

        Returns:
            Filtered and sorted list of alerts.
        """
        filtered = self.get_all_alerts()

        if severities:
            sev_set = {s.lower() for s in severities}
            filtered = [a for a in filtered if str(a.get("severity", "")).lower() in sev_set]

        if categories:
            cat_set = {c.lower() for c in categories}
            filtered = [a for a in filtered if str(a.get("category", "")).lower() in cat_set]

        if statuses:
            stat_set = {s.lower() for s in statuses}
            filtered = [a for a in filtered if str(a.get("status", "")).lower() in stat_set]

        if ip_address:
            ip_clean = ip_address.strip()
            filtered = [
                a for a in filtered
                if a.get("src_ip") == ip_clean or a.get("dst_ip") == ip_clean
            ]

        if search_query:
            query = search_query.strip().lower()
            filtered = [
                a for a in filtered
                if query in str(a.get("alert_id", "")).lower()
                or query in str(a.get("rule_name", "")).lower()
                or query in str(a.get("rule_id", "")).lower()
                or query in str(a.get("src_ip", "")).lower()
                or query in str(a.get("dst_ip", "")).lower()
                or query in str(a.get("detection_reasoning", "")).lower()
                or query in str(a.get("evidence", "")).lower()
            ]

        return filtered

    def get_severity_counts(self) -> Dict[str, int]:
        """Returns frequency map of alerts grouped by severity."""
        counts = {
            AlertSeverity.CRITICAL.value: 0,
            AlertSeverity.HIGH.value: 0,
            AlertSeverity.MEDIUM.value: 0,
            AlertSeverity.LOW.value: 0,
            AlertSeverity.INFORMATIONAL.value: 0,
        }
        for a in self._alerts.values():
            sev = a.get("severity")
            if sev in counts:
                counts[sev] += 1
            else:
                counts[str(sev)] = counts.get(str(sev), 0) + 1
        return counts

    def get_category_counts(self) -> Dict[str, int]:
        """Returns frequency map of alerts grouped by attack category."""
        counts: Dict[str, int] = {}
        for a in self._alerts.values():
            cat = a.get("category", "Uncategorized")
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def get_status_counts(self) -> Dict[str, int]:
        """Returns frequency map of alerts by triage state."""
        counts: Dict[str, int] = {s.value: 0 for s in TriageStatus}
        for a in self._alerts.values():
            st = a.get("status", TriageStatus.NEW.value)
            counts[st] = counts.get(st, 0) + 1
        return counts

    def get_top_flagged_ips(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Returns the most frequently flagged source IP addresses."""
        ip_counts: Dict[str, Dict[str, Any]] = {}
        for a in self._alerts.values():
            src = a.get("src_ip")
            if not src:
                continue
            if src not in ip_counts:
                ip_counts[src] = {"ip": src, "alert_count": 0, "severities": []}
            ip_counts[src]["alert_count"] += 1
            ip_counts[src]["severities"].append(a.get("severity"))

        sorted_ips = sorted(ip_counts.values(), key=lambda x: x["alert_count"], reverse=True)
        return sorted_ips[:limit]

    def to_dataframe(self, alerts_list: Optional[List[Dict[str, Any]]] = None) -> pd.DataFrame:
        """Converts alerts into a clean summary DataFrame for tabular UI rendering."""
        alerts = alerts_list if alerts_list is not None else self.get_all_alerts()
        if not alerts:
            return pd.DataFrame(columns=[
                "alert_id", "severity", "status", "rule_id", "rule_name",
                "src_ip", "dst_ip", "category", "timestamp_start"
            ])

        records = []
        for a in alerts:
            records.append({
                "alert_id": a.get("alert_id"),
                "severity": a.get("severity"),
                "status": a.get("status", "New"),
                "rule_id": a.get("rule_id"),
                "rule_name": a.get("rule_name"),
                "src_ip": a.get("src_ip"),
                "dst_ip": a.get("dst_ip"),
                "category": a.get("category"),
                "timestamp": a.get("timestamp_start"),
                "mitre_attack": a.get("mitre_attack"),
            })
        return pd.DataFrame(records)

    def export_to_json(self, output_path: Union[str, Path]) -> str:
        """Persists full alert store to disk as JSON."""
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(self.get_all_alerts(), f, indent=2)
        return str(p.resolve())

    def export_to_csv(self, output_path: Union[str, Path]) -> str:
        """Exports tabular summary of alerts to CSV."""
        df = self.to_dataframe()
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(p, index=False)
        return str(p.resolve())
