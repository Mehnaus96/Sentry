"""
PacketSentry – Automated Network Traffic Analyzer & SOC Reporting System
Professional Streamlit SOC Analyst Web Interface
"""

import io
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from analyzer.alert_manager import AlertManager, TriageStatus
from analyzer.detection_engine import DetectionEngine
from analyzer.environment import validate_environment
from analyzer.pcap_parser import (
    PCAPExtractionError,
    PCAPParser,
    PCAPValidationError,
    validate_pcap_file,
)
from analyzer.rules import RULES_CATALOG, get_default_thresholds
from analyzer.traffic_analyzer import TrafficAnalyzer
from reporting.report_generator import SOCReportGenerator

# -----------------------------------------------------------------------------
# Streamlit Page Configuration & Design System
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="PacketSentry // SOC Traffic Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DARK_NAVY_CSS = """
<style>
    /* Dark Navy Cybersecurity SOC Theme */
    .stApp {
        background-color: #0b1120;
        color: #f1f5f9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Top Header & Metrics Styling */
    div[data-testid="stMetric"] {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 14px 18px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    div[data-testid="stMetricLabel"] {
        color: #94a3b8 !important;
        font-size: 0.85rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    div[data-testid="stMetricValue"] {
        color: #38bdf8 !important;
        font-weight: 700 !important;
        font-size: 1.8rem !important;
    }

    /* Sidebar Customization */
    section[data-testid="stSidebar"] {
        background-color: #0f172a;
        border-right: 1px solid #1e293b;
    }

    /* Cards & Containers */
    .soc-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 16px;
    }

    /* Severity Badges */
    .badge-critical {
        background-color: rgba(220, 38, 38, 0.2);
        color: #f87171;
        border: 1px solid #dc2626;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-high {
        background-color: rgba(234, 88, 12, 0.2);
        color: #fb923c;
        border: 1px solid #ea580c;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-medium {
        background-color: rgba(202, 138, 4, 0.2);
        color: #facc15;
        border: 1px solid #ca8a04;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-low {
        background-color: rgba(37, 99, 235, 0.2);
        color: #60a5fa;
        border: 1px solid #2563eb;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }
    .badge-info {
        background-color: rgba(100, 116, 139, 0.2);
        color: #94a3b8;
        border: 1px solid #64748b;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.75rem;
    }

    /* Buttons */
    .stButton>button {
        background-color: #2563eb;
        color: #ffffff;
        border: none;
        border-radius: 6px;
        font-weight: 600;
        transition: all 0.2s ease;
    }
    .stButton>button:hover {
        background-color: #1d4ed8;
        box-shadow: 0 0 10px rgba(37, 99, 235, 0.5);
    }
</style>
"""
st.markdown(DARK_NAVY_CSS, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Session State Initialization
# -----------------------------------------------------------------------------
def init_session_state():
    defaults = {
        "pcap_path": None,
        "pcap_name": None,
        "df_packets": pd.DataFrame(),
        "telemetry": {},
        "alerts": [],
        "alert_manager": AlertManager(),
        "thresholds": get_default_thresholds(),
        "report_pdf_path": None,
        "env_diagnostics": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


init_session_state()

# Cache environment diagnostics
if st.session_state.env_diagnostics is None:
    st.session_state.env_diagnostics = validate_environment()


# -----------------------------------------------------------------------------
# Core Pipeline Execution
# -----------------------------------------------------------------------------
def run_analysis_pipeline(filepath: Union[str, Path]):
    """Runs extraction, traffic analytics, and rule-based detection."""
    p = Path(filepath)
    parser = PCAPParser()

    with st.spinner("Extracting packet telemetry with TShark..."):
        df = parser.parse(p)

    with st.spinner("Computing statistical aggregations & flow metrics..."):
        analyzer = TrafficAnalyzer(df)
        telemetry = analyzer.generate_full_telemetry()

    with st.spinner("Evaluating SOC detection rules against telemetry..."):
        engine = DetectionEngine(thresholds=st.session_state.thresholds)
        alerts = engine.evaluate(df, telemetry)

    # Persist intermediate outputs
    base_name = p.stem
    parser.export_processed_data(df, "data/processed", base_name)
    engine.export_alerts_json(alerts, f"data/processed/{base_name}_alerts.json")

    # Update session state
    st.session_state.pcap_path = str(p.resolve())
    st.session_state.pcap_name = p.name
    st.session_state.df_packets = df
    st.session_state.telemetry = telemetry
    st.session_state.alerts = alerts
    st.session_state.alert_manager = AlertManager(alerts)
    st.session_state.report_pdf_path = None


# -----------------------------------------------------------------------------
# Sidebar Navigation & System Health
# -----------------------------------------------------------------------------
st.sidebar.markdown(
    """
    <div style="padding: 10px 0;">
        <h2 style="color: #38bdf8; margin: 0; font-size: 1.4rem; font-weight: 800; letter-spacing: -0.02em;">
            🛡️ PacketSentry
        </h2>
        <div style="color: #94a3b8; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase;">
            SOC Traffic Analyzer & Reporting
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Operational Status Badge
env_ok = st.session_state.env_diagnostics.get("status") == "READY"
status_color = "#22c55e" if env_ok else "#ef4444"
status_text = "ENGINE ONLINE" if env_ok else "DEGRADED (TSHARK MISSING)"

st.sidebar.markdown(
    f"""
    <div style="background-color: #1e293b; border-left: 3px solid {status_color}; padding: 8px 12px; border-radius: 4px; margin-bottom: 16px;">
        <div style="font-size: 0.75rem; color: #94a3b8;">SYSTEM STATUS</div>
        <div style="font-size: 0.85rem; font-weight: 700; color: {status_color};">{status_text}</div>
    </div>
    """,
    unsafe_allow_html=True,
)

nav_page = st.sidebar.radio(
    "NAVIGATION",
    [
        "📊 Dashboard",
        "🔍 PCAP Analyzer",
        "🚨 Security Alerts",
        "📑 Investigation Reports",
        "🛡️ Detection Rules",
        "⚙️ Settings & Thresholds",
    ],
    index=0,
)

st.sidebar.markdown("---")
if st.session_state.pcap_name:
    st.sidebar.markdown(
        f"""
        <div style="background-color: #1e293b; padding: 10px; border-radius: 6px; border: 1px solid #334155;">
            <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Active Session</div>
            <div style="font-size: 0.85rem; font-weight: 700; color: #38bdf8; word-break: break-all;">{st.session_state.pcap_name}</div>
            <div style="font-size: 0.75rem; color: #cbd5e1; margin-top: 4px;">{len(st.session_state.df_packets):,} Packets | {len(st.session_state.alerts)} Alerts</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    st.sidebar.info("Awaiting PCAP upload or sample load.")


# -----------------------------------------------------------------------------
# Module View 1: 📊 Main Dashboard
# -----------------------------------------------------------------------------
if nav_page == "📊 Dashboard":
    st.markdown("## 📊 Security Operations Center — Executive Overview")
    st.caption("Real-time network telemetry, risk posture, and automated threat detections.")

    if st.session_state.df_packets.empty:
        st.info("💡 No network traffic loaded. Select a capture from `data/uploads/` below or upload a file in the **PCAP Analyzer**.")
        upload_dir = Path("data/uploads")
        available_files = [f.name for f in upload_dir.glob("*") if f.suffix.lower() in [".pcap", ".pcapng", ".cap"]]
        if available_files:
            col_sel, col_btn = st.columns([2, 1])
            with col_sel:
                selected_cap = st.selectbox("Available captures in data/uploads/:", options=available_files, key="dash_cap_sel")
            with col_btn:
                st.markdown("<br/>", unsafe_allow_html=True)
                if st.button("🚀 Analyze Selected Capture", type="primary", use_container_width=True):
                    run_analysis_pipeline(upload_dir / selected_cap)
                    st.rerun()
    else:
        summary = st.session_state.telemetry.get("summary", {})
        alerts = st.session_state.alerts
        sev_counts = st.session_state.alert_manager.get_severity_counts()

        # KPI Row
        kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
        kpi1.metric("Total Packets", f"{summary.get('total_packets', 0):,}")
        kpi2.metric("Traffic Volume", f"{summary.get('total_mb', 0)} MB")
        kpi3.metric("Unique Hosts", f"{summary.get('unique_total_ips', 0)}")
        kpi4.metric("High/Crit Alerts", f"{sev_counts['Critical'] + sev_counts['High']}")
        kpi5.metric("Capture Duration", f"{summary.get('duration_seconds', 0)}s")

        st.markdown("<br/>", unsafe_allow_html=True)

        # Charts Row 1: Protocol Distribution & Alerts by Severity
        col_c1, col_c2 = st.columns([1, 1])

        with col_c1:
            st.markdown("#### 🌐 Protocol Distribution")
            proto_dist = st.session_state.telemetry.get("protocol_distribution", [])
            if proto_dist:
                df_proto = pd.DataFrame(proto_dist)
                fig_proto = px.pie(
                    df_proto,
                    names="protocol",
                    values="packet_count",
                    hole=0.45,
                    color_discrete_sequence=["#38bdf8", "#3b82f6", "#6366f1", "#a855f7", "#ec4899"],
                )
                fig_proto.update_layout(
                    paper_bgcolor="#1e293b",
                    plot_bgcolor="#1e293b",
                    font_color="#f1f5f9",
                    margin=dict(t=20, b=20, l=20, r=20),
                    showlegend=True,
                )
                st.plotly_chart(fig_proto, use_container_width=True)

        with col_c2:
            st.markdown("#### 🚨 Security Alerts by Severity")
            df_sev = pd.DataFrame([
                {"Severity": k, "Count": v}
                for k, v in sev_counts.items()
                if v > 0
            ])
            if not df_sev.empty:
                color_map = {
                    "Critical": "#dc2626",
                    "High": "#ea580c",
                    "Medium": "#ca8a04",
                    "Low": "#2563eb",
                    "Informational": "#64748b",
                }
                fig_sev = px.bar(
                    df_sev,
                    x="Severity",
                    y="Count",
                    color="Severity",
                    color_discrete_map=color_map,
                )
                fig_sev.update_layout(
                    paper_bgcolor="#1e293b",
                    plot_bgcolor="#1e293b",
                    font_color="#f1f5f9",
                    margin=dict(t=20, b=20, l=20, r=20),
                    xaxis=dict(gridcolor="#334155"),
                    yaxis=dict(gridcolor="#334155"),
                    showlegend=False,
                )
                st.plotly_chart(fig_sev, use_container_width=True)
            else:
                st.success("✅ Clean network capture. Zero alerts triggered.")

        # Charts Row 2: Traffic Volume Timeline & Top Talkers
        col_c3, col_c4 = st.columns([1, 1])

        with col_c3:
            st.markdown("#### 📈 Network Traffic Timeline")
            timeline = st.session_state.telemetry.get("timeline", [])
            if timeline:
                df_time = pd.DataFrame(timeline)
                fig_time = px.area(
                    df_time,
                    x="time_label",
                    y="packet_count",
                    labels={"time_label": "Time (UTC)", "packet_count": "Packets/sec"},
                    color_discrete_sequence=["#38bdf8"],
                )
                fig_time.update_layout(
                    paper_bgcolor="#1e293b",
                    plot_bgcolor="#1e293b",
                    font_color="#f1f5f9",
                    margin=dict(t=20, b=20, l=20, r=20),
                    xaxis=dict(gridcolor="#334155"),
                    yaxis=dict(gridcolor="#334155"),
                )
                st.plotly_chart(fig_time, use_container_width=True)

        with col_c4:
            st.markdown("#### 🎯 Top Destination Ports & Services")
            top_ports = st.session_state.telemetry.get("top_destination_ports", [])[:6]
            if top_ports:
                df_ports = pd.DataFrame(top_ports)
                df_ports["Port_Service"] = df_ports["port"].astype(str) + " (" + df_ports["service"] + ")"
                fig_ports = px.bar(
                    df_ports,
                    x="packet_count",
                    y="Port_Service",
                    orientation="h",
                    color_discrete_sequence=["#3b82f6"],
                    labels={"packet_count": "Packet Volume", "Port_Service": "Port (Service)"},
                )
                fig_ports.update_layout(
                    paper_bgcolor="#1e293b",
                    plot_bgcolor="#1e293b",
                    font_color="#f1f5f9",
                    margin=dict(t=20, b=20, l=20, r=20),
                    xaxis=dict(gridcolor="#334155"),
                    yaxis=dict(gridcolor="#334155", autorange="reversed"),
                )
                st.plotly_chart(fig_ports, use_container_width=True)

        # Recent Findings Table
        st.markdown("#### 🚨 Recent Security Detections")
        if alerts:
            df_recent = st.session_state.alert_manager.to_dataframe()
            st.dataframe(
                df_recent[["alert_id", "severity", "status", "rule_name", "src_ip", "dst_ip", "category", "timestamp"]],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No security alerts generated for this capture.")


# -----------------------------------------------------------------------------
# Module View 2: 🔍 PCAP Analyzer
# -----------------------------------------------------------------------------
elif nav_page == "🔍 PCAP Analyzer":
    st.markdown("## 🔍 PCAP Ingestion & Protocol Dissection")
    st.caption("Upload raw packet captures (.pcap, .pcapng) for automated extraction.")

    upload_col, action_col = st.columns([2, 1])

    with upload_col:
        uploaded_file = st.file_uploader(
            "Upload PCAP / PCAPNG File",
            type=["pcap", "pcapng", "cap"],
            help="Strict signature validation checks magic bytes before passing to local TShark.",
        )

    with action_col:
        st.markdown("<br/>", unsafe_allow_html=True)
        if uploaded_file is not None:
            if st.button("⚡ Process Uploaded File", type="primary", use_container_width=True):
                # Save upload to data/uploads
                save_dest = Path("data/uploads") / uploaded_file.name
                save_dest.parent.mkdir(parents=True, exist_ok=True)
                save_dest.write_bytes(uploaded_file.getbuffer())

                try:
                    run_analysis_pipeline(save_dest)
                    st.success(f"Successfully processed {uploaded_file.name}")
                    st.rerun()
                except (PCAPValidationError, PCAPExtractionError) as e:
                    st.error(f"Extraction Error: {str(e)}")
        else:
            upload_dir = Path("data/uploads")
            available_files = [f.name for f in upload_dir.glob("*") if f.suffix.lower() in [".pcap", ".pcapng", ".cap"]]
            if available_files:
                selected_sample = st.selectbox("Or Select Existing Capture:", options=available_files, key="analyzer_sample_sel")
                if st.button(f"⚡ Analyze {selected_sample}", use_container_width=True):
                    run_analysis_pipeline(upload_dir / selected_sample)
                    st.success(f"Analyzed {selected_sample}")
                    st.rerun()

    if not st.session_state.df_packets.empty:
        st.markdown("---")
        st.markdown("### 📋 Extracted Packet Telemetry Explorer")

        df = st.session_state.df_packets

        # Filters
        f1, f2, f3 = st.columns([1, 1, 2])
        with f1:
            proto_filter = st.multiselect(
                "Filter Protocol",
                options=sorted(df["protocol"].unique()),
                default=[],
            )
        with f2:
            all_ips = sorted(list(set(df["src_ip"][df["src_ip"] != ""]).union(set(df["dst_ip"][df["dst_ip"] != ""]))))
            ip_filter = st.selectbox("Filter IP Address", options=["All"] + all_ips)
        with f3:
            search_str = st.text_input("Global Packet Search (IP, Port, DNS, Frame)", "")

        filtered_df = df.copy()
        if proto_filter:
            filtered_df = filtered_df[filtered_df["protocol"].isin(proto_filter)]
        if ip_filter != "All":
            filtered_df = filtered_df[(filtered_df["src_ip"] == ip_filter) | (filtered_df["dst_ip"] == ip_filter)]
        if search_str:
            q = search_str.strip().lower()
            filtered_df = filtered_df[
                filtered_df["src_ip"].str.lower().str.contains(q)
                | filtered_df["dst_ip"].str.lower().str.contains(q)
                | filtered_df["protocol"].str.lower().str.contains(q)
                | filtered_df["dns_query_name"].str.lower().str.contains(q)
                | filtered_df["connection_id"].str.lower().str.contains(q)
            ]

        st.caption(f"Displaying {len(filtered_df):,} of {len(df):,} packets")

        display_cols = [
            "frame_number", "timestamp", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol", "length",
            "tcp_flags_hex", "dns_query_name", "connection_id"
        ]
        available_cols = [c for c in display_cols if c in filtered_df.columns]
        st.dataframe(filtered_df[available_cols].head(500), use_container_width=True, hide_index=True)

        # Download Buttons
        dl1, dl2 = st.columns(2)
        with dl1:
            csv_data = filtered_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export Filtered Packets (CSV)",
                data=csv_data,
                file_name=f"{st.session_state.pcap_name or 'packets'}_extracted.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with dl2:
            json_data = filtered_df.to_json(orient="records", indent=2).encode("utf-8")
            st.download_button(
                "📥 Export Filtered Packets (JSON)",
                data=json_data,
                file_name=f"{st.session_state.pcap_name or 'packets'}_extracted.json",
                mime="application/json",
                use_container_width=True,
            )


# -----------------------------------------------------------------------------
# Module View 3: 🚨 Security Alerts (SOC Triage Console)
# -----------------------------------------------------------------------------
elif nav_page == "🚨 Security Alerts":
    st.markdown("## 🚨 SOC Alert Management & Incident Triage")
    st.caption("Search, prioritize, investigate, and document security detections.")

    manager: AlertManager = st.session_state.alert_manager
    all_alerts = manager.get_all_alerts()

    if not all_alerts:
        st.info("No security alerts generated. Load a PCAP with active threats in **PCAP Analyzer**.")
    else:
        # Filter Bar
        f_col1, f_col2, f_col3, f_col4 = st.columns(4)
        with f_col1:
            sel_sev = st.multiselect("Severity", options=["Critical", "High", "Medium", "Low", "Informational"])
        with f_col2:
            sel_cat = st.multiselect("Threat Category", options=sorted(list(manager.get_category_counts().keys())))
        with f_col3:
            sel_stat = st.multiselect("Triage Status", options=[s.value for s in TriageStatus])
        with f_col4:
            search_query = st.text_input("Search Alert Payload", "")

        filtered_alerts = manager.filter_alerts(
            severities=sel_sev if sel_sev else None,
            categories=sel_cat if sel_cat else None,
            statuses=sel_stat if sel_stat else None,
            search_query=search_query if search_query else None,
        )

        st.caption(f"Showing {len(filtered_alerts)} of {len(all_alerts)} alerts")

        # Tabular View
        df_alerts = manager.to_dataframe(filtered_alerts)
        st.dataframe(
            df_alerts[["alert_id", "severity", "status", "rule_id", "rule_name", "src_ip", "dst_ip", "mitre_attack"]],
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("---")
        st.markdown("### 🔬 Alert Forensic Dossier & Triage Operations")

        for alert in filtered_alerts:
            aid = alert["alert_id"]
            sev = alert["severity"]
            sev_badge = f"<span class='badge-{sev.lower()}'>{sev.upper()}</span>"

            with st.expander(f"{aid} — {alert['rule_name']} ({alert['src_ip']} -> {alert['dst_ip']})", expanded=False):
                st.markdown(
                    f"""
                    <div style="margin-bottom: 12px;">
                        {sev_badge} &nbsp;&nbsp;
                        <b>Rule ID:</b> <code>{alert['rule_id']}</code> &nbsp;&nbsp;|&nbsp;&nbsp;
                        <b>MITRE ATT&CK:</b> <code>{alert.get('mitre_attack', 'N/A')}</code> &nbsp;&nbsp;|&nbsp;&nbsp;
                        <b>Status:</b> <b>{alert.get('status', 'New')}</b>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.markdown("##### 📌 Detection Reasoning & Hypothesis")
                st.markdown(f"> {alert['detection_reasoning']}")

                st.markdown("##### 🔎 Observed Forensic Evidence")
                ev_col1, ev_col2 = st.columns(2)
                with ev_col1:
                    st.json(alert["evidence"])
                with ev_col2:
                    st.markdown("##### 🛡️ Recommended Incident Response Playbook")
                    for step in alert.get("recommended_steps", []):
                        st.markdown(f"- [ ] {step}")

                st.markdown("##### ✍️ SOC Triage Action & Case Notes")
                t_col1, t_col2, t_col3 = st.columns([1, 1, 2])

                current_status = alert.get("status", TriageStatus.NEW.value)
                status_idx = [s.value for s in TriageStatus].index(current_status) if current_status in [s.value for s in TriageStatus] else 0

                with t_col1:
                    new_status = st.selectbox(
                        "Update Triage Status",
                        options=[s.value for s in TriageStatus],
                        index=status_idx,
                        key=f"status_sel_{aid}",
                    )
                with t_col2:
                    assignee = st.text_input("Assigned Analyst", value=alert.get("assigned_to", "Unassigned"), key=f"assign_{aid}")
                with t_col3:
                    notes = st.text_area("Analyst Investigation Notes", value=alert.get("analyst_notes", ""), key=f"notes_{aid}", height=68)

                if st.button("💾 Save Triage Update", key=f"btn_save_{aid}"):
                    manager.update_triage_status(aid, new_status, analyst_notes=notes, assigned_to=assignee)
                    st.success(f"Alert {aid} updated successfully.")
                    st.rerun()


# -----------------------------------------------------------------------------
# Module View 4: 📑 Investigation Reports
# -----------------------------------------------------------------------------
elif nav_page == "📑 Investigation Reports":
    st.markdown("## 📑 SOC Incident Investigation Reporting")
    st.caption("Generate publication-ready, evidence-backed PDF reports for compliance and leadership.")

    if st.session_state.df_packets.empty:
        st.info("No capture data available to report on. Analyze a PCAP file first.")
    else:
        col_r1, col_r2 = st.columns([1, 1])

        with col_r1:
            st.markdown("#### ⚙️ Report Parameters")
            analyst_input = st.text_input("Lead Investigating Analyst", value="SOC Analyst Lead")
            class_input = st.selectbox("Information Classification Banner", options=[
                "CONFIDENTIAL // TLP:AMBER",
                "RESTRICTED // SOC INTERNAL",
                "CONFIDENTIAL // TLP:RED",
                "PUBLIC RELEASE // UNCLASSIFIED",
            ])

            if st.button("📄 Generate PDF Investigation Report", type="primary", use_container_width=True):
                report_dir = Path("data/reports")
                report_dir.mkdir(parents=True, exist_ok=True)
                pdf_target = report_dir / f"investigation_report_{Path(st.session_state.pcap_path).stem}.pdf"

                generator = SOCReportGenerator(
                    pcap_path=st.session_state.pcap_path,
                    telemetry=st.session_state.telemetry,
                    alerts=st.session_state.alerts,
                    analyst_name=analyst_input,
                    classification=class_input,
                )
                generated_path = generator.generate(pdf_target)
                st.session_state.report_pdf_path = generated_path
                st.success(f"Report compiled successfully: {pdf_target.name}")

        with col_r2:
            st.markdown("#### 📥 Download Incident Report")
            if st.session_state.report_pdf_path and Path(st.session_state.report_pdf_path).exists():
                pdf_bytes = Path(st.session_state.report_pdf_path).read_bytes()
                st.markdown(
                    f"""
                    <div style="background-color: #1e293b; border: 1px solid #334155; padding: 14px; border-radius: 8px; margin-bottom: 12px;">
                        <div style="font-weight: 700; color: #38bdf8;">{Path(st.session_state.report_pdf_path).name}</div>
                        <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">
                            Size: {len(pdf_bytes):,} bytes | Format: Adobe PDF
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.download_button(
                    label="⬇️ Download PDF Investigation Report",
                    data=pdf_bytes,
                    file_name=Path(st.session_state.report_pdf_path).name,
                    mime="application/pdf",
                    use_container_width=True,
                )
            else:
                st.info("Click 'Generate PDF Investigation Report' to build document.")


# -----------------------------------------------------------------------------
# Module View 5: 🛡️ Detection Rules Catalog
# -----------------------------------------------------------------------------
elif nav_page == "🛡️ Detection Rules":
    st.markdown("## 🛡️ PacketSentry Detection Rules Catalog")
    st.caption("Transparent, rule-based behavioral detection rules mapped to MITRE ATT&CK.")

    for rid, rule in RULES_CATALOG.items():
        with st.expander(f"{rule.rule_id} — {rule.name} [{rule.severity.value.upper()}]", expanded=True):
            st.markdown(
                f"""
                <div style="margin-bottom: 8px;">
                    <b>Threat Category:</b> <code>{rule.category}</code> &nbsp;&nbsp;|&nbsp;&nbsp;
                    <b>MITRE ATT&CK:</b> <code>{rule.mitre_attack}</code> &nbsp;&nbsp;|&nbsp;&nbsp;
                    <b>Base Severity:</b> <b>{rule.severity.value}</b>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(f"**Description:** {rule.description}")
            st.markdown("**Configurable Default Thresholds:**")
            st.json(rule.default_thresholds)
            st.markdown("**Incident Response Checklist:**")
            for step in rule.recommended_steps:
                st.markdown(f"- {step}")


# -----------------------------------------------------------------------------
# Module View 6: ⚙️ Settings & Thresholds
# -----------------------------------------------------------------------------
elif nav_page == "⚙️ Settings & Thresholds":
    st.markdown("## ⚙️ Detection Thresholds & System Diagnostics")
    st.caption("Tune detection sensitivity to your network environment and verify local dependencies.")

    t_col1, t_col2 = st.columns(2)

    with t_col1:
        st.markdown("#### 🎛️ Configurable Detection Thresholds")
        curr = st.session_state.thresholds

        p_scan = st.slider("Port Scan: Distinct Ports Threshold", 3, 50, int(curr["port_scan_distinct_ports"]))
        syn_thresh = st.slider("Repeated SYN: Unanswered Count Threshold", 3, 30, int(curr["syn_unanswered_count"]))
        dns_len = st.slider("DNS Anomaly: Maximum Domain Length (Chars)", 25, 120, int(curr["dns_max_domain_length"]))
        dns_freq = st.slider("DNS Anomaly: High Frequency Request Count", 10, 100, int(curr["dns_high_frequency_count"]))
        vol_mb = st.slider("Volume Spike: Host Threshold (MB)", 1.0, 50.0, float(curr["volume_spike_bytes"] / (1024 * 1024)))

        if st.button("💾 Apply Thresholds & Re-evaluate Detections", type="primary", use_container_width=True):
            st.session_state.thresholds["port_scan_distinct_ports"] = p_scan
            st.session_state.thresholds["syn_unanswered_count"] = syn_thresh
            st.session_state.thresholds["dns_max_domain_length"] = dns_len
            st.session_state.thresholds["dns_high_frequency_count"] = dns_freq
            st.session_state.thresholds["volume_spike_bytes"] = int(vol_mb * 1024 * 1024)

            # Re-evaluate if capture loaded
            if not st.session_state.df_packets.empty:
                engine = DetectionEngine(thresholds=st.session_state.thresholds)
                alerts = engine.evaluate(st.session_state.df_packets, st.session_state.telemetry)
                st.session_state.alerts = alerts
                st.session_state.alert_manager = AlertManager(alerts)
                st.success("Thresholds applied and alerts re-evaluated!")
                st.rerun()
            else:
                st.success("Thresholds updated successfully.")

    with t_col2:
        st.markdown("#### 🩺 Environment Diagnostics")
        diag = st.session_state.env_diagnostics
        st.json(diag)
