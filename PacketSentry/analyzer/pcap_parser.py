"""
PacketSentry PCAP Extraction & Normalization Module
Extracts packet telemetry from PCAP/PCAPNG captures using local TShark binary.
"""

import io
import json
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

from analyzer.environment import find_tshark_binary

logger = logging.getLogger("PacketSentry.Parser")

# Known Magic Bytes for PCAP and PCAPNG
PCAP_MAGIC_BYTES = [
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (little-endian, usec)
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (big-endian, usec)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (little-endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap (big-endian)
]
PCAPNG_MAGIC_BYTE = b"\x0a\x0d\x0d\x0a"  # Section Header Block (SHB)

SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

TSHARK_FIELDS = [
    ("frame.number", "frame_number"),
    ("frame.time_epoch", "timestamp_epoch"),
    ("frame.time", "timestamp"),
    ("frame.len", "length"),
    ("ip.src", "ipv4_src"),
    ("ipv6.src", "ipv6_src"),
    ("ip.dst", "ipv4_dst"),
    ("ipv6.dst", "ipv6_dst"),
    ("_ws.col.Protocol", "protocol"),
    ("tcp.srcport", "tcp_srcport"),
    ("udp.srcport", "udp_srcport"),
    ("tcp.dstport", "tcp_dstport"),
    ("udp.dstport", "udp_dstport"),
    ("tcp.flags", "tcp_flags_hex"),
    ("tcp.flags.syn", "tcp_syn"),
    ("tcp.flags.ack", "tcp_ack"),
    ("tcp.flags.reset", "tcp_rst"),
    ("tcp.flags.fin", "tcp_fin"),
    ("dns.qry.name", "dns_query_name"),
    ("dns.qry.type", "dns_query_type"),
    ("dns.flags.response", "dns_is_response"),
    ("dns.a", "dns_response_ip"),
]


class PCAPValidationError(Exception):
    """Raised when uploaded file fails security, format, or size validation."""
    pass


class PCAPExtractionError(Exception):
    """Raised when TShark encounters extraction or corruption errors."""
    pass


def validate_pcap_file(filepath: Union[str, Path], max_size_mb: int = 150) -> Dict[str, Any]:
    """
    Validates file existence, extension, size limit, and header magic bytes.

    Args:
        filepath: Path to the capture file.
        max_size_mb: Maximum allowed file size in Megabytes.

    Returns:
        Metadata dictionary with file stats and detected format ('pcap' or 'pcapng').

    Raises:
        PCAPValidationError: If file does not exist, exceeds limit, or has invalid magic bytes.
    """
    path = Path(filepath)

    if not path.exists() or not path.is_file():
        raise PCAPValidationError(f"File not found or inaccessible: {filepath}")

    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise PCAPValidationError(
            f"Unsupported file extension '{ext}'. Accepted formats: {', '.join(SUPPORTED_EXTENSIONS)}"
        )

    file_size = path.stat().st_size
    if file_size == 0:
        raise PCAPValidationError("File is empty (0 bytes). Invalid packet capture.")

    max_bytes = max_size_mb * 1024 * 1024
    if file_size > max_bytes:
        raise PCAPValidationError(
            f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum allowed limit of {max_size_mb} MB."
        )

    # Inspect Magic Bytes
    try:
        with open(path, "rb") as f:
            header_bytes = f.read(4)
    except Exception as e:
        raise PCAPValidationError(f"Unable to read file headers: {str(e)}")

    detected_format = None
    if header_bytes in PCAP_MAGIC_BYTES:
        detected_format = "pcap"
    elif header_bytes == PCAPNG_MAGIC_BYTE:
        detected_format = "pcapng"
    else:
        raise PCAPValidationError(
            f"Invalid file signature (magic bytes {header_bytes.hex()}). "
            "File is not a valid PCAP or PCAPNG capture."
        )

    return {
        "filename": path.name,
        "filepath": str(path.resolve()),
        "file_size_bytes": file_size,
        "file_size_mb": round(file_size / (1024 * 1024), 3),
        "format": detected_format,
        "extension": ext,
    }


class PCAPParser:
    """
    Production-grade PCAP/PCAPNG parser wrapping local TShark binary.
    Extracts structured network telemetry with missing-field resilience.
    """

    def __init__(self, tshark_path: Optional[str] = None, timeout_sec: int = 120):
        self.tshark_path = tshark_path or find_tshark_binary()
        if not self.tshark_path:
            raise RuntimeError(
                "TShark binary could not be found. Please ensure Wireshark/TShark is installed."
            )
        self.timeout_sec = timeout_sec

    def parse(self, pcap_path: Union[str, Path], max_packets: Optional[int] = None) -> pd.DataFrame:
        """
        Executes TShark extraction and converts stdout to a normalized pandas DataFrame.

        Args:
            pcap_path: Target PCAP or PCAPNG path.
            max_packets: Optional cap on maximum packets to process.

        Returns:
            Normalized pandas DataFrame with uniform columns.
        """
        validation = validate_pcap_file(pcap_path)
        clean_path = str(Path(pcap_path).resolve())

        # Construct TShark command
        cmd = [
            self.tshark_path,
            "-r", clean_path,
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=/t",
            "-E", "quote=d",
            "-E", "occurrence=f",
        ]

        if max_packets and max_packets > 0:
            cmd.extend(["-c", str(max_packets)])

        for tshark_field, _ in TSHARK_FIELDS:
            cmd.extend(["-e", tshark_field])

        logger.info(f"Invoking TShark parser on {validation['filename']} ({validation['file_size_mb']} MB)")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                check=False
            )
        except subprocess.TimeoutExpired:
            raise PCAPExtractionError(
                f"TShark packet extraction timed out after {self.timeout_sec} seconds. "
                "Consider increasing timeout or filtering the capture file."
            )
        except Exception as e:
            raise PCAPExtractionError(f"Subprocess invocation failure: {str(e)}")

        if res.returncode != 0 and not res.stdout:
            stderr_msg = res.stderr.strip() or "Unknown TShark error"
            raise PCAPExtractionError(f"TShark failed (Code {res.returncode}): {stderr_msg}")

        # Ingest output into pandas
        raw_output = res.stdout
        if not raw_output or len(raw_output.strip().splitlines()) <= 1:
            # Only header or empty
            return pd.DataFrame(columns=[alias for _, alias in TSHARK_FIELDS] + [
                "src_ip", "dst_ip", "src_port", "dst_port", "connection_id"
            ])

        try:
            df = pd.read_csv(
                io.StringIO(raw_output),
                sep="\t",
                dtype=str,
                keep_default_na=False,
                na_values=[""]
            )
        except Exception as e:
            raise PCAPExtractionError(f"Failed to parse TShark TSV output: {str(e)}")

        # Rename raw TShark columns to canonical names using case-insensitive mapping
        col_map = {col.lower(): col for col in df.columns}
        col_rename = {}
        for orig, alias in TSHARK_FIELDS:
            if orig.lower() in col_map:
                col_rename[col_map[orig.lower()]] = alias
        df.rename(columns=col_rename, inplace=True)

        return self._normalize_dataframe(df)

    def _normalize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Normalizes IP addresses, ports, protocols, timestamps, and connection signatures.
        Handles missing fields gracefully without dropping records.
        """
        if df.empty:
            return df

        # 1. Normalize Source and Destination IPs (IPv4 or IPv6)
        if "ipv4_src" in df.columns and "ipv6_src" in df.columns:
            df["src_ip"] = df["ipv4_src"].fillna("").astype(str).str.strip()
            df["src_ip"] = df["src_ip"].where(df["src_ip"] != "", df["ipv6_src"].fillna("").astype(str).str.strip())
        elif "ipv4_src" in df.columns:
            df["src_ip"] = df["ipv4_src"].fillna("").astype(str).str.strip()
        else:
            df["src_ip"] = ""

        if "ipv4_dst" in df.columns and "ipv6_dst" in df.columns:
            df["dst_ip"] = df["ipv4_dst"].fillna("").astype(str).str.strip()
            df["dst_ip"] = df["dst_ip"].where(df["dst_ip"] != "", df["ipv6_dst"].fillna("").astype(str).str.strip())
        elif "ipv4_dst" in df.columns:
            df["dst_ip"] = df["ipv4_dst"].fillna("").astype(str).str.strip()
        else:
            df["dst_ip"] = ""

        # 2. Normalize Ports (merge TCP and UDP ports)
        df["src_port"] = None
        df["dst_port"] = None

        if "tcp_srcport" in df.columns and "udp_srcport" in df.columns:
            src_p = df["tcp_srcport"].fillna("").astype(str).str.strip()
            src_p = src_p.where(src_p != "", df["udp_srcport"].fillna("").astype(str).str.strip())
            df["src_port"] = pd.to_numeric(src_p, errors="coerce")
        elif "tcp_srcport" in df.columns:
            df["src_port"] = pd.to_numeric(df["tcp_srcport"], errors="coerce")

        if "tcp_dstport" in df.columns and "udp_dstport" in df.columns:
            dst_p = df["tcp_dstport"].fillna("").astype(str).str.strip()
            dst_p = dst_p.where(dst_p != "", df["udp_dstport"].fillna("").astype(str).str.strip())
            df["dst_port"] = pd.to_numeric(dst_p, errors="coerce")
        elif "tcp_dstport" in df.columns:
            df["dst_port"] = pd.to_numeric(df["tcp_dstport"], errors="coerce")

        # 3. Numeric Conversions
        if "frame_number" in df.columns:
            df["frame_number"] = pd.to_numeric(df["frame_number"], errors="coerce").fillna(0).astype(int)

        if "length" in df.columns:
            df["length"] = pd.to_numeric(df["length"], errors="coerce").fillna(0).astype(int)

        if "timestamp_epoch" in df.columns:
            df["timestamp_epoch"] = pd.to_numeric(df["timestamp_epoch"], errors="coerce").fillna(0.0)
            df["datetime"] = pd.to_datetime(df["timestamp_epoch"], unit="s", errors="coerce")
        else:
            df["timestamp_epoch"] = 0.0
            df["datetime"] = pd.NaT

        # 4. Protocol Normalization
        if "protocol" in df.columns:
            df["protocol"] = df["protocol"].fillna("").astype(str).str.strip().str.upper()
        else:
            df["protocol"] = ""

        missing_proto = (df["protocol"] == "") | (df["protocol"] == "UNKNOWN")
        if "tcp_srcport" in df.columns and "tcp_dstport" in df.columns:
            tcp_mask = missing_proto & (df["tcp_srcport"].notna() | df["tcp_dstport"].notna())
            df.loc[tcp_mask, "protocol"] = "TCP"
        if "udp_srcport" in df.columns and "udp_dstport" in df.columns:
            udp_mask = missing_proto & (df["udp_srcport"].notna() | df["udp_dstport"].notna())
            df.loc[udp_mask, "protocol"] = "UDP"
        df["protocol"] = df["protocol"].replace("", "UNKNOWN")

        # 5. TCP Flags boolean normalization
        for flag_col in ["tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin"]:
            if flag_col in df.columns:
                df[flag_col] = df[flag_col].astype(str).str.strip().str.lower().isin(["1", "true"])
            else:
                df[flag_col] = False

        # 6. DNS normalization
        if "dns_query_name" in df.columns:
            df["dns_query_name"] = df["dns_query_name"].fillna("").astype(str).str.strip()
        else:
            df["dns_query_name"] = ""

        if "dns_is_response" in df.columns:
            df["dns_is_response"] = df["dns_is_response"].astype(str).str.strip().str.lower().isin(["1", "true"])
        else:
            df["dns_is_response"] = False

        if "dns_response_ip" in df.columns:
            df["dns_response_ip"] = df["dns_response_ip"].fillna("").astype(str).str.strip()
        else:
            df["dns_response_ip"] = ""

        # 7. Generate 5-Tuple Connection ID for transport layer flows
        def build_conn_id(row):
            if row["src_ip"] and row["dst_ip"] and pd.notna(row["src_port"]) and pd.notna(row["dst_port"]):
                return f"{row['src_ip']}:{int(row['src_port'])} -> {row['dst_ip']}:{int(row['dst_port'])} [{row['protocol']}]"
            elif row["src_ip"] and row["dst_ip"]:
                return f"{row['src_ip']} -> {row['dst_ip']} [{row['protocol']}]"
            return "NON-IP/BROADCAST"

        df["connection_id"] = df.apply(build_conn_id, axis=1)

        return df

    def export_processed_data(
        self, df: pd.DataFrame, output_dir: Union[str, Path], base_name: str
    ) -> Dict[str, str]:
        """
        Saves extracted telemetry as intermediate JSON and CSV artifacts.

        Returns:
            Dict containing paths to generated 'csv' and 'json' files.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        csv_file = out_path / f"{base_name}_extracted.csv"
        json_file = out_path / f"{base_name}_extracted.json"

        # Export CSV
        df.to_csv(csv_file, index=False)

        # Export JSON (records format with ISO timestamps)
        records = df.copy()
        if "datetime" in records.columns:
            records["datetime"] = records["datetime"].astype(str)
        records.to_json(json_file, orient="records", indent=2)

        return {
            "csv": str(csv_file.resolve()),
            "json": str(json_file.resolve()),
        }
