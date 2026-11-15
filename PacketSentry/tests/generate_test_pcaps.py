"""
Synthetic PCAP Generator for PacketSentry Tests & Demonstration.
Generates RFC-compliant PCAP files without external dependencies.
"""

import os
import socket
import struct
from pathlib import Path
from typing import List, Tuple


def _ip_checksum(data: bytes) -> int:
    """Calculates IPv4 header checksum."""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _make_eth(payload: bytes) -> bytes:
    """Constructs 14-byte Ethernet II frame header (IPv4)."""
    dst_mac = b"\x00\x0c\x29\x6d\x11\x22"
    src_mac = b"\x00\x50\x56\xc0\x00\x08"
    eth_type = 0x0800  # IPv4
    return struct.pack("!6s6sH", dst_mac, src_mac, eth_type) + payload


def _make_ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes) -> bytes:
    """Constructs 20-byte standard IPv4 header."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    total_len = 20 + len(payload)
    header_unck = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, 54321, 0, 64, proto, 0, src, dst
    )
    chksum = _ip_checksum(header_unck)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, 54321, 0, 64, proto, chksum, src, dst
    )
    return header + payload


def _make_tcp(
    src_port: int, dst_port: int, flags: int, seq: int = 1000, ack: int = 0
) -> bytes:
    """Constructs 20-byte TCP header."""
    offset_res = 5 << 4
    return struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_res,
        flags,
        8192,
        0,
        0,
    )


def _make_udp(src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
    """Constructs 8-byte UDP header."""
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def _encode_dns_name(domain: str) -> bytes:
    """Encodes a domain name into DNS question format."""
    parts = domain.strip(".").split(".")
    res = b""
    for part in parts:
        res += bytes([len(part)]) + part.encode("ascii")
    res += b"\x00"
    return res


def _make_dns_query(domain: str, qid: int = 0x1234) -> bytes:
    """Constructs a basic DNS A-record query payload."""
    flags = 0x0100  # Standard query with recursion desired
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    qname = _encode_dns_name(domain)
    qtype_qclass = struct.pack("!HH", 1, 1)  # Type A, Class IN
    return header + qname + qtype_qclass


def _write_pcap(filepath: Path, packets: List[Tuple[int, int, bytes]]):
    """Writes packets to a standard PCAP file."""
    # Global header (24 bytes): Magic 0xa1b2c3d4, v2.4, usec, snaplen 65535, Ethernet (1)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for ts_sec, ts_usec, pkt in packets:
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt))
            f.write(pkt_hdr + pkt)


def generate_sample_pcap(filepath: Path) -> Path:
    """
    Generates a realistic multi-flow sample PCAP:
    - Normal HTTP handshake & traffic (192.168.1.100 -> 93.184.216.34:80)
    - Normal DNS resolution (192.168.1.100 -> 8.8.8.8:53)
    - SYN Port Scan (10.0.0.99 scanning 192.168.1.50 across ports 21, 22, 23, 80, 443, 3389, 8080)
    - Repeated failed SYN attempts
    - Suspicious high-entropy / long DNS query
    """
    packets = []
    base_time = 1700000000

    # 1. Normal DNS Query (google.com)
    dns_payload = _make_dns_query("google.com", qid=0x1001)
    udp_dns = _make_udp(53001, 53, dns_payload)
    ip_dns = _make_ipv4("192.168.1.100", "8.8.8.8", 17, udp_dns)
    packets.append((base_time, 10000, _make_eth(ip_dns)))

    # 2. Normal HTTP 3-Way Handshake
    # Client SYN
    tcp_syn = _make_tcp(49152, 80, 0x02, seq=100)
    packets.append((base_time, 50000, _make_eth(_make_ipv4("192.168.1.100", "93.184.216.34", 6, tcp_syn))))
    # Server SYN-ACK
    tcp_synack = _make_tcp(80, 49152, 0x12, seq=500, ack=101)
    packets.append((base_time, 70000, _make_eth(_make_ipv4("93.184.216.34", "192.168.1.100", 6, tcp_synack))))
    # Client ACK
    tcp_ack = _make_tcp(49152, 80, 0x10, seq=101, ack=501)
    packets.append((base_time, 80000, _make_eth(_make_ipv4("192.168.1.100", "93.184.216.34", 6, tcp_ack))))

    # 3. Port Scan: Attacker 10.0.0.99 probes victim 192.168.1.50 on 15 distinct ports
    target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
    for idx, port in enumerate(target_ports):
        scan_syn = _make_tcp(50000 + idx, port, 0x02, seq=1000 + idx)
        packets.append((base_time + 1, 100000 + (idx * 20000), _make_eth(_make_ipv4("10.0.0.99", "192.168.1.50", 6, scan_syn))))

    # 4. Repeated Failed Connection Attempts (SYN Flooding / Repeated SYN without ACK)
    for i in range(12):
        rep_syn = _make_tcp(60000 + i, 445, 0x02, seq=2000 + i)
        packets.append((base_time + 2, 200000 + (i * 30000), _make_eth(_make_ipv4("10.0.0.77", "192.168.1.50", 6, rep_syn))))

    # 5. Suspicious Long DNS Query (Potential Tunneling/Exfiltration or DGA)
    tunnel_domain = "v1-exfil-secret-data-payload-chunk-998877.c2-command-and-control-server.example.org"
    d_pay = _make_dns_query(tunnel_domain, qid=0x9999)
    u_dns = _make_udp(54000, 53, d_pay)
    ip_tunnel = _make_ipv4("192.168.1.200", "8.8.4.4", 17, u_dns)
    packets.append((base_time + 3, 500000, _make_eth(ip_tunnel)))

    _write_pcap(filepath, packets)
    return filepath


if __name__ == "__main__":
    out = Path("data/uploads/sample_capture.pcap")
    generate_sample_pcap(out)
    print(f"Generated sample capture: {out.resolve()} ({out.stat().st_size} bytes)")
