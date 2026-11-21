#!/usr/bin/env python3
"""
generate_pcaps.py - Craft test traffic for the CodeAlpha NIDS task.

Generates four pcap files under ../pcaps/ using only the Python standard
library (no scapy required). Each pcap exercises a different part of the
rule set in rules/codealpha_ids.rules:

  port_scan.pcap          TCP SYN scan, plus single NULL / FIN / Xmas probes
  icmp_sweep.pcap         ICMP echo sweep across the 192.168.1.0/24 subnet
  ssh_brute_force.pcap    repeated SSH connections, a few FTP (below the
                          threshold, on purpose) and one outbound Telnet
  suspicious_payloads.pcap /etc/passwd traversal, SQLi, XSS, cmd.exe,
                          NOP sled and an oversized DNS query

The MAC/IP/port values are from documentation ranges (TEST-NET RFC 5737)
where the traffic is "external".
"""

import os
import struct

BASE_TS = 1795255200  # 2026-11-21 10:00:00 UTC (fixed so output is reproducible)

SRC_MAC = b"\x02\x00\x00\x00\x00\x01"
DST_MAC = b"\x02\x00\x00\x00\x00\x02"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ip_packet(src: str, dst: str, proto: int, payload: bytes, ident: int = 0) -> bytes:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, ident, 0x4000, 64, proto, 0) + src_b + dst_b
    csum = checksum(hdr)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, ident, 0x4000, 64, proto, csum) + src_b + dst_b
    return hdr + payload


def tcp_segment(sport: int, dport: int, flags: int, payload: bytes = b"",
                seq: int = 1000, ack: int = 0) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return hdr + payload


def icmp_echo(ident: int = 1, seq: int = 1) -> bytes:
    data = b"abcdefghijklmnopqrstuvwxyz012345"  # 32-byte payload, like a real ping
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    csum = checksum(hdr + data)
    return struct.pack("!BBHHH", 8, 0, csum, ident, seq) + data


def udp_datagram(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def eth_frame(ip_pkt: bytes) -> bytes:
    return DST_MAC + SRC_MAC + b"\x08\x00" + ip_pkt


class PcapWriter:
    def __init__(self, path: str):
        self.f = open(path, "wb")
        # global header: magic, v2.4, tz, sigfigs, snaplen, linktype Ethernet
        self.f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def write(self, ts: float, frame: bytes):
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()


def add_tcp_flow(pkts, src, dst, sport, dport, payload, ts):
    """Append a minimal but realistic TCP flow: SYN, SYN-ACK, ACK, data, FIN."""
    pkts.append((ts,        eth_frame(ip_packet(src, dst, 6, tcp_segment(sport, dport, 0x02, seq=1000)))))
    pkts.append((ts + 0.05, eth_frame(ip_packet(dst, src, 6, tcp_segment(dport, sport, 0x12, seq=5000, ack=1001)))))
    pkts.append((ts + 0.10, eth_frame(ip_packet(src, dst, 6, tcp_segment(sport, dport, 0x10, seq=1001, ack=5001)))))
    if payload:
        pkts.append((ts + 0.15, eth_frame(ip_packet(src, dst, 6, tcp_segment(sport, dport, 0x18, payload, seq=1001, ack=5001)))))
    pkts.append((ts + 0.20, eth_frame(ip_packet(src, dst, 6, tcp_segment(sport, dport, 0x11, seq=2000, ack=5001)))))


def gen_port_scan(path):
    pkts = []
    t = BASE_TS
    # SYN scan: 203.0.113.50 probes 25 ports on 192.168.1.10 in ~4 seconds
    ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
             995, 1433, 1521, 3306, 3389, 5900, 6379, 8000, 8080, 8443, 27017]
    for i, p in enumerate(ports):
        pkts.append((t + i * 0.16,
                     eth_frame(ip_packet("203.0.113.50", "192.168.1.10", 6,
                                         tcp_segment(40000 + i, p, 0x02, seq=7000 + i)))))
    # single NULL / FIN / Xmas probes from a second host
    t2 = t + 5.0
    pkts.append((t2,       eth_frame(ip_packet("203.0.113.51", "192.168.1.10", 6, tcp_segment(51000, 80, 0x00)))))
    pkts.append((t2 + 0.5, eth_frame(ip_packet("203.0.113.51", "192.168.1.10", 6, tcp_segment(51001, 80, 0x01)))))
    pkts.append((t2 + 1.0, eth_frame(ip_packet("203.0.113.51", "192.168.1.10", 6, tcp_segment(51002, 80, 0x29)))))  # FPU
    # a little normal traffic so the file is not 100% attack
    add_tcp_flow(pkts, "192.168.1.20", "192.168.1.10", 52000, 80, b"GET /index.html HTTP/1.1\r\nHost: intranet.local\r\n\r\n", t2 + 2.0)
    _write(path, pkts)


def gen_icmp_sweep(path):
    pkts = []
    t = BASE_TS
    # 198.51.100.23 pings 192.168.1.1 - 192.168.1.25 in ~8 seconds
    for i in range(1, 26):
        pkts.append((t + i * 0.3, eth_frame(ip_packet("198.51.100.23", f"192.168.1.{i}", 1, icmp_echo(1, i)))))
    # one lonely ping from another host (triggers the single-echo rule only)
    pkts.append((t + 9.0, eth_frame(ip_packet("198.51.100.40", "192.168.1.10", 1, icmp_echo(7, 1)))))
    _write(path, pkts)


def gen_brute_force(path):
    pkts = []
    t = BASE_TS
    # 8 SSH connections from 203.0.113.99 within ~50 seconds (threshold is 5/60s)
    for i in range(8):
        sport = 30000 + i
        ts = t + i * 6.5
        pkts.append((ts, eth_frame(ip_packet("203.0.113.99", "192.168.1.10", 6, tcp_segment(sport, 22, 0x02, seq=1000 + i)))))
        pkts.append((ts + 0.4, eth_frame(ip_packet("192.168.1.10", "203.0.113.99", 6, tcp_segment(22, sport, 0x12, seq=9000 + i, ack=1001 + i)))))
        pkts.append((ts + 0.8, eth_frame(ip_packet("203.0.113.99", "192.168.1.10", 6, tcp_segment(sport, 22, 0x04, seq=1001 + i)))))  # RST after failed login
    # only 2 FTP connections: below the threshold, should NOT alert
    for i in range(2):
        sport = 31000 + i
        ts = t + 2 + i * 10
        pkts.append((ts, eth_frame(ip_packet("203.0.113.99", "192.168.1.10", 6, tcp_segment(sport, 21, 0x02, seq=2000 + i)))))
    # one outbound Telnet session from an internal host (policy violation)
    add_tcp_flow(pkts, "192.168.1.20", "198.51.100.50", 53000, 23, b"admin\r\n", t + 55)
    _write(path, pkts)


def gen_suspicious_payloads(path):
    pkts = []
    t = BASE_TS
    add_tcp_flow(pkts, "203.0.113.77", "192.168.1.10", 44000, 80,
                 b"GET /../../../etc/passwd HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n", t)
    add_tcp_flow(pkts, "203.0.113.77", "192.168.1.10", 44001, 80,
                 b"POST /login.php HTTP/1.1\r\nHost: 192.168.1.10\r\nContent-Length: 52\r\n\r\n"
                 b"user=admin' UNION SELECT password FROM users--&pass=x", t + 2)
    add_tcp_flow(pkts, "203.0.113.78", "192.168.1.10", 44002, 80,
                 b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n", t + 4)
    add_tcp_flow(pkts, "203.0.113.79", "192.168.1.10", 44003, 80,
                 b"GET /cgi-bin/cmd.exe?/c+dir HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n", t + 6)
    # NOP sled followed by junk "shellcode"
    add_tcp_flow(pkts, "203.0.113.80", "192.168.1.10", 44004, 4444,
                 b"\x90" * 16 + b"\x31\xc0\x50\x68//sh\x68/bin\x89\xe3", t + 8)
    # oversized DNS query (300-byte payload) hitting our DNS server
    big_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"a" * 280
    pkts.append((t + 10, eth_frame(ip_packet("203.0.113.81", "192.168.1.53", 17,
                                             udp_datagram(53535, 53, big_query)))))
    _write(path, pkts)


def _write(path, pkts):
    pkts.sort(key=lambda p: p[0])
    w = PcapWriter(path)
    for ts, frame in pkts:
        w.write(ts, frame)
    w.close()
    print(f"wrote {path} ({len(pkts)} packets)")


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pcaps")
    os.makedirs(out, exist_ok=True)
    gen_port_scan(os.path.join(out, "port_scan.pcap"))
    gen_icmp_sweep(os.path.join(out, "icmp_sweep.pcap"))
    gen_brute_force(os.path.join(out, "ssh_brute_force.pcap"))
    gen_suspicious_payloads(os.path.join(out, "suspicious_payloads.pcap"))
