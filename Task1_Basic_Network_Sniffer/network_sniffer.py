#!/usr/bin/env python3
"""
Basic Network Sniffer - CodeAlpha Cyber Security Internship (Task 1)
Author: Mahmoud Mohamed Sayed

Captures live network traffic and displays the structure and content of each
packet: source/destination IPs, protocol, ports, flags and a payload preview.

Primary capture engine: scapy (cross-platform).
Fallback engine: raw sockets (Linux only) for environments without scapy.

A --demo mode generates synthetic packets in memory so the packet-analysis
logic can be demonstrated and tested without root privileges or a NIC.
"""

import argparse
import datetime
import sys

# ---------------------------------------------------------------------------
# Packet analysis
# ---------------------------------------------------------------------------

def analyze_scapy_packet(packet, verbose_payload=True):
    """Return a dict with the useful fields of a scapy packet."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw

    info = {
        "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": None,
        "dst": None,
        "protocol": "OTHER",
        "sport": None,
        "dport": None,
        "flags": None,
        "length": len(packet),
        "payload": None,
    }

    if packet.haslayer(IP):
        info["src"] = packet[IP].src
        info["dst"] = packet[IP].dst
    elif packet.haslayer(IPv6):
        info["src"] = packet[IPv6].src
        info["dst"] = packet[IPv6].dst

    if packet.haslayer(TCP):
        info["protocol"] = "TCP"
        info["sport"] = packet[TCP].sport
        info["dport"] = packet[TCP].dport
        info["flags"] = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        info["protocol"] = "UDP"
        info["sport"] = packet[UDP].sport
        info["dport"] = packet[UDP].dport
    elif packet.haslayer(ICMP):
        info["protocol"] = "ICMP"

    if packet.haslayer(Raw) and verbose_payload:
        raw = bytes(packet[Raw].load)
        # Show a safe preview: printable ASCII, hex for the rest.
        preview = "".join(chr(b) if 32 <= b < 127 else "." for b in raw[:64])
        info["payload"] = preview

    return info


def format_info(info):
    """Render one analysed packet as a human-readable line block."""
    line = f"[{info['time']}] {info['protocol']:5} {info['src']}:{info['sport']} -> {info['dst']}:{info['dport']} len={info['length']}"
    if info["flags"]:
        line += f" flags={info['flags']}"
    if info["payload"]:
        line += f"\n    payload: {info['payload']}"
    return line


# ---------------------------------------------------------------------------
# Capture engines
# ---------------------------------------------------------------------------

def sniff_with_scapy(interface, count, bpf_filter, output):
    from scapy.all import sniff

    print(f"[*] Sniffing on interface={interface or 'default'} "
          f"count={count or 'unlimited'} filter={bpf_filter or 'none'}")
    print("[*] Press Ctrl+C to stop.\n")

    seen = {"n": 0}

    def handle(packet):
        seen["n"] += 1
        info = analyze_scapy_packet(packet)
        text = format_info(info)
        print(f"#{seen['n']} {text}")
        if output:
            output.write(text + "\n")

    try:
        sniff(iface=interface, count=count, filter=bpf_filter or None,
              prn=handle, store=False)
    except PermissionError:
        sys.exit("[!] Permission denied: run as root (sudo) to capture packets.")
    except OSError as exc:
        sys.exit(f"[!] Capture error: {exc}")

    print(f"\n[*] Done. {seen['n']} packets captured.")


def sniff_with_socket(count, output):
    """Minimal raw-socket fallback (Linux AF_PACKET)."""
    import socket
    import struct

    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        sys.exit("[!] Permission denied: run as root (sudo) to capture packets.")

    print("[*] Raw-socket capture started (Linux). Press Ctrl+C to stop.\n")
    n = 0
    try:
        while count == 0 or n < count:
            raw, _ = s.recvfrom(65535)
            n += 1
            # Ethernet header: 14 bytes; assume IPv4 for the fallback parser.
            if len(raw) < 34:
                continue
            version_ihl = raw[14]
            if version_ihl >> 4 != 4:
                continue
            ihl = (version_ihl & 0xF) * 4
            proto = raw[23]
            src = socket.inet_ntoa(raw[26:30])
            dst = socket.inet_ntoa(raw[30:34])
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))
            sport = dport = None
            if proto in (6, 17) and len(raw) >= 14 + ihl + 4:
                sport, dport = struct.unpack("!HH", raw[14 + ihl:14 + ihl + 4])
            info = {
                "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src": src, "dst": dst, "protocol": proto_name,
                "sport": sport, "dport": dport, "flags": None,
                "length": len(raw), "payload": None,
            }
            text = format_info(info)
            print(f"#{n} {text}")
            if output:
                output.write(text + "\n")
    except KeyboardInterrupt:
        pass
    print(f"\n[*] Done. {n} packets captured.")


# ---------------------------------------------------------------------------
# Demo mode (no root needed): builds synthetic packets and analyses them.
# ---------------------------------------------------------------------------

def demo():
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.packet import Raw

    samples = [
        IP(src="192.168.1.10", dst="142.250.190.78") / TCP(sport=51514, dport=443, flags="PA")
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        IP(src="142.250.190.78", dst="192.168.1.10") / TCP(sport=443, dport=51514, flags="A"),
        IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53210, dport=53)
        / Raw(load=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
        IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(),
        IP(src="10.0.0.5", dst="192.168.1.10") / TCP(sport=44022, dport=22, flags="S"),
    ]
    print("[*] Demo mode: analysing 5 synthetic packets (no capture performed).\n")
    for i, pkt in enumerate(samples, 1):
        print(f"#{i} {format_info(analyze_scapy_packet(pkt))}")


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer - capture and analyse network packets.")
    parser.add_argument("-i", "--interface", help="Interface to sniff on (e.g. eth0, wlan0).")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited).")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter, e.g. 'tcp port 80' (scapy mode only).")
    parser.add_argument("-o", "--output", help="Also write captured summaries to this file.")
    parser.add_argument("--raw-socket", action="store_true",
                        help="Use the raw-socket fallback instead of scapy (Linux).")
    parser.add_argument("--demo", action="store_true",
                        help="Analyse synthetic packets in memory (no root required).")
    args = parser.parse_args()

    out = open(args.output, "a") if args.output else None
    try:
        if args.demo:
            demo()
        elif args.raw_socket:
            sniff_with_socket(args.count, out)
        else:
            try:
                import scapy  # noqa: F401
            except ImportError:
                print("[!] scapy not installed; falling back to raw sockets. "
                      "Install with: pip install scapy")
                sniff_with_socket(args.count, out)
            else:
                sniff_with_scapy(args.interface, args.count, args.filter, out)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    finally:
        if out:
            out.close()


if __name__ == "__main__":
    main()
