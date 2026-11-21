# Task 1: Basic Network Sniffer
CodeAlpha Cyber Security Internship | Mahmoud Mohamed Sayed

A Python program that captures live network traffic and analyses each packet:
source/destination IPs, protocol (TCP/UDP/ICMP), ports, TCP flags, packet
length and a safe preview of the payload.

## What it shows
- How data flows through a network, packet by packet.
- The structure of TCP, UDP and ICMP traffic on top of IPv4/IPv6.
- Which conversations happen on a network segment and what ports they use.

## Requirements
- Python 3.8+
- `pip install -r requirements.txt` (installs scapy)
- Root/administrator privileges for live capture (packet sniffing needs raw access)

## Usage
```bash
# Capture 20 packets on the default interface
sudo python3 network_sniffer.py -c 20

# Capture on a specific interface with a BPF filter, save to a log
sudo python3 network_sniffer.py -i wlan0 -f "tcp port 80" -o capture.log

# Raw-socket fallback (Linux, no scapy needed)
sudo python3 network_sniffer.py --raw-socket -c 10

# Demo mode: analyse synthetic packets, no root required
python3 network_sniffer.py --demo
```

## Sample output
See `sample_output.txt` (produced by `--demo`).

## Notes
- Payloads are previewed as printable ASCII (64 bytes max) to keep output readable.
- BPF filters follow standard tcpdump syntax, e.g. `"udp port 53"`, `"host 8.8.8.8"`.
