# Network Intrusion Detection System (Snort / Suricata)

CodeAlpha Cyber Security Internship - Task: **Network-Based Intrusion Detection System**

Author: **Bondok**

A signature-based Network Intrusion Detection System (NIDS) built on a custom
Snort/Suricata rule set. The rules detect the most common network attacks seen
against a small LAN: reconnaissance (ping sweeps, SYN/NULL/FIN/Xmas port scans),
brute-force login attempts (SSH/FTP/Telnet), suspicious payloads (path traversal,
SQL injection, XSS, shellcode NOP sleds) and policy violations (cleartext Telnet,
oversized DNS queries).

Everything needed to test the rules is included: crafted pcaps, a dependency-free
rule simulator that reproduces Snort's `fast.log` and Suricata's `eve.json`
output, and minimal config files for both engines.

## Repository layout

```
CodeAlpha_Network_IDS/
├── README.md                      <- this file
├── rules/
│   └── codealpha_ids.rules        <- 16 documented detection rules (SIDs 1000001-1000016)
├── config/
│   ├── snort.conf                 <- minimal Snort 2.9 config
│   ├── classification.config      <- classtype definitions used by the rules
│   └── suricata.yaml              <- minimal Suricata config
├── pcaps/                         <- crafted test traffic (generated)
│   ├── port_scan.pcap
│   ├── icmp_sweep.pcap
│   ├── ssh_brute_force.pcap
│   └── suspicious_payloads.pcap
├── scripts/
│   ├── generate_pcaps.py          <- builds the test pcaps (Python 3 stdlib only)
│   └── simulate_ids.py            <- runs the rules against pcaps without Snort/Suricata
└── sample_output/
    ├── alerts.log                 <- Snort fast.log-style output from the test pcaps
    ├── eve.json                   <- Suricata EVE-style JSON alerts
    └── summary.txt                <- per-packet-count and per-rule alert summary
```

## The rules

| SID | Detects | How |
|-----|---------|-----|
| 1000001 | Single ICMP echo request | `itype:8` from outside |
| 1000002 | ICMP ping sweep | 10+ echo requests from one host in 10s (`detection_filter`) |
| 1000003 | TCP SYN port scan | 20+ SYNs from one host in 5s, `flags:S,18` so SYN-ACK replies don't count |
| 1000004 | TCP NULL scan | packet with no flags (`flags:0,63`) |
| 1000005 | TCP FIN scan | FIN set, ACK clear (`flags:F,17`, so normal connection teardown doesn't match) |
| 1000006 | TCP Xmas scan | FIN+PSH+URG together (`flags:FPU,63`) |
| 1000007 | SSH brute force | 5+ new connections to port 22 from one host in 60s |
| 1000008 | FTP brute force | same logic on port 21 |
| 1000009 | Telnet brute force | same logic on port 23 |
| 1000010 | `/etc/passwd` access attempt | content match in HTTP traffic |
| 1000011 | `cmd.exe` in payload | content match (webshells, exploits) |
| 1000012 | SQL injection | `union select` (case-insensitive) in HTTP |
| 1000013 | XSS probe | `<script>` (case-insensitive) in HTTP |
| 1000014 | NOP sled / shellcode | 10+ consecutive `0x90` bytes |
| 1000015 | Outbound Telnet | internal host opening a cleartext Telnet session |
| 1000016 | DNS tunneling | UDP/53 query larger than 200 bytes (`dsize:>200`) |

Rate-based rules use `detection_filter` (track by source IP) so background
noise stays silent and only a genuine burst alerts.

## Quick start - test the rules with zero installation

The included simulator parses the same rule file and evaluates it against the
pcaps, so you can verify the detection logic on any machine with Python 3:

```bash
# regenerate the test traffic (optional - pcaps/ is already built)
python3 scripts/generate_pcaps.py

# run all 16 rules against all four pcaps
python3 scripts/simulate_ids.py -r rules/codealpha_ids.rules -p pcaps/*.pcap \
    --fast sample_output/alerts.log --eve sample_output/eve.json
```

Expected result: **63 alerts** across the four pcaps, broken down exactly as in
`sample_output/summary.txt`.

## Using the rules with Snort (Linux)

Tested instructions for Ubuntu/Debian:

```bash
sudo apt update && sudo apt install -y snort

# copy the rules and config
sudo cp rules/codealpha_ids.rules /etc/snort/rules/
sudo cp config/classification.config /etc/snort/

# option A: run against the included test pcaps (offline, no live traffic)
sudo snort -A fast -q -c config/snort.conf -l /tmp/snortlog -r pcaps/port_scan.pcap
cat /tmp/snortlog/alert             # fast-mode alerts land in <logdir>/alert

# option B: live capture on an interface (replace eth0 with yours)
sudo snort -A fast -q -c config/snort.conf -i eth0

# generate real attack traffic from another machine and watch the alerts:
nmap -sS <target>        # triggers sid 1000003
nmap -sN <target>        # triggers sid 1000004
nmap -sX <target>        # triggers sid 1000006
nmap --min-rate 50 192.168.1.0/24 -sn   # ping sweep, triggers sid 1000002
```

On a production install you would normally keep the stock
`/etc/snort/snort.conf` and just add one line:

```
include $RULE_PATH/codealpha_ids.rules
```

## Using the rules with Suricata (Linux)

```bash
sudo apt install -y suricata

# offline test against the pcaps
suricata -c config/suricata.yaml -r pcaps/ssh_brute_force.pcap -l /tmp/surilog
cat /tmp/surilog/fast.log           # Snort-style alerts
jq . /tmp/surilog/eve.json          # structured JSON alerts

# live mode
sudo suricata -c config/suricata.yaml -i eth0
```

The rule file is plain Snort 2.x syntax, which Suricata loads natively.

## Sample alert output

From `sample_output/alerts.log` (full file in this repo):

```
11/21-10:00:03.039999 [**] [1:1000003:1] NIDS: TCP SYN port scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.50:40019 -> 192.168.1.10:5900
11/21-10:00:03.000000 [**] [1:1000002:1] NIDS: ICMP ping sweep detected [**] [Classification: Attempted Information Leak] [Priority: 2] {ICMP} 198.51.100.23 -> 192.168.1.10
11/21-10:00:05.000000 [**] [1:1000004:1] NIDS: TCP NULL scan (no flags set) [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.51:51000 -> 192.168.1.10:80
11/21-10:00:26.000000 [**] [1:1000007:1] NIDS: Possible SSH brute force (repeated connections) [**] [Classification: Attempted Denial of Service] [Priority: 2] {TCP} 203.0.113.99:30004 -> 192.168.1.10:22
11/21-10:00:00.150000 [**] [1:1000010:1] NIDS: /etc/passwd access attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 2] {TCP} 203.0.113.77:44000 -> 192.168.1.10:80
```

## Testing notes (what was actually tested)

Honesty section - exactly what was and wasn't done:

* The test pcaps in `pcaps/` are **synthetic**, crafted packet by packet by
  `scripts/generate_pcaps.py`. They contain a SYN scan, NULL/FIN/Xmas probes,
  a 25-host ping sweep, 8 rapid SSH connections, 2 FTP connections (below the
  brute-force threshold on purpose), one outbound Telnet session, HTTP requests
  carrying `/etc/passwd`, `UNION SELECT`, `<script>` and `cmd.exe`, a NOP sled,
  and one oversized DNS query.
* The sample output in `sample_output/` was produced by
  `scripts/simulate_ids.py`, which parses the actual rule file
  (`rules/codealpha_ids.rules`) and evaluates the real rule logic
  (protocols, networks, ports, flag masks, content matching, `dsize` and
  `detection_filter` thresholds) against those pcaps. The output format
  mirrors Snort's `fast.log` and Suricata's `eve.json`.
* The rules were **not executed by a live Snort/Suricata daemon** during
  preparation (no sensor was available), and they have **not been tuned against
  real background traffic**. Syntax is standard Snort 2.x and the README
  commands above let you reproduce everything on a real engine.
* Negative cases are included and verified: the 2 FTP connections stay under
  the threshold and do not alert, and normal HTTP traffic in
  `port_scan.pcap` produces no alerts.

## Limitations and future work

* Signature-based detection only: it catches what it knows and nothing zero-day.
* The payload rules match on plaintext; TLS-encrypted attacks need TLS
  inspection or endpoint visibility.
* Thresholds (20 SYNs/5s, 5 SSH/60s, ...) are sensible defaults for a small
  LAN and would need tuning for a busy network to balance false positives.
* Next steps: add anomaly-based detection, integrate `eve.json` with a SIEM
  (e.g. Wazuh/ELK), and enable Snort's inline (IPS) mode to block instead of
  only alert.
