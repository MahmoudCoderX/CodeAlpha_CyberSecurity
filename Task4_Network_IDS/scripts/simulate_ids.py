#!/usr/bin/env python3
"""
simulate_ids.py - Run the custom rule set against a pcap, with no
Snort/Suricata installation required.

It parses the rules in rules/codealpha_ids.rules and evaluates them
packet by packet, then writes alerts in Snort "fast.log" format and in
Suricata "eve.json" format. Supported rule options: msg, sid, rev,
classtype, itype, flags, content (+ nocase), dsize:>N and
detection_filter (track by_src, count N, seconds S).

This exists so the rules can be tested and demonstrated on any machine
with Python 3. For a real deployment, load the same rules file into
Snort or Suricata as described in the README - the rule file itself is
standard Snort syntax and does not depend on this script.

Usage:
  python3 simulate_ids.py -r ../rules/codealpha_ids.rules \
      -p ../pcaps/port_scan.pcap [--home-net 192.168.1.0/24] \
      [--fast /path/fast.log] [--eve /path/eve.json]
"""

import argparse
import ipaddress
import json
import os
import struct
import sys

CLASSTYPES = {
    "attempted-admin":        ("Attempted Administrator Privilege Gain", 2),
    "attempted-dos":          ("Attempted Denial of Service", 2),
    "attempted-recon":        ("Attempted Information Leak", 2),
    "icmp-event":             ("Generic ICMP event", 3),
    "policy-violation":       ("Potential Corporate Privacy Violation", 1),
    "shellcode-detect":       ("Executable Code was Detected", 1),
    "trojan-activity":        ("A Network Trojan was detected", 1),
    "web-application-attack": ("Web Application Attack", 1),
}

TCP_FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10,
                 "U": 0x20, "E": 0x40, "C": 0x80}


# ---------------------------------------------------------------- rules

class Rule:
    def __init__(self, line, home_net):
        self.raw = line.strip()
        header, _, rest = self.raw.partition("(")
        parts = header.split()
        self.action = parts[0]
        self.proto = parts[1].lower()
        self.src = parts[2]
        self.sport = parts[3]
        self.dst = parts[5]
        self.dport = parts[6]

        opts = {}
        contents = []  # list of (bytes, nocase)
        for opt in rest.rstrip(")").split(";"):
            opt = opt.strip()
            if not opt:
                continue
            key, _, val = opt.partition(":")
            key, val = key.strip(), val.strip()
            if key == "content":
                contents.append((self._parse_content(val), False))
                opts.setdefault("_last_content", None)
                opts["_last_content"] = len(contents) - 1
            elif key == "nocase" and opts.get("_last_content") is not None:
                b, _ = contents[opts["_last_content"]]
                contents[opts["_last_content"]] = (b, True)
            else:
                opts[key] = val
        self.contents = contents
        self.msg = opts.get("msg", "").strip('"')
        self.sid = int(opts.get("sid", "0"))
        self.rev = int(opts.get("rev", "1"))
        self.classtype = opts.get("classtype", "misc-activity")
        self.itype = int(opts["itype"]) if "itype" in opts else None
        self.flags = opts.get("flags")
        self.dsize = opts.get("dsize")  # e.g. '>200'
        self.detection_filter = None
        if "detection_filter" in opts:
            df = {}
            for kv in opts["detection_filter"].split(","):
                k, _, v = kv.strip().partition(" ")
                df[k.strip()] = v.strip()
            self.detection_filter = {"count": int(df["count"]),
                                     "seconds": int(df["seconds"])}
        self.home_net = home_net

    @staticmethod
    def _parse_content(val):
        val = val.strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        out = bytearray()
        i = 0
        while i < len(val):
            if val[i] == "|":
                j = val.index("|", i + 1)
                for hexbyte in val[i + 1:j].split():
                    out.append(int(hexbyte, 16))
                i = j + 1
            else:
                out.extend(val[i].encode())
                i += 1
        return bytes(out)

    def _net_match(self, spec, ip):
        if spec == "any":
            return True
        if spec == "$HOME_NET":
            return ipaddress.ip_address(ip) in self.home_net
        if spec == "$EXTERNAL_NET":
            return ipaddress.ip_address(ip) not in self.home_net
        if spec.startswith("!"):
            return not self._net_match(spec[1:], ip)
        if "/" in spec:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(spec)
        return ip == spec

    @staticmethod
    def _port_match(spec, port):
        return spec == "any" or int(spec) == port

    def matches(self, pkt):
        if self.proto != "ip" and pkt["proto"] != self.proto:
            return False
        if not self._net_match(self.src, pkt["src"]):
            return False
        if not self._net_match(self.dst, pkt["dst"]):
            return False
        if pkt["proto"] in ("tcp", "udp"):
            if not self._port_match(self.sport, pkt["sport"]):
                return False
            if not self._port_match(self.dport, pkt["dport"]):
                return False
        if self.itype is not None and pkt.get("itype") != self.itype:
            return False
        if self.flags is not None and pkt["proto"] == "tcp":
            # Snort syntax: flags:<bits>[,<mask>]  e.g. flags:S,12 means
            # "within the SYN|ACK mask, SYN set and everything else clear".
            spec, _, mask_s = self.flags.partition(",")
            want = 0
            for ch in spec:
                if ch in TCP_FLAG_BITS:
                    want |= TCP_FLAG_BITS[ch]
            if mask_s:
                mask = int(mask_s, 0)
            elif spec == "0":
                mask = 0xFF  # flags:0 = no flags set at all
            else:
                mask = want  # no mask: listed bits must be set, rest don't-care
            if (pkt.get("flags", 0) & mask) != want:
                return False
        if self.dsize is not None:
            n = int(self.dsize[1:])
            if self.dsize[0] == ">" and not (len(pkt.get("payload", b"")) > n):
                return False
            if self.dsize[0] == "<" and not (len(pkt.get("payload", b"")) < n):
                return False
        for needle, nocase in self.contents:
            hay = pkt.get("payload", b"")
            if nocase:
                hay, needle = hay.lower(), needle.lower()
            if needle not in hay:
                return False
        return True


def load_rules(path, home_net):
    rules = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                rules.append(Rule(line, home_net))
    return rules


# ---------------------------------------------------------------- pcap

def read_pcap(path):
    pkts = []
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            raise ValueError(f"{path}: not a pcap file")
        f.read(20)  # rest of global header
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            sec, usec, incl, _ = struct.unpack(endian + "IIII", hdr)
            frame = f.read(incl)
            pkt = parse_frame(frame)
            if pkt:
                pkt["ts"] = sec + usec / 1_000_000
                pkts.append(pkt)
    return pkts


def parse_frame(frame):
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    proto_num = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    pkt = {"src": src, "dst": dst}
    body = ip[ihl:]
    if proto_num == 6:
        pkt["proto"] = "tcp"
        pkt["sport"], pkt["dport"] = struct.unpack("!HH", body[:4])
        pkt["flags"] = body[13]
        off = (body[12] >> 4) * 4
        pkt["payload"] = body[off:]
    elif proto_num == 17:
        pkt["proto"] = "udp"
        pkt["sport"], pkt["dport"] = struct.unpack("!HH", body[:4])
        pkt["payload"] = body[8:]
    elif proto_num == 1:
        pkt["proto"] = "icmp"
        pkt["itype"], pkt["icode"] = body[0], body[1]
        pkt["sport"] = pkt["dport"] = 0
        pkt["payload"] = body[8:]
    else:
        pkt["proto"] = "ip"
        pkt["sport"] = pkt["dport"] = 0
        pkt["payload"] = body
    return pkt


# ---------------------------------------------------------------- engine

def run(rules, pkts):
    """Evaluate rules; returns list of (ts, rule, pkt) alerts."""
    alerts = []
    df_state = {}  # (sid, src_ip) -> [timestamps]
    for pkt in pkts:
        for rule in rules:
            if not rule.matches(pkt):
                continue
            if rule.detection_filter:
                key = (rule.sid, pkt["src"])
                window = rule.detection_filter["seconds"]
                times = df_state.setdefault(key, [])
                times[:] = [t for t in times if pkt["ts"] - t < window]
                times.append(pkt["ts"])
                if len(times) < rule.detection_filter["count"]:
                    continue  # below threshold, stay quiet
            alerts.append((pkt["ts"], rule, pkt))
    return alerts


def fast_line(ts, rule, pkt):
    import datetime
    dt = datetime.datetime.utcfromtimestamp(ts)
    stamp = dt.strftime("%m/%d-%H:%M:%S.") + f"{int((ts % 1) * 1e6):06d}"
    desc, prio = CLASSTYPES.get(rule.classtype, ("Misc activity", 3))
    port_s = f":{pkt['sport']}" if pkt["proto"] in ("tcp", "udp") else ""
    port_d = f":{pkt['dport']}" if pkt["proto"] in ("tcp", "udp") else ""
    return (f"{stamp} [**] [1:{rule.sid}:{rule.rev}] {rule.msg} [**] "
            f"[Classification: {desc}] [Priority: {prio}] "
            f"{{{pkt['proto'].upper()}}} {pkt['src']}{port_s} -> {pkt['dst']}{port_d}")


def eve_obj(ts, rule, pkt):
    import datetime
    dt = datetime.datetime.utcfromtimestamp(ts)
    desc, prio = CLASSTYPES.get(rule.classtype, ("Misc activity", 3))
    return {
        "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int((ts % 1) * 1e6):06d}+0000",
        "event_type": "alert",
        "src_ip": pkt["src"],
        "src_port": pkt["sport"],
        "dest_ip": pkt["dst"],
        "dest_port": pkt["dport"],
        "proto": pkt["proto"].upper(),
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": rule.sid,
            "rev": rule.rev,
            "signature": rule.msg,
            "category": desc,
            "severity": prio,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-r", "--rules", required=True)
    ap.add_argument("-p", "--pcaps", nargs="+", required=True)
    ap.add_argument("--home-net", default="192.168.1.0/24")
    ap.add_argument("--fast", help="write Snort fast.log output here")
    ap.add_argument("--eve", help="write Suricata eve.json output here")
    args = ap.parse_args()

    home_net = ipaddress.ip_network(args.home_net)
    rules = load_rules(args.rules, home_net)
    print(f"loaded {len(rules)} rules from {args.rules}", file=sys.stderr)

    all_alerts = []
    for pcap in args.pcaps:
        pkts = read_pcap(pcap)
        pcap_alerts = run(rules, pkts)
        all_alerts.extend(pcap_alerts)
        print(f"{os.path.basename(pcap)}: {len(pkts)} packets, "
              f"{len(pcap_alerts)} alerts", file=sys.stderr)

    all_alerts.sort(key=lambda a: a[0])

    fast_lines = [fast_line(*a) for a in all_alerts]
    eve_lines = [json.dumps(eve_obj(*a)) for a in all_alerts]

    if args.fast:
        with open(args.fast, "w") as f:
            f.write("\n".join(fast_lines) + "\n")
    if args.eve:
        with open(args.eve, "w") as f:
            f.write("\n".join(eve_lines) + "\n")
    if not args.fast and not args.eve:
        print("\n".join(fast_lines))

    # per-rule summary, like the counts Snort prints on exit
    counts = {}
    for _, rule, _ in all_alerts:
        counts.setdefault((rule.sid, rule.msg), 0)
        counts[(rule.sid, rule.msg)] += 1
    print("\nalerts by rule:", file=sys.stderr)
    for (sid, msg), n in sorted(counts.items()):
        print(f"  sid {sid}: {n:3d}  {msg}", file=sys.stderr)


if __name__ == "__main__":
    main()
