"""Volume statistics: throughput timeline, top talkers, protocol mix, ICMP."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .reader import Packet

SERVICE_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
    139: "SMB", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE", 514: "Syslog", 587: "SMTP", 853: "DoT", 993: "IMAPS",
    995: "POP3S", 1194: "OpenVPN", 1900: "SSDP", 3389: "RDP", 3478: "STUN", 4500: "IPsec-NAT",
    5060: "SIP", 5353: "mDNS", 5355: "LLMNR", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}
ICMP_NAMES = {
    ("ICMP", 0): "echo reply", ("ICMP", 8): "echo request", ("ICMP", 3): "destination unreachable",
    ("ICMP", 11): "time exceeded", ("ICMP", 5): "redirect",
    ("ICMPv6", 1): "destination unreachable", ("ICMPv6", 2): "packet too big",
    ("ICMPv6", 3): "time exceeded", ("ICMPv6", 128): "echo request", ("ICMPv6", 129): "echo reply",
    ("ICMPv6", 133): "router solicitation", ("ICMPv6", 134): "router advertisement",
    ("ICMPv6", 135): "neighbour solicitation", ("ICMPv6", 136): "neighbour advertisement",
}
UNREACH_CODES = {0: "network unreachable", 1: "host unreachable", 2: "protocol unreachable",
                 3: "port unreachable", 4: "fragmentation needed (MTU)", 9: "network prohibited",
                 10: "host prohibited", 13: "administratively prohibited"}


def service_of(proto: str, sport: int, dport: int) -> str:
    for p in (dport, sport) if dport <= sport else (sport, dport):
        if p in SERVICE_NAMES:
            name = SERVICE_NAMES[p]
            if proto == "UDP" and p == 443:
                return "QUIC"
            return name
    return f"{proto}/{min(sport, dport)}" if proto in ("TCP", "UDP") else proto


@dataclass
class TrafficStats:
    first_ts: float = 0.0
    packets: int = 0
    bytes: int = 0
    per_second: dict = field(default_factory=lambda: defaultdict(int))
    proto_bytes: dict = field(default_factory=lambda: defaultdict(int))
    proto_packets: dict = field(default_factory=lambda: defaultdict(int))
    service_bytes: dict = field(default_factory=lambda: defaultdict(int))
    host_tx: dict = field(default_factory=lambda: defaultdict(int))
    host_rx: dict = field(default_factory=lambda: defaultdict(int))
    conversations: dict = field(default_factory=dict)
    icmp: dict = field(default_factory=dict)   # (proto, type, code) -> {count, examples}
    fragments: int = 0
    truncated: int = 0
    tso_zero_len: int = 0
    max_frame: int = 0
    bin_s: float = 0.01

    def process(self, pkt: Packet) -> None:
        if self.packets == 0:
            self.first_ts = pkt.ts
        self.packets += 1
        n = pkt.length
        self.bytes += n
        self.max_frame = max(self.max_frame, n)
        # Fine-grained bins (10 ms) that coarsen x10 whenever there are too many,
        # so short captures get a useful chart and long ones stay small in memory.
        b = int((pkt.ts - self.first_ts) / self.bin_s) if pkt.ts >= self.first_ts else 0
        self.per_second[b] += n
        if len(self.per_second) > 50_000:
            self.bin_s *= 10
            merged = defaultdict(int)
            for k, v in self.per_second.items():
                merged[k // 10] += v
            self.per_second = merged
        self.proto_bytes[pkt.proto] += n
        self.proto_packets[pkt.proto] += 1
        if pkt.truncated:
            self.truncated += 1
        if pkt.fragment:
            self.fragments += 1
        if pkt.proto == "TCP" and pkt.ip_len == 0 and pkt.src and "." in pkt.src:
            self.tso_zero_len += 1
        if not pkt.src:
            return
        self.host_tx[pkt.src] += n
        self.host_rx[pkt.dst] += n
        if pkt.proto in ("TCP", "UDP"):
            svc = service_of(pkt.proto, pkt.sport, pkt.dport)
            self.service_bytes[svc] += n
            a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
            key = (pkt.proto,) + ((a, b) if a <= b else (b, a))
            conv = self.conversations.get(key)
            if conv is None:
                if len(self.conversations) >= 200_000:
                    return
                conv = self.conversations[key] = {
                    "proto": pkt.proto, "a": f"{key[1][0]}:{key[1][1]}",
                    "b": f"{key[2][0]}:{key[2][1]}", "service": svc, "packets": 0,
                    "bytes": 0, "first_ts": pkt.ts, "last_ts": pkt.ts}
            conv["packets"] += 1
            conv["bytes"] += n
            conv["last_ts"] = pkt.ts
        elif pkt.proto in ("ICMP", "ICMPv6"):
            row = self.icmp.get((pkt.proto, pkt.icmp_type, pkt.icmp_code))
            if row is None:
                row = self.icmp[(pkt.proto, pkt.icmp_type, pkt.icmp_code)] = {"count": 0, "examples": []}
            row["count"] += 1
            if len(row["examples"]) < 10:
                row["examples"].append({"frame": pkt.no, "time": round(pkt.ts - self.first_ts, 6),
                                        "src": pkt.src, "dst": pkt.dst, "code": pkt.icmp_code,
                                        **pkt.icmp_info})

    # ---------------------------------------------------------------- outputs
    def timeline(self, max_points: int = 300) -> dict:
        """Throughput in bit/s per bucket; bucket size is a 'nice' value giving <= max_points."""
        if not self.per_second:
            return {"bucket_s": 1, "points": []}
        last = max(self.per_second)
        duration = (last + 1) * self.bin_s
        nice = [0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600]
        bucket = next((b for b in nice if b >= self.bin_s - 1e-9 and duration / b <= max_points), None)
        if bucket is None:
            bucket = duration / max_points
        per = max(1, round(bucket / self.bin_s))
        bucket = per * self.bin_s
        pts = defaultdict(int)
        for k, v in self.per_second.items():
            pts[k // per] += v
        n = last // per + 1
        return {"bucket_s": round(bucket, 6),
                "points": [(round(i * bucket, 6), pts.get(i, 0) * 8 / bucket) for i in range(n)]}

    def top_talkers(self, n: int = 10) -> list:
        hosts = set(self.host_tx) | set(self.host_rx)
        rows = [{"host": h, "tx_bytes": self.host_tx.get(h, 0), "rx_bytes": self.host_rx.get(h, 0)}
                for h in hosts]
        for r in rows:
            r["total_bytes"] = r["tx_bytes"] + r["rx_bytes"]
            r["share"] = r["total_bytes"] / (2 * self.bytes) if self.bytes else 0
        rows.sort(key=lambda r: -r["total_bytes"])
        return rows[:n]

    def top_conversations(self, n: int = 10) -> list:
        rows = sorted(self.conversations.values(), key=lambda r: -r["bytes"])[:n]
        out = []
        for r in rows:
            dur = r["last_ts"] - r["first_ts"]
            out.append({**r, "duration_s": round(dur, 3),
                        "avg_mbps": round(r["bytes"] * 8 / dur / 1e6, 3) if dur > 0 else None})
        return out

    def icmp_summary(self) -> list:
        rows = []
        for (proto, typ, code), row in sorted(self.icmp.items(), key=lambda kv: -kv[1]["count"]):
            name = ICMP_NAMES.get((proto, typ), f"type {typ}")
            if proto == "ICMP" and typ == 3:
                name += f": {UNREACH_CODES.get(code, f'code {code}')}"
            rows.append({"proto": proto, "type": typ, "code": code, "name": name,
                         "count": row["count"], "examples": row["examples"]})
        return rows
