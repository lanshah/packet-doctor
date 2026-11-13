"""DNS transaction analysis (UDP port 53).

Queries are matched to responses on (client IP, client port, resolver IP,
transaction ID). A query without a response is a *timeout* only if the capture
kept running for at least ``timeout`` seconds afterwards; otherwise we cannot
tell and say so.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import dpkt

from .reader import Packet

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
          5: "REFUSED"}
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

# NXDOMAIN answers that are normal client behaviour, not faults.
_RANDOM_PROBE = re.compile(r"^[a-z]{7,15}$")          # Chromium intranet-redirect probes
_BENIGN_SUFFIXES = (".local", ".lan", ".home", ".localdomain", ".internal",
                    ".home.arpa", ".in-addr.arpa", ".ip6.arpa")


def nxdomain_is_benign(name: str) -> Optional[str]:
    n = name.lower().rstrip(".")
    if _RANDOM_PROBE.match(n):
        return "single random label: browser probe for DNS hijacking, expected to fail"
    if "." not in n:
        return "single-label name: usually a search-list or NetBIOS-style lookup"
    if n.startswith("wpad.") or n == "wpad":
        return "WPAD proxy auto-discovery, normally fails on home networks"
    if n.endswith(_BENIGN_SUFFIXES):
        return "local/reverse zone that public resolvers do not know"
    return None


@dataclass
class DNSTransaction:
    client: str
    server: str
    txid: int
    name: str
    qtype: str
    query_frame: int
    query_ts: float
    retries: int = 0
    response_frame: int = 0
    response_ts: Optional[float] = None
    rcode: Optional[str] = None
    answers: int = 0
    truncated: bool = False
    status: str = "pending"   # ok / nxdomain / servfail / refused / error / timeout / unanswered

    @property
    def latency(self) -> Optional[float]:
        return None if self.response_ts is None else self.response_ts - self.query_ts


@dataclass
class DNSAnalyzer:
    timeout: float = 2.0
    transactions: list = field(default_factory=list)
    pending: dict = field(default_factory=dict)
    malformed: int = 0
    unmatched_responses: int = 0
    tcp_dns_packets: int = 0
    dot_packets: int = 0
    mdns_llmnr_packets: int = 0

    def process(self, pkt: Packet) -> None:
        if pkt.proto == "TCP":
            if pkt.sport == 53 or pkt.dport == 53:
                self.tcp_dns_packets += 1
            elif pkt.sport == 853 or pkt.dport == 853:
                self.dot_packets += 1
            return
        if pkt.proto != "UDP":
            return
        if pkt.sport in (5353, 5355) or pkt.dport in (5353, 5355):
            self.mdns_llmnr_packets += 1
            return
        if pkt.sport != 53 and pkt.dport != 53:
            return
        try:
            msg = dpkt.dns.DNS(pkt.payload)
        except Exception:
            self.malformed += 1
            return
        if msg.qr == dpkt.dns.DNS_Q:
            if not msg.qd:
                return
            q = msg.qd[0]
            key = (pkt.src, pkt.sport, pkt.dst, msg.id)
            existing = self.pending.get(key)
            if existing and existing.name == q.name:
                existing.retries += 1     # client re-sent the same query
                return
            if existing:                  # same ID reused for a new name: settle the old one
                existing.status = "timeout" if pkt.ts - existing.query_ts >= self.timeout else "unanswered"
            t = DNSTransaction(client=pkt.src, server=pkt.dst, txid=msg.id,
                               name=q.name, qtype=QTYPES.get(q.type, str(q.type)),
                               query_frame=pkt.no, query_ts=pkt.ts)
            self.pending[key] = t
            self.transactions.append(t)
        else:
            key = (pkt.dst, pkt.dport, pkt.src, msg.id)
            t = self.pending.pop(key, None)
            if t is None:
                self.unmatched_responses += 1
                return
            t.response_frame, t.response_ts = pkt.no, pkt.ts
            rc = msg.rcode
            t.rcode = RCODES.get(rc, f"RCODE{rc}")
            t.answers = len(msg.an)
            t.truncated = bool(msg.op & dpkt.dns.DNS_TC) if hasattr(dpkt.dns, "DNS_TC") else False
            t.status = {0: "ok", 2: "servfail", 3: "nxdomain", 5: "refused"}.get(rc, "error")

    def finish(self, capture_end: float) -> None:
        for t in self.pending.values():
            t.status = "timeout" if capture_end - t.query_ts >= self.timeout else "unanswered"
        self.pending.clear()

    # ---------------------------------------------------------------- summaries
    def by_server(self) -> list:
        out = {}
        for t in self.transactions:
            s = out.setdefault(t.server, {"server": t.server, "queries": 0, "answered": 0,
                                          "failures": 0, "nxdomain": 0, "timeouts": 0,
                                          "latencies": []})
            s["queries"] += 1
            if t.latency is not None:
                s["answered"] += 1
                s["latencies"].append(t.latency)
            if t.status in ("servfail", "refused", "error"):
                s["failures"] += 1
            elif t.status == "nxdomain":
                s["nxdomain"] += 1
            elif t.status == "timeout":
                s["timeouts"] += 1
        rows = []
        for s in out.values():
            lat = sorted(s.pop("latencies"))
            s["median_ms"] = round(_pct(lat, 50) * 1000, 1) if lat else None
            s["p95_ms"] = round(_pct(lat, 95) * 1000, 1) if lat else None
            s["max_ms"] = round(lat[-1] * 1000, 1) if lat else None
            rows.append(s)
        rows.sort(key=lambda r: -r["queries"])
        return rows


def _pct(sorted_vals: list, p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)
