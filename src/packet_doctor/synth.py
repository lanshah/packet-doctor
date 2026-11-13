"""Synthetic captures with injected faults and a known ground truth.

Each scenario simulates hosts talking through a capture point and records,
while it writes the frames, exactly which frames carry an injected event
(lost/retransmitted segment, duplicate ACK, zero window, DNS failure ...).
The tests then score Packet Doctor against that truth, and ``judge.py`` scores
it against Wireshark on the same files.

Run ``packet-doctor make-samples samples/`` to regenerate the corpus.
"""
from __future__ import annotations

import json
import os
import socket
import struct
from typing import Optional

import dpkt

T0 = 1_763_100_000.0      # fixed epoch so files are reproducible
CLIENT = "192.168.1.50"
GATEWAY_DNS = "192.168.1.1"
MAC_C = b"\x02\x00\x00\x00\x00\x01"
MAC_R = b"\x02\x00\x00\x00\x00\xfe"


def _ip(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6 if ":" in addr else socket.AF_INET, addr)


class Capture:
    """Collects frames and the ground truth for one scenario."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.frames: list = []           # (ts, bytes)
        self.truth: dict = {"events": {}, "expect_findings": [], "forbid_findings": [],
                            "expect_cause": None, "notes": []}
        self._ip_id = 0x1000

    def next_id(self) -> int:
        self._ip_id = (self._ip_id + 1) & 0xFFFF or 1
        return self._ip_id

    def mark(self, event: str, frame: int) -> None:
        self.truth["events"].setdefault(event, []).append(frame)

    def add(self, ts: float, frame: bytes) -> int:
        """Store a frame; returns a provisional id that ``write`` maps to the final
        frame number after sorting frames into time order."""
        self.frames.append((ts, frame))
        return len(self.frames)

    def ip_packet(self, src, dst, proto_obj, proto_num, ip_id=None, ttl=64, df=True):
        if ":" in src:
            ip = dpkt.ip6.IP6(src=_ip(src), dst=_ip(dst), nxt=proto_num, hlim=ttl, data=proto_obj)
            ip.plen = len(bytes(proto_obj))
            etype = dpkt.ethernet.ETH_TYPE_IP6
        else:
            ip = dpkt.ip.IP(src=_ip(src), dst=_ip(dst), p=proto_num, ttl=ttl,
                            id=self.next_id() if ip_id is None else ip_id,
                            df=1 if df else 0, data=proto_obj)
            etype = dpkt.ethernet.ETH_TYPE_IP
        out_mac = src == CLIENT or src.startswith("2001:db8:1::")
        eth = dpkt.ethernet.Ethernet(src=MAC_C if out_mac else MAC_R, dst=MAC_R if out_mac else MAC_C,
                                     type=etype, data=ip)
        return bytes(eth), ip

    def write(self, directory: str, fmt: str = "pcap") -> str:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{self.name}.{fmt}")
        with open(path, "wb") as f:
            w = dpkt.pcap.Writer(f, snaplen=65535) if fmt == "pcap" else dpkt.pcapng.Writer(f, snaplen=65535)
            order = sorted(range(len(self.frames)), key=lambda i: (self.frames[i][0], i))
            remap = {}
            for final, i in enumerate(order, 1):
                ts, fr = self.frames[i]
                remap[i + 1] = final
                w.writepkt(fr, ts=ts)
        truth = dict(self.truth)
        truth["events"] = {k: sorted(remap[x] for x in v) for k, v in self.truth["events"].items()}
        truth["scenario"] = self.name
        truth["description"] = self.description
        truth["frames"] = len(self.frames)
        with open(os.path.join(directory, f"{self.name}.truth.json"), "w", encoding="utf-8") as f:
            json.dump(truth, f, indent=2)
        return path


class TCP:
    """One simulated TCP connection seen from a capture point.

    Times passed in are capture-point times. ``rtt`` is the round trip between
    the capture point and the far host.
    """

    def __init__(self, cap: Capture, client: str, cport: int, server: str, sport: int,
                 rtt: float = 0.020, c_isn: int = 1000, s_isn: int = 50000, mss: int = 1460,
                 c_win: int = 1024, s_win: int = 1024, wscale: Optional[int] = 6):
        self.cap, self.client, self.cport, self.server, self.sport = cap, client, cport, server, sport
        self.rtt, self.mss = rtt, mss
        self.c_isn, self.s_isn = c_isn, s_isn
        self.cseq, self.sseq = c_isn, s_isn          # next sequence number each side will send
        self.c_ack, self.s_ack = 0, 0                # ack value each side last sent
        self.c_win, self.s_win = c_win, s_win
        self.wscale = wscale

    # -- raw segment
    def seg(self, ts, from_client, flags, payload=b"", seq=None, ack=None, win=None, opts=b"",
            ip_id=None, ip_len_zero=False):
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        if seq is None:
            seq = self.cseq if from_client else self.sseq
        if ack is None:
            ack = self.c_ack if from_client else self.s_ack
        if win is None:
            win = self.c_win if from_client else self.s_win
        tcp = dpkt.tcp.TCP(sport=sp, dport=dp, seq=seq & 0xFFFFFFFF, ack=ack & 0xFFFFFFFF,
                           flags=flags, win=win, opts=opts, data=payload)
        tcp.off = (20 + len(opts)) // 4
        frame, ip = self.cap.ip_packet(src, dst, tcp, dpkt.ip.IP_PROTO_TCP, ip_id=ip_id)
        if ip_len_zero and isinstance(ip, dpkt.ip.IP):
            raw = bytearray(frame)
            raw[16:18] = b"\x00\x00"      # total length 0, as written by TSO on Linux
            frame = bytes(raw)
        return self.cap.add(ts, frame)

    @staticmethod
    def _syn_opts(mss, wscale):
        o = struct.pack("!BBH", 2, 4, mss)
        if wscale is not None:
            o += b"\x01" + struct.pack("!BBB", 3, 3, wscale)
        o += b"\x04\x02\x01\x01"     # SACK permitted + 2 NOPs  -> 12 bytes
        return o if len(o) % 4 == 0 else o + b"\x01" * (4 - len(o) % 4)

    def handshake(self, ts: float, server_side: Optional[float] = None, client_side: float = 0.0003):
        """SYN, SYN/ACK, ACK. Returns the time of the final ACK."""
        server_side = self.rtt if server_side is None else server_side
        A, S = dpkt.tcp.TH_ACK, dpkt.tcp.TH_SYN
        self.seg(ts, True, S, seq=self.c_isn, ack=0, win=64240, opts=self._syn_opts(self.mss, self.wscale))
        self.cseq = self.c_isn + 1
        self.s_ack = self.cseq
        t2 = ts + server_side
        self.seg(t2, False, S | A, seq=self.s_isn, ack=self.s_ack, win=65160,
                 opts=self._syn_opts(self.mss, self.wscale))
        self.sseq = self.s_isn + 1
        self.c_ack = self.sseq
        t3 = t2 + client_side
        self.seg(t3, True, A)
        return t3

    def send(self, ts, from_client, data: bytes, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, **kw):
        f = self.seg(ts, from_client, flags, payload=data, **kw)
        if from_client:
            self.cseq += len(data)
            self.s_ack = self.cseq
        else:
            self.sseq += len(data)
            self.c_ack = self.sseq
        return f

    def ack(self, ts, from_client, **kw):
        return self.seg(ts, from_client, dpkt.tcp.TH_ACK, **kw)

    def close(self, ts, client_first=True):
        A, F = dpkt.tcp.TH_ACK, dpkt.tcp.TH_FIN
        first = client_first
        self.seg(ts, first, F | A)
        if first:
            self.cseq += 1
            self.s_ack = self.cseq
        else:
            self.sseq += 1
            self.c_ack = self.sseq
        t = ts + self.rtt
        self.seg(t, not first, F | A)
        if first:
            self.sseq += 1
            self.c_ack = self.sseq
        else:
            self.cseq += 1
            self.s_ack = self.cseq
        self.seg(t + 0.0002, first, A)
        return t + 0.0002

    def download(self, ts, nseg: int, lose=(), spurious=(), burst: int = 10, gap: float = 0.0004):
        """Server sends ``nseg`` full segments to the client; capture is at the client.

        ``lose``: indexes of segments lost *before* the capture point. Every
        later segment triggers an immediate (duplicate) ACK and the missing
        segment is retransmitted one RTT later.
        ``spurious``: indexes the server re-sends although the client already
        ACKed them (the ACK was lost after the capture point).
        """
        cap = self.cap
        payload = b"\x17" * self.mss
        lose, spurious = set(lose), set(spurious)
        AP = dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH
        t = ts
        last_ack = self.c_ack
        highest_end = self.sseq
        for start in range(0, nseg, burst):
            holes, sp_seqs, since, last_t = [], [], 0, t
            for j in range(start, min(nseg, start + burst)):
                seq = self.sseq
                self.sseq += self.mss
                tt = t + (j - start) * gap
                last_t = tt
                if j in spurious:
                    sp_seqs.append(seq)
                if j in lose:
                    holes.append(seq)
                    continue
                f = self.seg(tt, False, AP, payload=payload, seq=seq, ack=self.s_ack)
                if seq != highest_end:
                    cap.mark("lost_segment", f)
                highest_end = seq + self.mss
                if holes:
                    fa = self.ack(tt + 0.0001, True, ack=holes[0])
                    if last_ack == holes[0]:
                        cap.mark("duplicate_ack", fa)
                    last_ack = holes[0]
                else:
                    since += 1
                    if since == 2:
                        self.ack(tt + 0.0001, True, ack=seq + self.mss)
                        last_ack = seq + self.mss
                        since = 0
            end_t = last_t
            if holes:
                tr = last_t + self.rtt + 0.002
                for h in holes:
                    fr = self.seg(tr, False, AP, payload=payload, seq=h, ack=self.s_ack)
                    cap.mark("retransmission", fr)
                    end_t = tr
                    tr += gap
            if holes or since:
                self.ack(end_t + 0.0001, True, ack=self.sseq)
                last_ack = self.sseq
                end_t += 0.0001
            for sq in sp_seqs:
                tsp = end_t + 0.003
                fr = self.seg(tsp, False, AP, payload=payload, seq=sq, ack=self.s_ack)
                cap.mark("retransmission", fr)
                cap.mark("spurious_retransmission", fr)
                fa = self.ack(tsp + 0.0001, True, ack=self.sseq)
                cap.mark("duplicate_ack", fa)
                end_t = tsp + 0.0001
            t = end_t + self.rtt
        self.c_ack = self.sseq
        return t


def _dns_query(name: str, txid: int, qtype=dpkt.dns.DNS_A) -> bytes:
    d = dpkt.dns.DNS(id=txid, qr=dpkt.dns.DNS_Q, opcode=0, rd=1)
    d.qd = [dpkt.dns.DNS.Q(name=name, type=qtype, cls=dpkt.dns.DNS_IN)]
    return bytes(d)


def _dns_response(name: str, txid: int, rcode=0, addr="93.184.216.34") -> bytes:
    d = dpkt.dns.DNS(id=txid, qr=dpkt.dns.DNS_R, opcode=0, rd=1, ra=1, rcode=rcode)
    d.qd = [dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]
    if rcode == 0:
        d.an = [dpkt.dns.DNS.RR(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN, ttl=300,
                                rdata=socket.inet_aton(addr))]
    return bytes(d)


def dns_exchange(cap: Capture, ts: float, name: str, txid: int, latency: Optional[float],
                 rcode: int = 0, server: str = GATEWAY_DNS, client: str = CLIENT, sport: int = 50000,
                 retries: int = 0):
    """Returns (query_frame, response_frame or None)."""
    def udp(src, dst, sp, dp, payload):
        u = dpkt.udp.UDP(sport=sp, dport=dp, data=payload)
        u.ulen = 8 + len(payload)
        frame, _ = cap.ip_packet(src, dst, u, dpkt.ip.IP_PROTO_UDP, df=False)
        return frame
    q = cap.add(ts, udp(client, server, sport, 53, _dns_query(name, txid)))
    for k in range(retries):
        cap.add(ts + 1.0 * (k + 1), udp(client, server, sport, 53, _dns_query(name, txid)))
    if latency is None:
        return q, None
    r = cap.add(ts + latency, udp(server, client, 53, sport, _dns_response(name, txid, rcode)))
    return q, r


def client_hello(sni: str, versions=(0x0304, 0x0303)) -> bytes:
    def ext(t, data):
        return struct.pack("!HH", t, len(data)) + data
    name = sni.encode()
    sni_ext = ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    alpn = b"\x02h2\x08http/1.1"
    alpn_ext = ext(16, struct.pack("!H", len(alpn)) + alpn)
    sv = b"".join(struct.pack("!H", v) for v in versions)
    sv_ext = ext(43, bytes([len(sv)]) + sv)
    exts = sni_ext + alpn_ext + sv_ext
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x20" + b"\x22" * 32 + b"\x00\x04\x13\x01\x13\x02"
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def server_hello(version=0x0304, cipher=0x1301) -> bytes:
    exts = b""
    if version == 0x0304:
        exts = struct.pack("!HHH", 43, 2, 0x0304)
    body = (struct.pack("!H", min(version, 0x0303)) + b"\x33" * 32 + b"\x20" + b"\x22" * 32 + struct.pack("!H", cipher) + b"\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    rec = b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs
    if version == 0x0304:
        rec += b"\x14\x03\x03\x00\x01\x01"                       # CCS (compat)
        rec += b"\x17\x03\x03\x00\x40" + b"\xaa" * 64             # encrypted extensions etc.
    return rec


def tls_session(conn: TCP, ts: float, sni: str, version=0x0304, server_delay=0.0,
                request=600, response=4000) -> float:
    """TLS handshake plus one request/response over an established connection."""
    conn.send(ts, True, client_hello(sni))
    t = ts + conn.rtt + server_delay
    sh = server_hello(version)
    conn.send(t, False, sh)
    t += 0.0003
    if version == 0x0304:
        conn.send(t, True, b"\x14\x03\x03\x00\x01\x01" + b"\x17\x03\x03\x00\x35" + b"\xbb" * 53)
    else:
        conn.send(t, True, b"\x16\x03\x03\x00\x25" + b"\x10" * 37 + b"\x14\x03\x03\x00\x01\x01"
                  + b"\x16\x03\x03\x00\x28" + b"\xcc" * 40)
        t += conn.rtt
        conn.send(t, False, b"\x14\x03\x03\x00\x01\x01" + b"\x16\x03\x03\x00\x28" + b"\xdd" * 40)
    t += 0.0002
    conn.send(t, True, b"\x17\x03\x03" + struct.pack("!H", request) + b"\xee" * request)
    t += conn.rtt
    left = response
    while left > 0:
        n = min(conn.mss - 5, left)
        conn.send(t, False, b"\x17\x03\x03" + struct.pack("!H", n) + b"\xff" * n)
        left -= n
        t += 0.0003
    conn.ack(t, True)
    return t


# ============================================================== scenarios
def sc_healthy() -> Capture:
    cap = Capture("healthy_browsing", "Normal browsing: fast DNS, three TLS 1.3 sessions (one over IPv6), "
                                      "small downloads, clean closes. Nothing should be flagged.")
    t = T0
    sites = [("www.example.com", "93.184.216.34", 0.018), ("news.example.org", "198.51.100.20", 0.024),
             ("cdn.example.net", "203.0.113.80", 0.012)]
    for k, (name, ip, rtt) in enumerate(sites):
        dns_exchange(cap, t, name, 0x100 + k, 0.012, sport=51000 + k)
        t += 0.02
        c = TCP(cap, CLIENT, 52000 + k, ip, 443, rtt=rtt, c_isn=1000 + 7919 * k, s_isn=90000 + 104729 * k)
        t = c.handshake(t)
        t = tls_session(c, t + 0.001, name)
        t = c.download(t + 0.001, 20)
        t = c.close(t + 0.05)
        t += 0.1
    v6 = TCP(cap, "2001:db8:1::50", 52100, "2001:db8:2::10", 443, rtt=0.015, c_isn=7000, s_isn=8000)
    t = v6.handshake(t)
    t = tls_session(v6, t + 0.001, "v6.example.com")
    t = v6.close(t + 0.05)
    cap.truth["forbid_findings"] = ["tcp_loss", "tcp_zero_window", "tcp_connect_fail", "tcp_slow_response",
                                    "dns_failures", "dns_slow", "tls_alerts", "tcp_high_rtt"]
    cap.truth["expect_health"] = "healthy"
    cap.truth["tls_sni"] = [s[0] for s in sites] + ["v6.example.com"]
    return cap


def _bulk_with_loss(name, desc, loss_plan, expect_cause, spurious_plan=None):
    cap = Capture(name, desc)
    t = T0
    servers = ["203.0.113.10", "198.51.100.25", "192.0.2.77", "203.0.113.99"]
    for k, ip in enumerate(servers):
        c = TCP(cap, CLIENT, 53000 + k, ip, 443, rtt=0.030, c_isn=3000 + 1000 * k, s_isn=700000 + 99991 * k)
        t = c.handshake(t)
        c.send(t + 0.001, True, b"\x17\x03\x03\x01\x00" + b"\x01" * 256)
        t = c.download(t + 0.001 + c.rtt, 80, lose=loss_plan.get(k, ()),
                       spurious=(spurious_plan or {}).get(k, ()))
        t = c.close(t + 0.01)
        t += 0.05
    cap.truth["expect_findings"] = ["tcp_loss"]
    cap.truth["forbid_findings"] = ["tcp_zero_window", "tcp_connect_fail", "capture_drops"]
    cap.truth["expect_cause"] = expect_cause
    return cap


def sc_loss_one_server() -> Capture:
    return _bulk_with_loss(
        "loss_one_server",
        "Four bulk downloads; only the one from 203.0.113.10 loses packets (5 of 80 segments). "
        "Expected: loss finding, cause = path/server-side for 203.0.113.10, not the local link.",
        {0: (12, 13, 37, 55, 71)}, "path to 203.0.113.10")


def sc_loss_local() -> Capture:
    return _bulk_with_loss(
        "loss_local_link",
        "Four bulk downloads from four unrelated servers all lose packets, plus one spurious "
        "retransmission. Expected: loss finding, cause = the client's local link (e.g. Wi-Fi).",
        {0: (15, 44), 1: (8, 52, 66), 2: (21, 22), 3: (30, 61)}, "local link",
        spurious_plan={1: (25,)})


def sc_zero_window() -> Capture:
    cap = Capture("zero_window", "Download where the client application stops reading: shrinking window, "
                                 "zero window for ~1.6 s with probes, then a window update. Expected: critical "
                                 "zero-window finding blaming the client host, not the network.")
    t = T0
    c = TCP(cap, CLIENT, 54000, "198.51.100.40", 80, rtt=0.025, wscale=None, c_win=8760, s_win=29200)
    t = c.handshake(t)
    c.send(t + 0.001, True, b"GET /big.iso HTTP/1.1\r\nHost: files.example\r\n\r\n")
    t += 0.001 + c.rtt
    pl = b"\x42" * 1460
    # fill the 8760-byte window exactly: 6 segments, last one is "window full"
    for i in range(6):
        f = c.send(t + i * 0.0004, False, pl)
        if i == 5:
            cap.mark("window_full", f)
    t += 6 * 0.0004
    f = c.ack(t + 0.0002, True, win=0)
    cap.mark("zero_window", f)
    # probes from the server; client answers with window 0
    for dt in (0.2, 0.6, 1.4):
        fp = c.seg(t + dt, False, dpkt.tcp.TH_ACK, payload=b"\x42", seq=c.sseq)
        cap.mark("zero_window_probe", fp)
        fa = c.ack(t + dt + 0.0003, True, win=0)
        cap.mark("zero_window", fa)
        cap.mark("zero_window_probe_ack", fa)
    t += 1.6
    fu = c.ack(t, True, win=8760)
    cap.mark("window_update", fu)
    t += c.rtt
    for i in range(6):
        f = c.send(t + i * 0.0004, False, pl)
        if i == 5:            # the refill reaches the window edge again
            cap.mark("window_full", f)
    t += 0.003
    c.ack(t, True, win=8760)
    t = c.close(t + 0.01)
    cap.truth["expect_findings"] = ["tcp_zero_window"]
    cap.truth["forbid_findings"] = ["tcp_loss", "tcp_connect_fail"]
    cap.truth["expect_cause"] = "not reading"
    return cap


def sc_slow_server() -> Capture:
    cap = Capture("slow_server", "Fast network (20 ms RTT) but the server takes 1.8 s to answer an HTTP "
                                 "request, while a second server answers in 40 ms. Expected: slow-response "
                                 "finding pointing at the server, not the network.")
    t = T0
    a = TCP(cap, CLIENT, 55000, "203.0.113.30", 80, rtt=0.020)
    t = a.handshake(t)
    req = a.send(t + 0.001, True, b"GET /report HTTP/1.1\r\nHost: app.example\r\n\r\n")
    a.ack(t + 0.001 + a.rtt, False)
    resp = a.send(t + 0.001 + 1.8, False, b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + b"x" * 1000)
    cap.mark("slow_response", resp)
    a.ack(t + 1.802 + 0.0002, True)
    t = a.close(t + 1.9)
    b = TCP(cap, CLIENT, 55001, "198.51.100.31", 80, rtt=0.022, c_isn=40000, s_isn=80000)
    t = b.handshake(t + 0.05)
    b.send(t + 0.001, True, b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n")
    b.send(t + 0.001 + b.rtt + 0.040, False, b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n" + b"y" * 500)
    b.ack(t + 0.07, True)
    t = b.close(t + 0.1)
    # TLS 1.3 style: the server's session tickets (small, immediate) come before the
    # real reply, which arrives 900 ms later. The delay must still be measured.
    s = TCP(cap, CLIENT, 55002, "192.0.2.33", 443, rtt=0.018, c_isn=60000, s_isn=70000)
    t = s.handshake(t + 0.05)
    s.send(t + 0.001, True, client_hello("tickets.example.com"))
    s.send(t + 0.001 + s.rtt, False, server_hello(0x0304))
    t += 0.002 + s.rtt
    s.send(t + 0.001, True, b"\x17\x03\x03\x01\x00" + b"\x01" * 256)
    s.send(t + 0.001 + s.rtt, False, b"\x17\x03\x03\x00\xfa" + b"\x02" * 250)     # session ticket
    s.ack(t + 0.001 + s.rtt + 0.0002, True)
    late = s.send(t + 0.001 + 0.9, False, b"\x17\x03\x03\x05\x00" + b"\x03" * 1280)
    cap.mark("slow_response", late)
    s.ack(t + 0.902, True)
    t = s.close(t + 1.0)
    cap.truth["expect_findings"] = ["tcp_slow_response"]
    cap.truth["forbid_findings"] = ["tcp_loss", "tcp_zero_window", "tcp_high_rtt"]
    cap.truth["expect_cause"] = "processing"
    return cap


def sc_dns() -> Capture:
    cap = Capture("dns_problems", "Resolver 192.168.1.1: two SERVFAILs for one domain, one timeout, one slow "
                                  "(650 ms) answer, a real NXDOMAIN, a benign browser-probe NXDOMAIN, and "
                                  "normal fast lookups. Expected: DNS failure, NXDOMAIN and slow-DNS findings.")
    t = T0
    tx = 0x2000
    for k, name in enumerate(["www.example.com", "mail.example.com", "api.example.net", "img.example.org"]):
        dns_exchange(cap, t, name, tx + k, 0.015, sport=56000 + k)
        t += 0.1
    q, r = dns_exchange(cap, t, "broken.example.net", 0x3001, 0.040, rcode=2, sport=56100)
    cap.mark("dns_servfail", q)
    t += 0.2
    q, r = dns_exchange(cap, t, "broken.example.net", 0x3002, 0.045, rcode=2, sport=56101)
    cap.mark("dns_servfail", q)
    t += 0.2
    q, _ = dns_exchange(cap, t, "slow.example.org", 0x3003, None, sport=56102, retries=1)
    cap.mark("dns_timeout", q)
    t += 0.3
    q, r = dns_exchange(cap, t, "far.example.com", 0x3004, 0.650, sport=56103)
    cap.mark("dns_slow", q)
    t += 0.8
    q, r = dns_exchange(cap, t, "intranet.exampel-typo.com", 0x3005, 0.030, rcode=3, sport=56104)
    cap.mark("dns_nxdomain", q)
    t += 0.1
    q, r = dns_exchange(cap, t, "qwhjzkxlpd", 0x3006, 0.020, rcode=3, sport=56105)
    cap.mark("dns_nxdomain", q)
    t += 3.0
    dns_exchange(cap, t, "www.example.com", 0x3007, 0.010, sport=56106)
    cap.truth["expect_findings"] = ["dns_failures", "dns_nxdomain", "dns_slow"]
    cap.truth["forbid_findings"] = ["tcp_loss"]
    cap.truth["expect_cause"] = "domain"
    cap.truth["notes"].append("Both SERVFAILs are for the same name while the resolver answers other names, so "
                              "the domain (not the resolver) is the most probable cause.")
    return cap


def sc_connect_fail() -> Capture:
    cap = Capture("connection_failures", "One port refuses (RST), one is silently dropped (SYN retried at 1 s and "
                                         "3 s, never answered), one connection works. Expected: connect-failure "
                                         "finding.")
    t = T0
    ok = TCP(cap, CLIENT, 57000, "203.0.113.50", 443, rtt=0.02)
    t = ok.handshake(t)
    t = ok.close(t + 0.1)
    r = TCP(cap, CLIENT, 57001, "203.0.113.50", 8080, rtt=0.02, c_isn=111)
    f = r.seg(t + 0.1, True, dpkt.tcp.TH_SYN, seq=111, ack=0, win=64240, opts=TCP._syn_opts(1460, 6))
    fr = r.seg(t + 0.12, False, dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK, seq=0, ack=112, win=0)
    cap.mark("refused", fr)
    d = TCP(cap, CLIENT, 57002, "198.51.100.60", 3389, rtt=0.02, c_isn=222)
    t2 = t + 0.3
    for k, dt in enumerate((0.0, 1.0, 3.0)):
        fs = d.seg(t2 + dt, True, dpkt.tcp.TH_SYN, seq=222, ack=0, win=64240, opts=TCP._syn_opts(1460, 6))
        cap.mark("syn_unanswered", fs)
        if k:
            cap.mark("retransmission", fs)
    dns_exchange(cap, t2 + 4.0, "www.example.com", 0x4444, 0.01)
    cap.truth["expect_findings"] = ["tcp_connect_fail"]
    cap.truth["forbid_findings"] = ["tcp_loss"]
    cap.truth["expect_cause"] = "not running/listening"   # the RST case; the silent drop is listed as "possible"
    return cap


def sc_artefacts() -> Capture:
    cap = Capture("capture_artefacts", "Upload captured on the sending host with TSO (segments of 14,600 bytes "
                                       "and IPv4 length 0), a download with packets missing from the capture "
                                       "but ACKed by the receiver, and duplicated frames from a mirror port. "
                                       "Expected: three capture-artefact findings and NO packet-loss finding.")
    t = T0
    up = TCP(cap, CLIENT, 58000, "203.0.113.70", 443, rtt=0.02, c_isn=5000, s_isn=6000)
    t = up.handshake(t)
    for i in range(8):
        f = up.send(t + i * 0.001, True, b"\x55" * 14600, ip_len_zero=(i % 2 == 1))
        cap.mark("tso_oversize", f)
        up.ack(t + i * 0.001 + up.rtt, False)
    t = up.close(t + 0.1)
    # capture drops: the client ACKs data that never appears in the file
    dn = TCP(cap, CLIENT, 58001, "198.51.100.71", 443, rtt=0.02, c_isn=9000, s_isn=19000)
    t = dn.handshake(t + 0.01)
    pl = b"\x66" * 1460
    for i in range(30):
        seq = dn.sseq
        dn.sseq += 1460
        tt = t + i * 0.0005
        if i in (9, 10, 21):          # on the wire, not in the capture
            continue
        f = dn.seg(tt, False, dpkt.tcp.TH_ACK, payload=pl, seq=seq)
        if i in (11, 22):
            cap.mark("lost_segment", f)
        if i % 2 == 1:
            fa = dn.ack(tt + 0.0001, True, ack=dn.sseq)
            if i in (11, 23):
                cap.mark("ack_lost_segment", fa)
    dn.c_ack = dn.sseq
    t = dn.close(t + 0.1)
    # mirror-port duplicates: identical frames (same IP ID) a few microseconds apart
    du = TCP(cap, CLIENT, 58002, "192.0.2.72", 80, rtt=0.02, c_isn=12000, s_isn=13000)
    t = du.handshake(t + 0.01)
    du.send(t + 0.001, True, b"GET / HTTP/1.1\r\n\r\n")
    for i in range(4):
        seq = du.sseq
        tt = t + du.rtt + i * 0.0005
        f1 = du.seg(tt, False, dpkt.tcp.TH_ACK, payload=pl, seq=seq, ip_id=0x7000 + i)
        if i in (1, 2):
            f2 = du.seg(tt + 0.000004, False, dpkt.tcp.TH_ACK, payload=pl, seq=seq, ip_id=0x7000 + i)
            cap.mark("capture_duplicate", f2)
            cap.mark("retransmission", f2)   # what Wireshark calls it; PD must not count it as loss
        du.sseq += 1460
        du.c_ack = du.sseq
    du.ack(t + du.rtt + 0.003, True)
    t = du.close(t + 0.1)
    cap.truth["expect_findings"] = ["capture_offload", "capture_drops", "capture_duplicates"]
    cap.truth["forbid_findings"] = ["tcp_loss"]
    cap.truth["notes"].append("Wireshark will flag the duplicate frames as retransmissions; Packet Doctor "
                              "should recognise them as the same frame (same IP ID) and exclude them.")
    return cap


def sc_reorder() -> Capture:
    cap = Capture("reordering", "Download where pairs of segments arrive swapped within 0.5 ms (path "
                                "reordering, no loss). Expected: out-of-order flags but no loss finding.")
    t = T0
    c = TCP(cap, CLIENT, 59000, "203.0.113.90", 443, rtt=0.030)
    t = c.handshake(t)
    c.send(t + 0.001, True, b"\x17\x03\x03\x00\x20" + b"\x01" * 32)
    t += 0.001 + c.rtt
    pl = b"\x77" * 1460
    base = c.sseq
    order = list(range(40))
    for a in (6, 17, 29):
        order[a], order[a + 1] = order[a + 1], order[a]
    last_ack = None
    for pos, i in enumerate(order):
        f = c.seg(t + pos * 0.0004, False, dpkt.tcp.TH_ACK, payload=pl, seq=base + i * 1460)
        if pos > 0 and order[pos] < order[pos - 1]:
            cap.mark("out_of_order", f)
        if pos > 0 and i > max(order[:pos]) + 1:
            cap.mark("lost_segment", f)          # arrived ahead of the one it overtook
        if pos % 2 == 1:
            contiguous = next(k for k in range(41) if k not in order[:pos + 1])
            fa = c.ack(t + pos * 0.0004 + 0.0001, True, ack=base + contiguous * 1460)
            if last_ack == contiguous:
                cap.mark("duplicate_ack", fa)    # the gap kept the ACK from moving
            last_ack = contiguous
    c.sseq = base + 40 * 1460
    c.c_ack = c.sseq
    t = c.close(t + 0.05)
    cap.truth["expect_findings"] = []
    cap.truth["forbid_findings"] = ["tcp_loss"]
    return cap


def sc_high_latency() -> Capture:
    cap = Capture("high_latency", "Two servers: one 350 ms away (intercontinental), one 15 ms away; no loss. "
                                  "Expected: informational high-latency finding only.")
    t = T0
    far = TCP(cap, CLIENT, 60000, "198.51.100.200", 443, rtt=0.350)
    t = far.handshake(t)
    t = tls_session(far, t + 0.001, "far.example.com")
    t = far.close(t + 0.05)
    near = TCP(cap, CLIENT, 60001, "203.0.113.15", 443, rtt=0.015, c_isn=1234, s_isn=4321)
    t = near.handshake(t + 0.05)
    t = tls_session(near, t + 0.001, "near.example.my")
    t = near.close(t + 0.05)
    cap.truth["expect_findings"] = ["tcp_high_rtt"]
    cap.truth["forbid_findings"] = ["tcp_loss", "tcp_slow_response", "tls_slow"]
    return cap


def sc_tls_failure() -> Capture:
    cap = Capture("tls_failure", "Client rejects the server certificate (TLS alert unknown_ca) and a second "
                                 "server negotiates TLS 1.0. Expected: TLS failure and old-version findings.")
    t = T0
    c = TCP(cap, CLIENT, 61000, "203.0.113.120", 443, rtt=0.02)
    t = c.handshake(t)
    c.send(t + 0.001, True, client_hello("intranet.example.my"))
    c.send(t + 0.001 + c.rtt, False, server_hello(0x0303, 0xc02f)
           + b"\x16\x03\x03\x00\x30" + b"\x0b" + b"\x00\x00\x2c" + b"\x00" * 44)
    fa = c.send(t + 0.03, True, b"\x15\x03\x03\x00\x02\x02\x30")
    cap.mark("tls_alert", fa)
    t = c.close(t + 0.04)
    o = TCP(cap, CLIENT, 61001, "198.51.100.121", 443, rtt=0.02, c_isn=9999, s_isn=19999)
    t = o.handshake(t + 0.05)
    t = tls_session(o, t + 0.001, "legacy.example.com", version=0x0301)
    t = o.close(t + 0.05)
    cap.truth["expect_findings"] = ["tls_alerts", "tls_old_version"]
    cap.truth["forbid_findings"] = ["tcp_loss"]
    return cap


def sc_sender_side() -> Capture:
    cap = Capture("upload_fast_retransmit", "Upload captured on the sending client: one segment is lost after "
                                            "the capture point, the server sends three duplicate ACKs and the "
                                            "client fast-retransmits within 1 ms. Expected: fast retransmission "
                                            "flagged, loss located beyond the capture point.")
    t = T0
    c = TCP(cap, CLIENT, 62000, "203.0.113.140", 443, rtt=0.040)
    t = c.handshake(t)
    pl = b"\x88" * 1460
    base = c.cseq
    # first flight: 10 segments, #4 lost after capture point
    for i in range(10):
        c.seg(t + i * 0.0003, True, dpkt.tcp.TH_ACK, payload=pl, seq=base + i * 1460)
    c.cseq = base + 10 * 1460
    ta = t + c.rtt
    c.ack(ta, False, ack=base + 2 * 1460)
    c.ack(ta + 0.0006, False, ack=base + 4 * 1460)
    for k in range(4):                       # segments 5..9 arrive -> ACK=seg4 each time
        f = c.ack(ta + 0.0009 + k * 0.0003, False, ack=base + 4 * 1460)
        # every one repeats the previous ACK (ack=seg4 was already sent above), so all
        # four are duplicates. (v0 of this generator labelled only three; Wireshark
        # and Packet Doctor both counted four, which exposed the labelling mistake.)
        cap.mark("duplicate_ack", f)
    fr = c.seg(ta + 0.0009 + 3 * 0.0003 + 0.0005, True, dpkt.tcp.TH_ACK, payload=pl, seq=base + 4 * 1460)
    cap.mark("retransmission", fr)
    cap.mark("fast_retransmission", fr)
    c.ack(ta + c.rtt + 0.002, False, ack=c.cseq)
    t = c.close(ta + c.rtt + 0.01)
    # a clean second upload to another server for comparison
    d = TCP(cap, CLIENT, 62001, "198.51.100.141", 443, rtt=0.035, c_isn=777, s_isn=888)
    t = d.handshake(t + 0.05)
    for i in range(30):
        d.send(t + i * 0.0003, True, pl, flags=dpkt.tcp.TH_ACK)
        if i % 2:
            d.ack(t + i * 0.0003 + d.rtt, False)
    t = d.close(t + 0.1)
    cap.truth["expect_findings"] = ["tcp_loss"]
    cap.truth["forbid_findings"] = ["tcp_connect_fail", "capture_drops"]
    cap.truth["notes"].append("Only 1 retransmission: below the 3-retransmission noise floor, so the finding "
                              "is expected to be the informational 'tcp_loss_minor', not 'tcp_loss'.")
    cap.truth["expect_findings"] = ["tcp_loss_minor"]
    return cap


SCENARIOS = [sc_healthy, sc_loss_one_server, sc_loss_local, sc_zero_window, sc_slow_server, sc_dns,
             sc_connect_fail, sc_artefacts, sc_reorder, sc_high_latency, sc_tls_failure, sc_sender_side]


def make_samples(directory: str) -> list:
    paths = []
    for fn in SCENARIOS:
        cap = fn()
        paths.append(cap.write(directory, "pcap"))
    # the same scenario in pcapng format to exercise the second reader
    cap = sc_loss_one_server()
    cap.name = "loss_one_server_pcapng"
    paths.append(cap.write(directory, "pcapng"))
    return paths
