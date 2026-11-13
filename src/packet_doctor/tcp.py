"""TCP connection tracking and expert analysis.

The per-segment checks deliberately follow the same rules Wireshark uses in
``tcp_analyze_sequence_number()`` (packet-tcp.c) so an engineer can reconcile
Packet Doctor's numbers with what they see in Wireshark's Expert Info. On top
of those flags we compute things Wireshark leaves to the human: handshake RTT
split by side, application response time, zero-window duration, connection
outcome and capture-point artefacts.
"""
from __future__ import annotations

from array import array
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from .reader import Packet, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN

M32 = 0xFFFFFFFF
_EMPTY = ()         # shared stand-in for an empty deque (saves memory per connection)
HALF = 0x80000000

# Flag names match Wireshark's tcp.analysis.* field names.
FLAGS = (
    "retransmission", "fast_retransmission", "spurious_retransmission",
    "out_of_order", "lost_segment", "ack_lost_segment", "duplicate_ack",
    "zero_window", "zero_window_probe", "zero_window_probe_ack", "window_full",
    "window_update", "keep_alive", "keep_alive_ack",
)
EXAMPLES_PER_FLAG = 12
MAX_UNACKED = 10000          # same cap as Wireshark (TCP_MAX_UNACKED_SEGMENTS)

WELL_KNOWN_SERVER_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587,
    636, 853, 993, 995, 1433, 1521, 1883, 3306, 3389, 5060, 5061, 5432, 5671,
    5672, 5900, 6379, 8000, 8008, 8080, 8443, 8883, 9000, 9090, 9200, 27017,
}


def _gt(a: int, b: int) -> bool:
    d = (a - b) & M32
    return 0 < d < HALF


def _lt(a: int, b: int) -> bool:
    return _gt(b, a)


def _le(a: int, b: int) -> bool:
    return a == b or _gt(b, a)


class Direction:
    __slots__ = (
        "ip", "port", "base_seq", "nextseq", "nextseqtime", "nextseqframe",
        "maxseqtobeacked", "lastack", "lastacktime", "lastnondupack",
        "dupacknum", "window", "window_bytes", "win_scale", "lastsegflags",
        "packets", "bytes_wire", "data_segments", "data_bytes", "retrans_bytes", "retrans_segs", "dup_segs",
        "fin", "syn_seen", "mss", "sack_perm", "max_seg", "zw_start",
        "zw_total", "zw_max", "pending", "rtt_samples", "rtt_count", "rtt_sum",
        "rtt_min", "rtt_max", "recent_ids", "asm_next", "asm_done", "asm_bytes", "sack",
        "unacked", "unacked_live", "max_ack", "lastacklen",
        "last_data_ts", "last_data_frame", "first_ts", "last_ts",
    )

    def __init__(self, ip: str, port: int):
        self.ip, self.port = ip, port
        self.base_seq = None
        self.nextseq = None
        self.nextseqtime = 0.0
        self.nextseqframe = 0
        self.maxseqtobeacked = None
        self.lastack = None
        self.lastacktime = None
        self.lastnondupack = 0
        self.dupacknum = 0
        self.window = None          # raw window field of the last segment
        self.window_bytes = None    # window in bytes after scaling
        self.win_scale = -1         # -1 unknown, -2 not negotiated, >=0 shift
        self.lastsegflags = frozenset()
        self.packets = 0
        self.bytes_wire = 0
        self.data_segments = 0
        self.data_bytes = 0
        self.retrans_bytes = 0
        self.retrans_segs = 0
        self.dup_segs = 0
        self.fin = False
        self.syn_seen = False
        self.mss = None
        self.sack_perm = False
        self.max_seg = 0
        self.zw_start = None
        self.zw_total = 0.0
        self.zw_max = 0.0
        self.pending = _EMPTY       # (end_seq, ts) of unacknowledged new data (deque when used)
        self.rtt_samples = []
        self.rtt_count = 0
        self.rtt_sum = 0.0
        self.rtt_min = None
        self.rtt_max = None
        self.recent_ids = {}        # seq -> (ip_id, ts) for duplicate-frame detection
        self.sack = ()              # SACK blocks of the last segment sent this way
        self.unacked = _EMPTY       # (seq, nextseq) sent this way, not yet ACKed (deque when used)
        self.unacked_live = 256     # size after the last compaction
        self.max_ack = None         # highest ACK the peer has sent for this direction
        self.lastacklen = 0         # length of the segment that last advanced nextseq
        self.asm_next = None
        self.asm_done = False
        self.asm_bytes = 0
        self.last_data_ts = None
        self.last_data_frame = 0
        self.first_ts = None
        self.last_ts = None


@dataclass
class Connection:
    index: int
    key: tuple
    a: Direction                       # first side seen
    b: Direction
    first_ts: float
    first_frame: int
    last_ts: float = 0.0
    client: Optional[Direction] = None  # side that sent the SYN (or best guess)
    syn_ts: Optional[float] = None
    syn_frame: int = 0
    syn_count: int = 0
    synack_ts: Optional[float] = None
    synack_frame: int = 0
    synack_count: int = 0
    hs_ack_ts: Optional[float] = None
    hs_ack_frame: int = 0
    irtt: Optional[float] = None       # Wireshark's tcp.analysis.initial_rtt
    syn_mru_ts: Optional[float] = None
    synack_last_ts: Optional[float] = None
    hs_server_side: Optional[float] = None
    hs_client_side: Optional[float] = None
    rst_frame: int = 0
    saw_fin_rst: bool = False
    rst_ts: Optional[float] = None
    rst_by: Optional[str] = None       # "client" / "server"
    rst_phase: Optional[str] = None    # "handshake" / "data" / "closing"
    counts: dict = field(default_factory=dict)
    dir_counts: dict = field(default_factory=dict)   # (flag, "c2s"/"s2c") -> n
    examples: dict = field(default_factory=dict)
    turns: list = field(default_factory=list)       # (req_frame, resp_frame, resp_ts, delay)
    turn_count: int = 0
    tso_frames: int = 0
    dup_frames: int = 0
    last_data_dir: Optional[Direction] = None
    turn_srv_bytes: int = 0
    cur_turn: Optional[tuple] = None   # (index in turns, request time) eligible for re-timing
    tls_seen: bool = False             # client sent a TLS handshake record
    frames: int = 0

    @property
    def server(self) -> Optional[Direction]:
        if self.client is None:
            return None
        return self.b if self.client is self.a else self.a

    def other(self, d: Direction) -> Direction:
        return self.b if d is self.a else self.a


class TCPAnalyzer:
    """Feed packets in capture order with :meth:`process`; read results after."""

    def __init__(self, stream_callback: Optional[Callable] = None,
                 asm_limit: int = 16384):
        self.conns: dict = {}
        self.all_conns: list = []
        self.flag_frames = {f: array("I") for f in FLAGS}
        self.rst_frames = array("I")
        self.stream_callback = stream_callback
        self.asm_limit = asm_limit
        self.segments = 0
        self.decision_log = None    # set to {} to record inputs of each retransmission decision

    # ------------------------------------------------------------------ helpers
    def _new_conn(self, key, pkt: Packet) -> Connection:
        a = Direction(pkt.src, pkt.sport)
        b = Direction(pkt.dst, pkt.dport)
        c = Connection(index=len(self.all_conns), key=key, a=a, b=b,
                       first_ts=pkt.ts, first_frame=pkt.no)
        self.conns[key] = c
        self.all_conns.append(c)
        return c

    def _flag(self, c: Connection, name: str, pkt: Packet, detail: str, fwd: Direction):
        self.flag_frames[name].append(pkt.no)
        c.counts[name] = c.counts.get(name, 0) + 1
        k = (name, "c2s" if fwd is c.client else "s2c")
        c.dir_counts[k] = c.dir_counts.get(k, 0) + 1
        ex = c.examples.setdefault(name, [])
        if len(ex) < EXAMPLES_PER_FLAG:
            ex.append((pkt.no, pkt.ts, detail))

    def _count(self, c: Connection, name: str, pkt: Packet, detail: str = ""):
        c.counts[name] = c.counts.get(name, 0) + 1
        ex = c.examples.setdefault(name, [])
        if len(ex) < EXAMPLES_PER_FLAG:
            ex.append((pkt.no, pkt.ts, detail))

    # ------------------------------------------------------------------ main
    def process(self, pkt: Packet) -> None:
        if pkt.proto != "TCP" or pkt.fragment or not pkt.src:
            return
        self.segments += 1
        fl = pkt.flags
        syn, fin, rst = fl & TCP_SYN, fl & TCP_FIN, fl & TCP_RST
        has_ack = fl & TCP_ACK
        ka = (pkt.src, pkt.sport)
        kb = (pkt.dst, pkt.dport)
        key = (ka, kb) if ka <= kb else (kb, ka)
        c = self.conns.get(key)
        if c is not None:
            fwd = c.a if (c.a.ip == pkt.src and c.a.port == pkt.sport) else c.b
            # Port reuse (same rule as Wireshark's tcp.stream numbering): a SYN or
            # SYN/ACK starts a new conversation if its ISN differs from the one we
            # know, or if the old conversation already saw a FIN or RST.
            if syn and fwd.base_seq is not None and (pkt.seq != fwd.base_seq or c.saw_fin_rst):
                c = None
            elif syn and not has_ack and fwd.base_seq is not None:
                fwd.nextseq = fwd.maxseqtobeacked     # same-ISN SYN retry (issue 17616)
        if c is None:
            c = self._new_conn(key, pkt)
        fwd = c.a if (c.a.ip == pkt.src and c.a.port == pkt.sport) else c.b
        rev = c.other(fwd)
        c.frames += 1
        c.last_ts = pkt.ts
        ts = pkt.ts
        seq = pkt.seq
        seglen = pkt.seglen
        win = pkt.win
        ack = pkt.ack if has_ack else None

        fwd.packets += 1
        fwd.bytes_wire += pkt.length
        if fwd.first_ts is None:
            fwd.first_ts = ts
        fwd.last_ts = ts
        if fwd.base_seq is None:
            fwd.base_seq = seq if syn else (seq - 1) & M32
        if rev.base_seq is None and has_ack:
            rev.base_seq = (pkt.ack - 1) & M32

        # ---- handshake bookkeeping
        if syn:
            fwd.syn_seen = True
            if pkt.mss:
                fwd.mss = pkt.mss
            fwd.sack_perm = fwd.sack_perm or pkt.sack_perm
            fwd.win_scale = pkt.wscale if pkt.wscale is not None else -2
            if not has_ack:
                c.syn_count += 1
                if c.syn_ts is None:
                    c.syn_ts, c.syn_frame = ts, pkt.no
                    c.client = fwd
            else:
                c.synack_count += 1
                # Split RTT from the *most recent* SYN to the *latest* SYN/ACK, so a
                # retried SYN does not inflate the server-side figure.
                c.synack_last_ts = ts
                if c.syn_mru_ts is not None:
                    c.hs_server_side = ts - c.syn_mru_ts
                if c.synack_ts is None:
                    c.synack_ts, c.synack_frame = ts, pkt.no
                    if c.client is None:
                        c.client = rev
                # Window scaling is only in effect if both sides offered it.
                if fwd.win_scale >= 0 and rev.win_scale >= 0:
                    pass
                elif rev.win_scale == -1:      # client SYN not captured
                    fwd.win_scale = -1
                else:
                    fwd.win_scale = rev.win_scale = -2
        elif (c.synack_ts is not None and c.hs_ack_ts is None and has_ack
              and fwd is c.client and ack == ((c.server.base_seq + 1) & M32)):
            c.hs_ack_ts, c.hs_ack_frame = ts, pkt.no
            c.hs_client_side = ts - c.synack_last_ts
        if c.client is None and c.frames == 1:
            c.client = self._guess_client(c, fwd, rev)

        if syn or fwd.win_scale < 0:
            wbytes = win
        else:
            wbytes = win << fwd.win_scale

        if rst:
            self.rst_frames.append(pkt.no)
            if c.rst_frame == 0:
                c.rst_frame, c.rst_ts = pkt.no, ts
                c.rst_by = "client" if fwd is c.client else "server"
                if c.synack_ts is None and c.syn_ts is not None:
                    c.rst_phase = "handshake"
                elif fwd.fin or rev.fin:
                    c.rst_phase = "closing"
                else:
                    c.rst_phase = "data"
        if fin:
            fwd.fin = True
        if fin or rst:
            c.saw_fin_rst = True
            if rst or (fwd.fin and rev.fin):
                for d in (fwd, rev):          # free per-connection working memory
                    d.recent_ids = {}
                    d.pending = _EMPTY

        # ---- Wireshark-equivalent sequence analysis
        # Mirrors tcp_analyze_sequence_number() in Wireshark 4.6
        # (epan/dissectors/packet-tcp.c), including its SACK handling, so that
        # frame numbers reconcile with Wireshark's Expert Info.
        ta = set()
        nextseq = fwd.nextseq
        sfr = fl & (TCP_SYN | TCP_FIN | TCP_RST)
        goto_finished = False

        if (seglen == 1 and nextseq is not None and seq == nextseq
                and rev.window is not None and rev.window == 0):
            ta.add("zero_window_probe")
            goto_finished = True
        if not goto_finished:
            if win == 0 and not sfr:
                ta.add("zero_window")
            if nextseq is not None and _gt(seq, nextseq) and not rst:
                ta.add("lost_segment")
            if (seglen in (0, 1) and nextseq is not None
                    and seq == ((nextseq - 1) & M32) and not sfr):
                ta.add("keep_alive")
                goto_finished = True
        if not goto_finished:
            same_seq_ack = (nextseq is not None and seq == nextseq
                            and ack is not None and ack == fwd.lastack)
            if (seglen == 0 and win and fwd.window is not None and win != fwd.window
                    and same_seq_ack and not sfr):
                if pkt.sack:
                    # "Late discovery of a false Window Update in presence of SACK":
                    # Wireshark re-labels it a duplicate ACK.
                    fwd.dupacknum += 1
                    ta.add("duplicate_ack")
                else:
                    ta.add("window_update")
                goto_finished = True
            if not goto_finished:
                if (seglen > 0 and rev.win_scale != -1 and rev.lastack is not None
                        and rev.window_bytes is not None and not sfr
                        and ((seq + seglen) & M32) == ((rev.lastack + rev.window_bytes) & M32)):
                    ta.add("window_full")
                if (seglen == 0 and win and win == fwd.window and same_seq_ack
                        and "keep_alive" in rev.lastsegflags and not sfr):
                    ta.add("keep_alive_ack")
                    goto_finished = True
            if not goto_finished:
                if (seglen == 0 and win == 0 and fwd.window == 0 and nextseq is not None
                        and seq == nextseq and ack is not None and fwd.lastack is not None
                        and (ack == fwd.lastack or ack == ((fwd.lastack + 1) & M32))
                        and "zero_window_probe" in rev.lastsegflags and not sfr):
                    ta.add("zero_window_probe_ack")
                    if ack == ((fwd.lastack + 1) & M32):
                        rev.nextseq = rev.maxseqtobeacked = ack
                    goto_finished = True
            if not goto_finished:
                if seglen == 0 and win and win == fwd.window and same_seq_ack and not sfr:
                    fwd.dupacknum += 1
                    ta.add("duplicate_ack")

        # finished_fwd:
        if ack != fwd.lastack:
            fwd.lastnondupack = pkt.no
            fwd.dupacknum = 0
        if (ack is not None and rev.maxseqtobeacked is not None
                and _gt(ack, rev.maxseqtobeacked)):
            if (fwd.lastack is not None and ack == ((fwd.lastack + 1) & M32)
                    and seq == fwd.nextseq and "zero_window_probe" in rev.lastsegflags):
                rev.nextseq = rev.maxseqtobeacked = ack
                ta.add("window_update")
            else:
                # Continue past contiguous segments we did see after the gap.
                tail_le = tail_re = None
                for s0, s1 in self._live_unacked(rev, reverse=True):
                    if tail_le == tail_re:
                        tail_le, tail_re = s0, s1
                    if s0 == ack or _gt(s0, ack):
                        if s1 == tail_le:
                            tail_le = s0
                        else:
                            tail_le, tail_re = s0, s1
                if tail_le is not None and ack == tail_le and _gt(tail_re, ack):
                    rev.maxseqtobeacked = tail_re
                else:
                    rev.maxseqtobeacked = ack
                ta.add("ack_lost_segment")

        retrans_kind = None
        if (seglen > 0 or fl & (TCP_SYN | TCP_FIN)) and "keep_alive" not in ta:
            seq_not_advanced = nextseq is not None and _lt(seq, nextseq)
            if seglen > 1 and nextseq is not None and ((nextseq - 1) & M32) == seq:
                seq_not_advanced = False
            end_data = (seq + seglen) & M32
            if seglen > 0 and rev.lastack and _le(end_data, rev.lastack):
                retrans_kind = "spurious_retransmission"
            elif seq_not_advanced:
                # Time since the peer's last segment (not since our last new data).
                t = max(0.0, ts - rev.lastacktime) if rev.lastacktime is not None else float("inf")
                in_sack = any(_le(l, seq) and _le(end_data, r) for l, r in rev.sack[:4])
                if self.decision_log is not None:
                    self.decision_log[pkt.no] = {"t": t, "irtt": c.irtt, "dupacks": rev.dupacknum,
                                                 "ack_eq_seq": rev.lastack == seq, "sack": rev.sack,
                                                 "in_sack": in_sack}
                if t < 0.020 and rev.dupacknum >= 2 and rev.lastack == seq:
                    retrans_kind = "fast_retransmission"
                elif t < 0.020 and rev.dupacknum >= 2 and rev.sack and not in_sack:
                    retrans_kind = "fast_retransmission"
                else:
                    ooo_thresh = c.irtt if c.irtt else 0.003
                    already_seen = any(_le(s0, seq) and _le(end_data, s1)
                                       for s0, s1 in self._live_unacked(fwd))
                    end = (end_data + (1 if fl & (TCP_SYN | TCP_FIN) else 0)) & M32
                    if t < ooo_thresh and not already_seen and (nextseq != end or fwd.lastacklen == 0):
                        retrans_kind = "out_of_order"
                    else:
                        retrans_kind = "retransmission"
        if retrans_kind:
            ta.add(retrans_kind)

        # Remember this segment until it is acknowledged (Wireshark's "unacked" list).
        nxt = (seq + seglen) & M32
        if (seglen or fl & (TCP_SYN | TCP_FIN)) and len(fwd.unacked) < MAX_UNACKED:
            if fl & (TCP_SYN | TCP_FIN):
                nxt = (nxt + 1) & M32
            if fwd.unacked is _EMPTY:
                fwd.unacked = deque()
            fwd.unacked.append((seq, nxt))
        if nextseq is None or _gt(nxt, (nextseq + (1 if fl & (TCP_SYN | TCP_FIN) else 0)) & M32):
            fwd.lastacklen = seglen
        zwp = "zero_window_probe" in ta
        if (fwd.nextseq is None or _gt(nxt, fwd.nextseq)) and not zwp:
            fwd.nextseq, fwd.nextseqframe, fwd.nextseqtime = nxt, pkt.no, ts
        if (fwd.maxseqtobeacked is None or seq == fwd.maxseqtobeacked) and not zwp:
            fwd.maxseqtobeacked = fwd.nextseq
        # The peer's ACK releases our record of its acknowledged segments.
        if ack is not None:
            if rev.max_ack is None or _gt(ack, rev.max_ack):
                rev.max_ack = ack
            while rev.unacked and _le(rev.unacked[0][1], rev.max_ack):
                rev.unacked.popleft()
            # Wireshark drops every acknowledged entry on each ACK; we do the same
            # in amortised batches so a stuck first entry cannot make the list grow.
            if len(rev.unacked) > 512 and len(rev.unacked) > 2 * rev.unacked_live:
                m = rev.max_ack
                rev.unacked = deque(e for e in rev.unacked if not _le(e[1], m))
                rev.unacked_live = max(256, len(rev.unacked))
        # Initial RTT as Wireshark defines it: most recent SYN -> first pure ACK.
        if syn and not has_ack:
            c.syn_mru_ts = ts
        elif has_ack and not syn and c.syn_mru_ts is not None and c.irtt is None:
            c.irtt = ts - c.syn_mru_ts

        # ---- record flags
        for name in ta:
            detail = self._detail(name, pkt, fwd, rev)
            self._flag(c, name, pkt, detail, fwd)

        # ---- own metrics
        is_retx = retrans_kind in ("retransmission", "fast_retransmission",
                                   "spurious_retransmission")
        if seglen > 0:
            fwd.data_segments += 1
            if is_retx:
                fwd.retrans_bytes += seglen
                fwd.retrans_segs += 1
                # The *same* frame captured twice (port mirroring/SPAN duplicate) is not
                # a real retransmission: same non-zero IPv4 ID, or (IPv6 / ID 0) an
                # identical segment less than 1 ms later, faster than any TCP timer.
                orig = fwd.recent_ids.get(seq)
                fp = (pkt.ack, pkt.win, pkt.flags, seglen, hash(pkt.payload))
                if orig and ts - orig[1] < 1.0 and (
                        (pkt.ip_id and orig[0] == pkt.ip_id)
                        or (orig[2] == fp and ts - orig[1] < 0.001)):
                    c.dup_frames += 1
                    fwd.dup_segs += 1
                    why = (f"same IP ID 0x{pkt.ip_id:04x} as an earlier frame" if pkt.ip_id and orig[0] == pkt.ip_id
                           else f"identical to an earlier frame {1e6 * (ts - orig[1]):.0f} µs before")
                    self._count(c, "capture_duplicate", pkt, why)
                fwd.pending = _EMPTY  # Karn's rule: RTT samples now ambiguous
            elif retrans_kind != "out_of_order":
                fwd.data_bytes += seglen
                if fwd.pending is _EMPTY:
                    fwd.pending = deque()
                fwd.pending.append((nxt, ts))
                if len(fwd.pending) > 4096:
                    fwd.pending.popleft()
                if len(fwd.recent_ids) > 512:
                    fwd.recent_ids.clear()
                fwd.recent_ids[seq] = (pkt.ip_id, ts, (pkt.ack, pkt.win, pkt.flags, seglen, hash(pkt.payload)))
            if seglen > fwd.max_seg:
                fwd.max_seg = seglen
            peer_mss = rev.mss
            if (peer_mss and seglen > peer_mss) or (pkt.ip_len == 0 and seglen > 1460):
                c.tso_frames += 1
                self._count(c, "tso_oversize", pkt,
                            f"payload {seglen} B > MSS {peer_mss or '?'}")
            # application turns (request -> response)
            if is_retx and fwd is c.client and fwd.last_data_ts is not None:
                # A re-sent request: the server can only answer once a copy arrives,
                # so time the reply from the retransmission, not the lost original.
                fwd.last_data_ts, fwd.last_data_frame = ts, pkt.no
            if not is_retx and retrans_kind != "out_of_order":
                is_server = c.client is not None and fwd is c.server
                if (c.last_data_dir is not None and c.last_data_dir is not fwd
                        and is_server and rev.last_data_ts is not None):
                    delay = ts - rev.last_data_ts
                    c.turn_count += 1
                    c.turn_srv_bytes = 0
                    c.cur_turn = None
                    if len(c.turns) < 500:
                        c.turns.append((rev.last_data_frame, pkt.no, ts, delay))
                        # TLS 1.3 servers send session tickets (small encrypted records)
                        # straight after the handshake, before the real reply. Only that
                        # pattern, early in a TLS connection, may be re-timed below.
                        if c.turn_count <= 3 and c.tls_seen and pkt.payload[:3] == b"\x17\x03\x03":
                            c.cur_turn = (len(c.turns) - 1, rev.last_data_ts)
                elif (is_server and c.last_data_dir is fwd and c.cur_turn is not None
                        and fwd.last_data_ts is not None and ts - fwd.last_data_ts >= 0.2
                        and c.turn_srv_bytes < 2000):
                    # Only a small preamble came first, then silence: time the real reply.
                    idx, req_ts = c.cur_turn
                    c.turns[idx] = (c.turns[idx][0], pkt.no, ts, ts - req_ts)
                    c.cur_turn = None
                if not is_server and pkt.payload[:1] == b"\x16" and pkt.payload[1:2] == b"\x03":
                    c.tls_seen = True
                if is_server:
                    c.turn_srv_bytes += seglen
                c.last_data_dir = fwd
                fwd.last_data_ts, fwd.last_data_frame = ts, pkt.no

        # ACK RTT (time from new data to the ACK that covers it)
        if ack is not None and rev.pending:
            sample_ts = None
            while rev.pending and _le(rev.pending[0][0], ack):
                sample_ts = rev.pending.popleft()[1]
            if sample_ts is not None:
                r = ts - sample_ts
                rev.rtt_count += 1
                rev.rtt_sum += r
                rev.rtt_min = r if rev.rtt_min is None else min(rev.rtt_min, r)
                rev.rtt_max = r if rev.rtt_max is None else max(rev.rtt_max, r)
                if len(rev.rtt_samples) < 600:
                    rev.rtt_samples.append((ts, r))

        # zero-window duration (advertised by fwd)
        if win == 0 and not sfr:
            if fwd.zw_start is None:
                fwd.zw_start = ts
        elif fwd.zw_start is not None and (win > 0 or rst or fin):
            self._close_stall(fwd, ts)
        if rst and rev.zw_start is not None:      # a reset ends the peer's stall too
            self._close_stall(rev, ts)

        # in-order reassembly of the first bytes of each direction (for TLS)
        if self.stream_callback and seglen > 0 and pkt.payload and not fwd.asm_done:
            self._reassemble(c, fwd, pkt)

        fwd.window = win
        fwd.window_bytes = wbytes
        fwd.lastack = ack
        fwd.lastacktime = ts
        fwd.lastsegflags = frozenset(ta)
        fwd.sack = pkt.sack

    @staticmethod
    def _live_unacked(d: Direction, reverse: bool = False):
        """Unacknowledged segments, trimmed by the highest ACK seen (Wireshark trims
        partially-acknowledged entries and drops fully-acknowledged ones)."""
        items = reversed(d.unacked) if reverse else d.unacked
        for s0, s1 in items:
            if d.max_ack is not None:
                if _le(s1, d.max_ack):
                    continue
                if _gt(d.max_ack, s0):
                    s0 = d.max_ack
            yield s0, s1

    def _reassemble(self, c: Connection, fwd: Direction, pkt: Packet):
        seq, data = pkt.seq, pkt.payload
        if pkt.flags & TCP_SYN:
            seq = (seq + 1) & M32
        if fwd.asm_next is None:
            fwd.asm_next = seq
        if seq == fwd.asm_next:
            chunk = data
        elif _lt(seq, fwd.asm_next) and _gt((seq + len(data)) & M32, fwd.asm_next):
            chunk = data[(fwd.asm_next - seq) & M32:]
        elif _gt(seq, fwd.asm_next):
            fwd.asm_done = True    # gap: stop, we only parse contiguous bytes
            return
        else:
            return
        fwd.asm_next = (fwd.asm_next + len(chunk)) & M32
        fwd.asm_bytes += len(chunk)
        if fwd.asm_bytes >= self.asm_limit:
            fwd.asm_done = True
        if len(chunk) < pkt.seglen and chunk is data:
            fwd.asm_done = True    # snaplen-truncated payload
        is_client = fwd is c.client
        keep = self.stream_callback(c, is_client, chunk, pkt)
        if keep is False:
            fwd.asm_done = True

    @staticmethod
    def _guess_client(c: Connection, fwd: Direction, rev: Direction) -> Direction:
        # Mid-stream capture: the side using a well-known/low port is the server.
        if rev.port in WELL_KNOWN_SERVER_PORTS and fwd.port not in WELL_KNOWN_SERVER_PORTS:
            return fwd
        if fwd.port in WELL_KNOWN_SERVER_PORTS and rev.port not in WELL_KNOWN_SERVER_PORTS:
            return rev
        return fwd if fwd.port > rev.port else rev

    @staticmethod
    def _detail(name: str, pkt: Packet, fwd: Direction, rev: Direction) -> str:
        if name in ("retransmission", "fast_retransmission", "spurious_retransmission",
                    "out_of_order"):
            return f"seq {pkt.seq} len {pkt.seglen}"
        if name == "duplicate_ack":
            return f"ack {pkt.ack} (dup #{fwd.dupacknum})"
        if name in ("zero_window", "window_full"):
            return f"window {pkt.win}"
        if name == "lost_segment":
            missing = (pkt.seq - (fwd.nextseq or pkt.seq)) & M32
            return f"{missing} bytes before this segment were not seen"
        if name == "ack_lost_segment":
            return f"acks {pkt.ack}, data up to it was not seen"
        return ""

    # ------------------------------------------------------------------ results
    @staticmethod
    def _close_stall(d: Direction, ts: float) -> None:
        dur = max(0.0, ts - d.zw_start)
        d.zw_total += dur
        d.zw_max = max(d.zw_max, dur)
        d.zw_start = None

    def finish(self, capture_end: float) -> None:
        for c in self.all_conns:
            for d in (c.a, c.b):
                if d.zw_start is not None:   # still stalled: count up to the connection's last frame
                    self._close_stall(d, c.last_ts)


def outcome(c: Connection, capture_end: float) -> str:
    """Human label for how the connection went."""
    if c.syn_ts is not None and c.synack_ts is None:
        if c.rst_phase == "handshake":
            return "refused"
        return "no_answer" if capture_end - c.syn_ts >= 3.0 else "pending"
    if c.syn_ts is None and c.synack_ts is None:
        return "mid_stream"
    if c.rst_frame:
        return "reset"
    if c.a.fin and c.b.fin:
        return "closed"
    return "open"
