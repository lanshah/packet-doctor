"""One-pass analysis pipeline: read -> analysers -> result dict -> diagnosis."""
from __future__ import annotations

import os
import statistics
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

from . import __version__
from .dns import DNSAnalyzer
from .reader import CaptureInfo, iter_packets, sniff_format
from .tcp import FLAGS, TCPAnalyzer, outcome
from .tls import TLSAnalyzer
from .traffic import TrafficStats, service_of


@dataclass
class Thresholds:
    retrans_warn_pct: float = 1.0       # % of a sender's data segments retransmitted
    retrans_crit_pct: float = 5.0
    min_retrans: int = 3                # ignore single stray retransmissions
    comparable_segments: int = 20       # a "clean" connection must carry this much data
    high_rtt_ms: float = 300.0          # handshake RTT considered high
    slow_response_ms: float = 500.0     # server think time
    long_poll_s: float = 10.0           # longer gaps are long-polling/push, not a slow reply
    dns_slow_ms: float = 200.0
    dns_resolver_median_ms: float = 100.0
    dns_timeout_s: float = 2.0
    tls_slow_ms: float = 1000.0
    zero_window_crit_s: float = 1.0


MAX_CONN_DETAIL = 20_000


def _ms(x: Optional[float]) -> Optional[float]:
    return None if x is None else round(x * 1000, 2)


def _pct(vals, p):
    if not vals:
        return None
    vals = sorted(vals)
    k = (len(vals) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(vals) - 1)
    return vals[lo] + (vals[hi] - vals[lo]) * (k - lo)


def _addr_filter(ip_a: str, port_a: int, ip_b: str, port_b: int, proto: str = "tcp") -> str:
    f = "ipv6.addr" if ":" in ip_a else "ip.addr"
    return f"{f}=={ip_a} && {proto}.port=={port_a} && {f}=={ip_b} && {proto}.port=={port_b}"


def frames_filter(frames) -> str:
    frames = sorted(set(int(f) for f in frames))[:60]
    return "frame.number in {" + " ".join(str(f) for f in frames) + "}" if frames else ""


def analyse(path: str, max_packets: Optional[int] = None,
            thresholds: Optional[Thresholds] = None, keep_objects: bool = False) -> dict:
    """Analyse a capture file and return a JSON-serialisable result dict."""
    th = thresholds or Thresholds()
    t_start = time.perf_counter()
    info = CaptureInfo(path=path, file_format=sniff_format(path), linktype=-1,
                       file_size=os.path.getsize(path))
    tls = TLSAnalyzer()
    tcp = TCPAnalyzer(stream_callback=tls.feed)
    dns = DNSAnalyzer(timeout=th.dns_timeout_s)
    traffic = TrafficStats()
    for pkt in iter_packets(path, info, max_packets=max_packets):
        traffic.process(pkt)
        if pkt.proto == "TCP":
            tcp.process(pkt)
            if pkt.sport in (53, 853) or pkt.dport in (53, 853):
                dns.process(pkt)
        elif pkt.proto == "UDP":
            dns.process(pkt)
    end = info.last_ts
    tcp.finish(end)
    dns.finish(end)
    elapsed = time.perf_counter() - t_start

    t0 = info.first_ts

    def rel(ts):
        return None if ts is None else round(ts - t0, 6)

    tls_by_conn = {s.conn_index: s for s in tls.results()}
    # Bound the per-connection detail kept in the result (and therefore the size of the
    # HTML/JSON/CSV) on captures with huge connection counts, e.g. port scans. Totals and
    # flags still cover every connection; the busiest and the flagged ones are kept.
    all_c = tcp.all_conns
    if len(all_c) > MAX_CONN_DETAIL:
        def weight(c):
            return (bool(c.counts) or c.rst_frame > 0, c.a.data_bytes + c.b.data_bytes)
        keep = sorted(all_c, key=weight, reverse=True)[:MAX_CONN_DETAIL]
        keep.sort(key=lambda c: c.index)
        info.warnings.append(
            f"{len(all_c):,} TCP connections: per-connection detail is kept for the {MAX_CONN_DETAIL:,} busiest or "
            "flagged ones; the totals and flags still cover all of them.")
    else:
        keep = all_c
    conns = [_conn_summary(c, end, rel, tls_by_conn.get(c.index), th) for c in keep]

    dns_rows = []
    for t in dns.transactions:
        dns_rows.append({
            "name": t.name, "qtype": t.qtype, "client": t.client, "server": t.server,
            "txid": t.txid, "query_frame": t.query_frame, "time": rel(t.query_ts),
            "response_frame": t.response_frame or None,
            "latency_ms": _ms(t.latency), "rcode": t.rcode, "status": t.status,
            "answers": t.answers, "retries": t.retries})

    tls_rows = []
    for s in tls.results():
        tls_rows.append({
            "conn": s.conn_index, "client": s.client, "server": s.server, "port": s.server_port,
            "sni": s.sni, "alpn": s.alpn, "offered": s.offered, "version": s.version,
            "cipher": f"0x{s.cipher:04x}" if s.cipher is not None else None,
            "client_hello_frame": s.ch_frame, "time": rel(s.ch_ts),
            "server_hello_frame": s.sh_frame or None,
            "server_hello_ms": round(s.server_hello_ms, 2) if s.server_hello_ms is not None else None,
            "done_frame": s.done_frame or None,
            "setup_ms": round(s.setup_ms, 2) if s.setup_ms is not None else None,
            "alert": s.alert, "alert_frame": s.alert_frame or None, "alert_by": s.alert_by})

    duration = info.duration
    result = {
        "tool": {"name": "Packet Doctor", "version": __version__},
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "capture": {
            "file": os.path.basename(path), "format": info.file_format,
            "linktype": info.linktype, "file_size": info.file_size,
            "packets": info.packets, "bytes": traffic.bytes,
            "start_utc": _utc(info.first_ts), "end_utc": _utc(info.last_ts),
            "duration_s": round(duration, 3),
            "avg_mbps": round(traffic.bytes * 8 / duration / 1e6, 3) if duration > 0 else None,
            "non_ip_frames": info.non_ip_frames, "warnings": info.warnings,
            "time_went_backwards": info.time_went_backwards,
            "truncated_frames": traffic.truncated, "ip_fragments": traffic.fragments,
            "tso_zero_length": traffic.tso_zero_len, "max_frame": traffic.max_frame,
            "stopped_early": info.stopped_early,
            "reported_drops": info.reported_drops,
            "extra_linktypes": info.extra_linktypes,
            "analysis_seconds": round(elapsed, 2),
            "packets_per_second": int(info.packets / elapsed) if elapsed > 0 else None,
        },
        "thresholds": asdict(th),
        "traffic": {
            "timeline": traffic.timeline(),
            "protocols": [{"proto": p, "packets": traffic.proto_packets[p], "bytes": b}
                          for p, b in sorted(traffic.proto_bytes.items(), key=lambda kv: -kv[1])],
            "services": [{"service": s, "bytes": b} for s, b in
                         sorted(traffic.service_bytes.items(), key=lambda kv: -kv[1])[:12]],
            "top_talkers": traffic.top_talkers(),
            "top_conversations": traffic.top_conversations(),
            "icmp": traffic.icmp_summary(),
        },
        "tcp": {
            "connections": conns,
            "segments": tcp.segments,
            "flag_totals": {f: len(tcp.flag_frames[f]) for f in FLAGS},
            "flag_frames": {f: list(tcp.flag_frames[f]) for f in FLAGS},
            "rst_frames": list(tcp.rst_frames),
            "capture_point": _capture_point(conns),
        },
        "dns": {
            "transactions": dns_rows, "servers": dns.by_server(),
            "malformed": dns.malformed, "unmatched_responses": dns.unmatched_responses,
            "tcp_dns_packets": dns.tcp_dns_packets, "dot_packets": dns.dot_packets,
        },
        "tls": {"sessions": tls_rows},
    }
    from .diagnose import diagnose
    result["findings"], result["diagnosis"] = diagnose(result, th)
    if keep_objects:
        result["_objects"] = {"tcp": tcp, "dns": dns, "tls": tls, "traffic": traffic}
    return result


def _utc(ts: float) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
    except (OverflowError, OSError, ValueError):
        return f"invalid timestamp ({ts:.0f})"


def _conn_summary(c, end, rel, tls_s, th) -> dict:
    cl = c.client or c.a
    sv = c.other(cl)
    counts = dict(c.counts)
    hs = {}
    if c.hs_server_side is not None:
        hs["server_side_ms"] = _ms(c.hs_server_side)
    if c.hs_client_side is not None:
        hs["client_side_ms"] = _ms(c.hs_client_side)
    hs["irtt_ms"] = _ms(c.irtt)
    hs["syn_count"] = c.syn_count
    hs["syn_frame"] = c.syn_frame or None
    hs["synack_frame"] = c.synack_frame or None

    dirs = {}
    for label, d in (("c2s", cl), ("s2c", sv)):
        # Spurious retransmissions (data already ACKed) and capture duplicates are
        # not forward-path loss, so they are left out of the loss rate.
        spurious = c.dir_counts.get(("spurious_retransmission", label), 0)
        retx_real = max(0, d.retrans_segs - d.dup_segs - spurious)
        rtts = [r for _, r in d.rtt_samples]
        dirs[label] = {
            "sender": d.ip, "packets": d.packets, "wire_bytes": d.bytes_wire,
            "data_bytes": d.data_bytes, "data_segments": d.data_segments,
            "retrans_segments": d.retrans_segs, "retrans_real": retx_real,
            "retrans_pct": round(100 * retx_real / d.data_segments, 2) if d.data_segments else 0.0,
            "mss": d.mss, "win_scale": d.win_scale, "max_segment": d.max_seg,
            "zero_window_total_s": round(d.zw_total, 3), "zero_window_max_s": round(d.zw_max, 3),
            "ack_rtt_ms": {"samples": d.rtt_count,
                           "min": _ms(d.rtt_min), "median": _ms(_pct(rtts, 50)),
                           "p95": _ms(_pct(rtts, 95)), "max": _ms(d.rtt_max)} if d.rtt_count else None,
            "fin": d.fin,
            "flags": {k[0]: v for k, v in c.dir_counts.items() if k[1] == label},
        }
    duration = max(0.0, c.last_ts - c.first_ts)
    turns = [(rf, sf, ts, dl) for rf, sf, ts, dl in c.turns]
    delays = [dl for *_, dl in turns]
    # Server time = response delay minus the network round trip on the server side
    # of the capture point. Without a captured handshake there is no baseline, so
    # no server-time judgement is made for that connection.
    ss = hs.get("server_side_ms")
    base = ss / 1000.0 if ss is not None else None
    candidates = []
    if base is not None:
        for rf, sf, ts, dl in turns:
            think = dl - base
            if think * 1000 >= th.slow_response_ms and dl < th.long_poll_s and think > 3 * base:
                candidates.append((rf, sf, ts, dl, think))
    # Timer-driven pushes (websocket heartbeats, streaming updates) look like slow
    # replies: several gaps of almost the same length on one connection.
    periodic = False
    # Real servers vary; a timer does not. Needs at least 5 gaps, most within 3%.
    if len(candidates) >= 5:
        ds = sorted(x[3] for x in candidates)
        med = ds[len(ds) // 2]
        periodic = sum(1 for d in ds if abs(d - med) <= 0.03 * med) >= 0.8 * len(ds)
    slow = [] if periodic else [
        {"request_frame": rf, "response_frame": sf, "time": rel(ts),
         "response_ms": round(dl * 1000, 1), "think_ms": round(think * 1000, 1)}
        for rf, sf, ts, dl, think in candidates]
    long_gaps = sum(1 for d in delays if d >= th.long_poll_s)
    examples = {k: [{"frame": f, "time": rel(t), "detail": dt} for f, t, dt in v]
                for k, v in c.examples.items()}
    out = {
        "id": c.index,
        "client": cl.ip, "client_port": cl.port, "server": sv.ip, "server_port": sv.port,
        "service": service_of("TCP", cl.port, sv.port),
        "outcome": outcome(c, end),
        "start": rel(c.first_ts), "end": rel(c.last_ts), "duration_s": round(duration, 6),
        "first_frame": c.first_frame, "frames": c.frames,
        "handshake": hs, "dirs": dirs, "counts": counts, "examples": examples,
        "rst": {"frame": c.rst_frame, "by": c.rst_by, "phase": c.rst_phase,
                "time": rel(c.rst_ts)} if c.rst_frame else None,
        "responses": {"turns": c.turn_count,
                      "median_ms": _ms(statistics.median(delays)) if delays else None,
                      "max_ms": _ms(max(delays)) if delays else None,
                      "slow": slow[:20], "slow_count": len(slow), "long_gaps": long_gaps,
                      "periodic_push": periodic},
        "tso_frames": c.tso_frames, "duplicate_frames": c.dup_frames,
        "throughput_mbps": round((cl.data_bytes + sv.data_bytes) * 8 / duration / 1e6, 3)
        if duration > 0.001 else None,
        "filter": _addr_filter(cl.ip, cl.port, sv.ip, sv.port),
    }
    if tls_s is not None:
        out["tls"] = {"sni": tls_s.sni, "version": tls_s.version,
                      "server_hello_ms": round(tls_s.server_hello_ms, 1) if tls_s.server_hello_ms is not None else None,
                      "setup_ms": round(tls_s.setup_ms, 1) if tls_s.setup_ms is not None else None,
                      "alert": tls_s.alert}
    return out


def _capture_point(conns: list) -> dict:
    """Infer where the capture was taken from handshake timing.

    SYN -> SYN/ACK is the round trip on the server's side of the capture point;
    SYN/ACK -> ACK is the round trip on the client's side.
    """
    cs, ss = [], []
    for c in conns:
        h = c["handshake"]
        if h.get("client_side_ms") is not None and h.get("server_side_ms") is not None:
            cs.append(h["client_side_ms"])
            ss.append(h["server_side_ms"])
    if len(cs) < 1:
        return {"position": "unknown", "samples": 0,
                "text": "No complete TCP handshakes were captured, so the capture point "
                        "cannot be inferred."}
    mc, ms = statistics.median(cs), statistics.median(ss)
    if mc <= 2.0 and ms >= 4 * max(mc, 0.25):
        pos, text = "client", ("near the client: the client answers the SYN/ACK almost "
                               f"instantly (median {mc:.2f} ms) while the server side takes "
                               f"{ms:.1f} ms.")
    elif ms <= 2.0 and mc >= 4 * max(ms, 0.25):
        pos, text = "server", ("near the server: the server answers the SYN almost instantly "
                               f"(median {ms:.2f} ms) while the client side takes {mc:.1f} ms.")
    else:
        pos, text = "middle", (f"between client and server (client side {mc:.1f} ms, server "
                               f"side {ms:.1f} ms), for example on a router, firewall or SPAN port.")
    return {"position": pos, "samples": len(cs), "client_side_median_ms": round(mc, 2),
            "server_side_median_ms": round(ms, 2), "text": "Capture appears to be taken " + text}
