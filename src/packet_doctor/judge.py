"""Outside judge: compare Packet Doctor with Wireshark's own analysis.

Runs ``tshark`` (Wireshark's command-line engine) on the same capture and
compares, frame by frame, the TCP expert flags (retransmission, duplicate ACK,
zero window ...), plus handshake RTT, DNS response time and TLS server names.
Packet Doctor does not use tshark for its own analysis, so this is an
independent check.
"""
from __future__ import annotations

import csv
import re
import io
import os
import shutil
import subprocess
from typing import Optional

from .analyse import analyse

TCP_FIELDS = [
    "retransmission", "fast_retransmission", "spurious_retransmission", "out_of_order",
    "lost_segment", "ack_lost_segment", "duplicate_ack", "zero_window", "zero_window_probe",
    "zero_window_probe_ack", "window_full", "window_update", "keep_alive", "keep_alive_ack",
]
OTHER_FIELDS = ["tcp.stream", "tcp.analysis.initial_rtt", "dns.time", "dns.id", "dns.flags.rcode",
                "dns.flags.response", "tls.handshake.extensions_server_name", "tcp.flags.reset"]


def find_tshark() -> Optional[str]:
    env = os.environ.get("PACKET_DOCTOR_TSHARK")
    if env and os.path.exists(env):
        return env
    p = shutil.which("tshark")
    if p:
        return p
    for cand in (r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe",
                 "/Applications/Wireshark.app/Contents/MacOS/tshark", "/usr/bin/tshark"):
        if os.path.exists(cand):
            return cand
    return None


def tshark_version(tshark: str) -> str:
    out = subprocess.run([tshark, "--version"], capture_output=True, text=True, timeout=60).stdout
    first = out.splitlines()[0] if out else "unknown"
    m = re.search(r"(\d+\.\d+\.\d+)", first)
    return f"tshark {m.group(1)}" if m else first


def run_tshark(path: str, tshark: str) -> list:
    fields = ["frame.number"] + [f"tcp.analysis.{f}" for f in TCP_FIELDS] + OTHER_FIELDS
    cmd = [tshark, "-n", "-r", path,
           "-o", "tcp.analyze_sequence_numbers:TRUE", "-o", "tcp.track_bytes_in_flight:TRUE",
           "-o", "tcp.fastrt_supersedes_ooo:TRUE", "-o", "tcp.relative_sequence_numbers:TRUE",
           "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
           "-E", "quote=n"]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=3600)
    if proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(f"tshark failed: {proc.stderr.strip()[:500]}")
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts += [""] * (len(fields) - len(parts))
        rows.append(dict(zip(fields, parts)))
    return rows


def _cmp(ours: set, theirs: set) -> dict:
    both = ours & theirs
    union = ours | theirs
    return {
        "packet_doctor": len(ours), "wireshark": len(theirs), "both": len(both),
        "only_packet_doctor": sorted(ours - theirs)[:20],
        "only_wireshark": sorted(theirs - ours)[:20],
        "n_only_packet_doctor": len(ours - theirs), "n_only_wireshark": len(theirs - ours),
        "agreement_pct": round(100 * len(both) / len(union), 2) if union else 100.0,
    }


def judge(path: str, tshark: Optional[str] = None, result: Optional[dict] = None) -> dict:
    tshark = tshark or find_tshark()
    if not tshark:
        return {"available": False,
                "reason": "tshark not found. Install Wireshark (tick 'TShark' in the installer) or set "
                          "PACKET_DOCTOR_TSHARK to tshark's path."}
    res = result or analyse(path)
    rows = run_tshark(path, tshark)
    ws = {f: set() for f in TCP_FIELDS}
    ws_rst, frame_stream, stream_irtt = set(), {}, {}
    dns_ws, sni_ws = {}, {}
    for r in rows:
        try:
            fno = int(r["frame.number"])
        except ValueError:
            continue
        for f in TCP_FIELDS:
            if r[f"tcp.analysis.{f}"]:
                ws[f].add(fno)
        if r["tcp.flags.reset"] in ("1", "True", "true"):
            ws_rst.add(fno)
        if r["tcp.stream"]:
            st = int(r["tcp.stream"])
            frame_stream[fno] = st
            if r["tcp.analysis.initial_rtt"] and st not in stream_irtt:
                stream_irtt[st] = float(r["tcp.analysis.initial_rtt"])
        if r["dns.time"] and r["dns.flags.response"] in ("1", "True", "true"):
            dns_ws[fno] = (float(r["dns.time"]), r["dns.flags.rcode"])
        if r["tls.handshake.extensions_server_name"] and r["tcp.stream"]:
            sni_ws.setdefault(int(r["tcp.stream"]), r["tls.handshake.extensions_server_name"])

    ours = {f: set(res["tcp"]["flag_frames"][f]) for f in TCP_FIELDS}
    comp = {}
    # Wireshark also sets "retransmission" on fast and spurious retransmissions.
    comp["retransmission (all kinds)"] = _cmp(
        ours["retransmission"] | ours["fast_retransmission"] | ours["spurious_retransmission"],
        ws["retransmission"])
    for f in TCP_FIELDS:
        if f == "retransmission":
            continue
        comp[f] = _cmp(ours[f], ws[f])
    comp["reset (RST flag)"] = _cmp(set(res["tcp"]["rst_frames"]), ws_rst)

    # Handshake RTT per connection (matched through the connection's first frame)
    irtt_diffs, stream_map_ok, stream_map_n = [], 0, 0
    for c in res["tcp"]["connections"]:
        st = frame_stream.get(c["first_frame"])
        if st is None:
            continue
        stream_map_n += 1
        if st == c["id"]:
            stream_map_ok += 1
        if c["handshake"].get("irtt_ms") is not None and st in stream_irtt:
            irtt_diffs.append(abs(c["handshake"]["irtt_ms"] - stream_irtt[st] * 1000))
    # DNS response time
    dns_diffs, dns_rcode_ok, dns_n = [], 0, 0
    for t in res["dns"]["transactions"]:
        if t["response_frame"] and t["response_frame"] in dns_ws:
            dns_n += 1
            wtime, wrcode = dns_ws[t["response_frame"]]
            dns_diffs.append(abs(t["latency_ms"] - wtime * 1000))
            rc_map = {"NOERROR": "0", "FORMERR": "1", "SERVFAIL": "2", "NXDOMAIN": "3", "NOTIMP": "4",
                      "REFUSED": "5"}
            if rc_map.get(t["rcode"], (t["rcode"] or "").replace("RCODE", "")) == wrcode:
                dns_rcode_ok += 1
    # TLS SNI
    sni_ok, sni_n = 0, 0
    for s in res["tls"]["sessions"]:
        conn = res["tcp"]["connections"][s["conn"]]
        st = frame_stream.get(conn["first_frame"])
        if st in sni_ws:
            sni_n += 1
            sni_ok += int(sni_ws[st] == s["sni"])

    flagged = [k for k in comp if comp[k]["packet_doctor"] or comp[k]["wireshark"]]
    tot_both = sum(comp[k]["both"] for k in flagged)
    tot_union = sum(comp[k]["both"] + comp[k]["n_only_packet_doctor"] + comp[k]["n_only_wireshark"]
                    for k in flagged)
    return {
        "available": True,
        "file": os.path.basename(path),
        "tshark": tshark_version(tshark),
        "frames": res["capture"]["packets"],
        "tcp_flags": comp,
        "overall_flag_agreement_pct": round(100 * tot_both / tot_union, 2) if tot_union else 100.0,
        "tcp_stream_numbering": {"matched": stream_map_ok, "of": stream_map_n},
        "handshake_rtt": {"compared": len(irtt_diffs),
                          "max_abs_diff_ms": round(max(irtt_diffs), 4) if irtt_diffs else None},
        "dns": {"compared": dns_n, "rcode_agree": dns_rcode_ok,
                "max_abs_latency_diff_ms": round(max(dns_diffs), 4) if dns_diffs else None},
        "tls_sni": {"compared": sni_n, "agree": sni_ok},
    }


def judge_table(j: dict) -> str:
    """Markdown table of one judge result."""
    if not j.get("available"):
        return j.get("reason", "judge unavailable")
    lines = [f"**{j['file']}** ({j['frames']:,} frames, {j['tshark']}): overall agreement "
             f"**{j['overall_flag_agreement_pct']}%**", "",
             "| Flag | Packet Doctor | Wireshark | Both | Agreement |", "|---|---:|---:|---:|---:|"]
    for k, v in j["tcp_flags"].items():
        if v["packet_doctor"] or v["wireshark"]:
            lines.append(f"| {k} | {v['packet_doctor']} | {v['wireshark']} | {v['both']} | {v['agreement_pct']}% |")
    h, d, s, n = j["handshake_rtt"], j["dns"], j["tls_sni"], j["tcp_stream_numbering"]
    lines.append("")
    lines.append(f"Stream numbering matches Wireshark's `tcp.stream`: {n['matched']}/{n['of']}. "
                 f"Handshake RTT compared on {h['compared']} connections, max difference "
                 f"{h['max_abs_diff_ms']} ms. DNS: {d['compared']} responses, rcode agrees on {d['rcode_agree']}, "
                 f"max latency difference {d['max_abs_latency_diff_ms']} ms. TLS SNI agrees {s['agree']}/{s['compared']}.")
    return "\n".join(lines)


def judge_csv(results: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["file", "flag", "packet_doctor", "wireshark", "both", "agreement_pct"])
    for j in results:
        if not j.get("available"):
            continue
        for k, v in j["tcp_flags"].items():
            w.writerow([j["file"], k, v["packet_doctor"], v["wireshark"], v["both"], v["agreement_pct"]])
    return buf.getvalue()
