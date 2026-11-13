"""Score an analysis result against a synthetic scenario's ground truth."""
from __future__ import annotations

import glob
import json
import os

from .tcp import FLAGS as TCP_FLAGS

TCP_EVENTS = {"retransmission", "fast_retransmission", "spurious_retransmission", "out_of_order",
              "lost_segment", "ack_lost_segment", "duplicate_ack", "zero_window", "zero_window_probe",
              "window_full", "window_update", "zero_window_probe_ack", "keep_alive", "keep_alive_ack"}


def detected_frames(result: dict, event: str) -> set:
    """Frames where Packet Doctor reports ``event``."""
    tcp = result["tcp"]
    if event == "retransmission":   # any kind, as in Wireshark's tcp.analysis.retransmission
        ff = tcp["flag_frames"]
        return set(ff["retransmission"]) | set(ff["fast_retransmission"]) | set(ff["spurious_retransmission"])
    if event in TCP_EVENTS:
        return set(tcp["flag_frames"][event])
    conns = tcp["connections"]
    dns = result["dns"]["transactions"]
    if event == "dns_servfail":
        return {t["query_frame"] for t in dns if t["status"] == "servfail"}
    if event == "dns_timeout":
        return {t["query_frame"] for t in dns if t["status"] == "timeout"}
    if event == "dns_nxdomain":
        return {t["query_frame"] for t in dns if t["status"] == "nxdomain"}
    if event == "dns_slow":
        th = result["thresholds"]["dns_slow_ms"]
        return {t["query_frame"] for t in dns if t["latency_ms"] is not None and t["latency_ms"] >= th}
    if event == "refused":
        return {c["rst"]["frame"] for c in conns if c["outcome"] == "refused"}
    if event == "syn_unanswered":
        out = set()
        for c in conns:
            if c["outcome"] == "no_answer":
                out |= {e["frame"] for e in c["examples"].get("retransmission", [])}
                out.add(c["handshake"]["syn_frame"])
        return out
    if event == "slow_response":
        return {s["response_frame"] for c in conns for s in c["responses"]["slow"]}
    if event == "tls_alert":
        return {s["alert_frame"] for s in result["tls"]["sessions"] if s["alert"]}
    if event in ("tso_oversize", "capture_duplicate"):
        return {e["frame"] for c in conns for e in c["examples"].get(event, [])}
    raise KeyError(event)


def score(result: dict, truth: dict) -> dict:
    rows = []
    for event, frames in sorted(truth["events"].items()):
        want = set(frames)
        got = detected_frames(result, event)
        rows.append({"event": event, "expected": len(want), "found": len(want & got),
                     "missed": sorted(want - got), "false": sorted(got - want)})
    # The truth files list every TCP expert event the generator injected, so any other
    # TCP flag Packet Doctor raises in that file is a false detection.
    listed = set(truth["events"])
    for flag in TCP_FLAGS:
        if flag in listed or (flag in ("fast_retransmission", "spurious_retransmission")
                              and "retransmission" in listed):
            continue
        got = set(result["tcp"]["flag_frames"][flag])
        if got:
            rows.append({"event": flag, "expected": 0, "found": 0, "missed": [], "false": sorted(got)})
    keys = {f["key"] for f in result["findings"]}
    exp = truth.get("expect_findings", [])
    forb = truth.get("forbid_findings", [])
    cause_ok = None
    if truth.get("expect_cause"):
        probs = result["diagnosis"]["problems"]
        cause_ok = bool(probs) and truth["expect_cause"].lower() in probs[0]["most_probable"].lower()
    return {
        "scenario": truth["scenario"], "events": rows,
        "findings_expected": exp, "findings_missing": [k for k in exp if k not in keys],
        "findings_forbidden_present": [k for k in forb if k in keys],
        "expected_cause": truth.get("expect_cause"), "cause_ok": cause_ok,
        "health_ok": (result["diagnosis"]["health"] == truth["expect_health"]) if truth.get("expect_health") else None,
    }


def score_corpus(directory: str) -> list:
    from .analyse import analyse
    out = []
    for tp in sorted(glob.glob(os.path.join(directory, "*.truth.json"))):
        with open(tp, encoding="utf-8") as f:
            truth = json.load(f)
        base = tp[:-len(".truth.json")]
        cap = next((base + ext for ext in (".pcap", ".pcapng") if os.path.exists(base + ext)), None)
        if cap:
            out.append(score(analyse(cap), truth))
    return out


def markdown_table(scores: list) -> str:
    lines = ["| Scenario | Injected event | Expected | Found | Missed | False |", "|---|---|---:|---:|---:|---:|"]
    tot = [0, 0, 0, 0]
    for s in scores:
        for r in s["events"]:
            lines.append(f"| {s['scenario']} | {r['event']} | {r['expected']} | {r['found']} | "
                         f"{len(r['missed'])} | {len(r['false'])} |")
            tot[0] += r["expected"]; tot[1] += r["found"]; tot[2] += len(r["missed"]); tot[3] += len(r["false"])
    lines.append(f"| **Total** | | **{tot[0]}** | **{tot[1]}** | **{tot[2]}** | **{tot[3]}** |")
    lines += ["", "| Scenario | Expected findings | Missing | Unwanted findings | Expected cause | Cause picked |",
              "|---|---|---|---|---|---|"]
    for s in scores:
        lines.append(f"| {s['scenario']} | {', '.join(s['findings_expected']) or '(none)'} | "
                     f"{', '.join(s['findings_missing']) or '–'} | {', '.join(s['findings_forbidden_present']) or '–'} | "
                     f"{s['expected_cause'] or '–'} | "
                     f"{'–' if s['cause_ok'] is None else ('yes' if s['cause_ok'] else '**no**')} |")
    return "\n".join(lines)
