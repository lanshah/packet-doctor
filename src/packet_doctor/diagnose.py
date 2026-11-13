"""Diagnosis layer: evidence-backed findings plus Kepner-Tregoe problem records.

Rules of the road (from the K-T method):
  * every finding cites frames, times and values;
  * a problem is specified as IS / IS-NOT before any cause is named;
  * each candidate cause is tested against the whole specification and
    dropped if it contradicts an IS-NOT;
  * capture-point artefacts (offload, duplicates, capture drops) are reported
    separately and never counted as network faults;
  * confidence is stated and lowered when the evidence is thin.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from statistics import median

from .analyse import frames_filter
from .dns import nxdomain_is_benign

SEV_RANK = {"critical": 0, "warning": 1, "info": 2}
CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def _lower(conf: str) -> str:
    return {"high": "medium", "medium": "low", "low": "low"}[conf]


def _ep(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _f(key, category, severity, confidence, title, summary, evidence, check_next,
       artefact=False, metrics=None, kt=None, wfilter=None):
    frames = [e["frame"] for e in evidence if e.get("frame")]
    return {"key": key, "category": category, "severity": severity, "confidence": confidence,
            "artefact": artefact, "title": title, "summary": summary,
            "evidence": evidence[:25], "check_next": check_next, "metrics": metrics or {},
            "wireshark_filter": wfilter or frames_filter(frames), "kt": kt}


def _ev(frame, time, text):
    return {"frame": frame, "time": time, "text": text}


def _times_text(times: list, duration: float) -> tuple:
    """Describe WHEN: clustered burst or spread across the capture."""
    if not times:
        return "", ""
    lo, hi = min(times), max(times)
    span = hi - lo
    if duration > 0 and len(times) >= 3 and span <= 0.2 * duration:
        return (f"concentrated between t={lo:.2f}s and t={hi:.2f}s",
                f"the rest of the capture (0-{lo:.1f}s and {hi:.1f}-{duration:.1f}s) is clean")
    return (f"spread from t={lo:.2f}s to t={hi:.2f}s",
            "no clean period long enough to be meaningful")


def _comparable(conns, th):
    return [c for c in conns if c["dirs"]["c2s"]["data_segments"] + c["dirs"]["s2c"]["data_segments"]
            >= th.comparable_segments]


# --------------------------------------------------------------------- capture
def _capture_findings(r, th, F):
    cap = r["capture"]
    conns = r["tcp"]["connections"]
    tso = [c for c in conns if c["tso_frames"]]
    if tso or cap["tso_zero_length"]:
        n = sum(c["tso_frames"] for c in tso)
        ev = []
        for c in tso[:6]:
            for e in c["examples"].get("tso_oversize", [])[:2]:
                ev.append(_ev(e["frame"], e["time"], f"{_ep(c['client'], c['client_port'])} ↔ "
                              f"{_ep(c['server'], c['server_port'])}: {e['detail']}"))
        F.append(_f("capture_offload", "capture", "info", "high",
                    "Capture taken on a host using segmentation offload (TSO/GSO/LRO)",
                    f"{n} TCP segments are larger than the negotiated MSS"
                    + (f" and {cap['tso_zero_length']} IPv4 packets have total length 0" if cap["tso_zero_length"] else "")
                    + ". The network card splits or merges these on the wire, so the capture shows "
                      "packets that never existed in that size on the network. This is a capture-point "
                      "artefact, not a fault. Large frames do not mean jumbo frames are in use.",
                    ev, ["Treat segment sizes and per-packet counts with care; byte totals are still valid.",
                         "To see on-wire packets, capture on a SPAN/mirror port or disable offload "
                         "temporarily (Windows: adapter Properties > Advanced > Large Send Offload)."],
                    artefact=True, metrics={"oversize_segments": n}))
    dups = [c for c in conns if c["duplicate_frames"]]
    if dups:
        n = sum(c["duplicate_frames"] for c in dups)
        ev = [_ev(e["frame"], e["time"], e["detail"]) for c in dups[:5]
              for e in c["examples"].get("capture_duplicate", [])[:3]]
        F.append(_f("capture_duplicates", "capture", "info", "medium",
                    "Duplicate frames from the capture setup",
                    f"{n} 'retransmissions' carry the same IP identification number as the original "
                    "frame, so they are the same packet captured twice (typical of a SPAN/mirror port "
                    "that copies both ingress and egress, or capturing on two interfaces). They have "
                    "been excluded from the packet-loss figures.",
                    ev, ["Check the mirror session copies only one direction per port, or deduplicate "
                         "with `editcap -D 10 in.pcapng out.pcapng`."], artefact=True,
                    metrics={"duplicate_frames": n}))
    drop_conns = [c for c in conns if c["counts"].get("ack_lost_segment")]
    if drop_conns:
        n = sum(c["counts"]["ack_lost_segment"] for c in drop_conns)
        gaps = sum(c["counts"].get("lost_segment", 0) for c in drop_conns)
        ev = [_ev(e["frame"], e["time"], e["detail"]) for c in drop_conns[:6]
              for e in c["examples"].get("ack_lost_segment", [])[:2]]
        F.append(_f("capture_drops", "capture", "info", "high" if n >= 3 else "medium",
                    "The capture missed packets (capture drops)",
                    f"{n} ACKs on {len(drop_conns)} connection(s) acknowledge data that never appears "
                    f"in the capture ({gaps} gaps seen). The receiver got the data, so the network "
                    "delivered it; the capturing machine failed to record it (busy CPU, small capture "
                    "buffer, or a mirror port that was oversubscribed). Gaps alone are not proof of "
                    "network loss.",
                    ev, ["Capture to a fast local disk with a larger buffer: `dumpcap -B 64 -i <if> -w f.pcapng`.",
                         "On a SPAN port, check the switch for mirror-port output drops."],
                    artefact=True, metrics={"acked_unseen": n, "gaps": gaps}))
    if cap.get("reported_drops"):
        F.append(_f("capture_tool_drops", "capture", "info", "high",
                    "The capture tool reported dropped packets",
                    f"The capture file's own statistics say {cap['reported_drops']:,} packets were dropped while "
                    "capturing (the interface or capture buffer could not keep up). Gaps and 'ACKed unseen' "
                    "segments may be capture losses, not network losses.", [],
                    ["Capture again with a bigger buffer (`dumpcap -B 64`), a capture filter, or to a faster disk."],
                    artefact=True, metrics={"reported_drops": cap["reported_drops"]}))
    if cap["truncated_frames"]:
        F.append(_f("capture_snaplen", "capture", "info", "high",
                    "Frames were cut short by the capture snap length",
                    f"{cap['truncated_frames']} frames were captured only partly. Headers are intact so "
                    "TCP analysis still works, but TLS names and DNS contents in long packets may be missing.",
                    [], ["Capture without a snaplen limit (Wireshark default) when payload details matter."],
                    artefact=True))
    if cap["time_went_backwards"]:
        F.append(_f("capture_time", "capture", "info", "high",
                    "Timestamps go backwards",
                    f"{cap['time_went_backwards']} frames have an earlier timestamp than the frame before. "
                    "This happens with merged captures or multi-queue NICs. Timing values near those "
                    "frames are unreliable.", [],
                    ["Re-order with `reordercap in.pcapng out.pcapng` before analysing."], artefact=True))
    mid = [c for c in conns if c["outcome"] == "mid_stream"]
    if mid and len(mid) >= 0.3 * max(1, len(conns)):
        F.append(_f("capture_midstream", "capture", "info", "high",
                    "Many connections were already open when the capture started",
                    f"{len(mid)} of {len(conns)} TCP connections have no handshake in the capture, so "
                    "their RTT, MSS and window scaling are unknown and window-full checks are skipped "
                    "for them.", [],
                    ["Start the capture before reproducing the problem so handshakes are included."],
                    artefact=True))


# --------------------------------------------------------------------- TCP loss
def _loss_findings(r, th, F):
    conns = r["tcp"]["connections"]
    duration = r["capture"]["duration_s"]
    affected, minor = [], []
    for c in conns:
        for label in ("c2s", "s2c"):
            d = c["dirs"][label]
            n = d["retrans_real"]
            if n <= 0:
                continue
            row = (c, label, d)
            # IS side of the specification: a sender whose retransmission rate is above
            # the warning level with at least two retransmissions. A single stray
            # retransmission is not evidence that a path is lossy (it counts as
            # neither affected nor clean). Whether this adds up to a problem is
            # decided on the total below.
            if d["retrans_pct"] >= th.retrans_warn_pct and n >= 2:
                affected.append(row)
            else:
                minor.append(row)
    if sum(d["retrans_real"] for _, _, d in affected) < th.min_retrans:
        minor += affected
        affected = []
    if not affected:
        if minor:
            n = sum(d["retrans_real"] for _, _, d in minor)
            F.append(_f("tcp_loss_minor", "tcp", "info", "high",
                        "Occasional TCP retransmissions (normal level)",
                        f"{n} retransmitted segments across {len({c['id'] for c, _, _ in minor})} "
                        f"connection(s), all below {th.retrans_warn_pct}% of the data sent or fewer than "
                        f"{th.min_retrans} per connection. TCP recovers from this routinely.",
                        [], [], metrics={"retransmissions": n}))
        return
    affected.sort(key=lambda row: (-row[2]["retrans_pct"], -row[2]["retrans_real"]))
    total = sum(d["retrans_real"] for _, _, d in affected)
    worst = affected[0][2]["retrans_pct"]
    sev = "critical" if worst >= th.retrans_crit_pct and total >= 10 else "warning"
    dupacks = sum(c["counts"].get("duplicate_ack", 0) for c, _, _ in affected)
    fast = sum(c["counts"].get("fast_retransmission", 0) for c, _, _ in affected)
    spurious = sum(d["flags"].get("spurious_retransmission", 0) for _, _, d in affected)
    gaps = sum(d["flags"].get("lost_segment", 0) for _, _, d in affected)
    conf = "high" if total >= 20 or (total >= 6 and (dupacks or fast)) else "medium"
    artefacts = any(c["counts"].get("ack_lost_segment") for c, _, _ in affected)
    if artefacts:
        conf = _lower(conf)

    ev, times = [], []
    for c, label, d in affected[:8]:
        sender = d["sender"]
        flags = c["examples"]
        first = (flags.get("retransmission") or flags.get("fast_retransmission")
                 or flags.get("spurious_retransmission") or [{}])[0]
        ev.append(_ev(first.get("frame"), first.get("time"),
                      f"{sender} → {c['server'] if sender == c['client'] else c['client']} "
                      f"({c['service']}): {d['retrans_real']} of {d['data_segments']} data segments "
                      f"retransmitted ({d['retrans_pct']}%)"))
    for c, _, _ in affected:
        for k in ("retransmission", "fast_retransmission", "spurious_retransmission"):
            times += [e["time"] for e in c["examples"].get(k, [])]

    # WHERE: which endpoints, and which comparable connections are clean?
    aff_ids = {c["id"] for c, _, _ in affected}
    aff_servers = Counter(c["server"] for c, _, _ in affected)
    aff_clients = Counter(c["client"] for c, _, _ in affected)
    clean = [c for c in _comparable(conns, th) if c["id"] not in aff_ids
             and not any(c["dirs"][x]["retrans_real"] for x in ("c2s", "s2c"))]
    clean_servers = {c["server"] for c in clean} - set(aff_servers)
    same_client_clean = [c for c in clean if c["client"] in aff_clients]
    when_is, when_not = _times_text(times, duration)
    cp = r["tcp"]["capture_point"]["position"]

    # Location of the loss relative to the capture point
    seen_orig = sum(d["retrans_real"] for c, lab, d in affected
                    if (cp == "client" and lab == "c2s") or (cp == "server" and lab == "s2c"))
    loc_text = ""
    if cp in ("client", "server"):
        if seen_orig >= total * 0.7:
            loc_text = ("Most retransmitted data was sent *from* the capture side and the originals were "
                        "captured, so the packets (or their ACKs) were lost beyond the capture point, "
                        "further along the path.")
        else:
            loc_text = ("Most retransmissions were sent *towards* the capture side, so packets were lost "
                        "before they reached the capture point.")

    summary = (f"{total} TCP segments were sent again on {len(aff_ids)} connection(s); the worst "
               f"sender retransmitted {worst}% of its data. Retransmission means a segment (or its ACK) "
               "was lost or badly delayed, which costs throughput and adds delay. "
               + (f"{dupacks} duplicate ACKs and {fast} fast retransmissions confirm the receiver noticed "
                  "gaps. " if dupacks or fast else "")
               + (f"{spurious} were spurious (data already acknowledged), pointing at delayed ACKs or an "
                  "aggressive retransmission timer rather than real loss. " if spurious else "")
               + loc_text)

    # Is the loss sitting on a transfer that dominates the link? TCP congestion
    # control raises its rate until a queue overflows, so a bulk transfer that
    # fills the bottleneck *always* loses some packets; no fault is needed.
    cap_bytes = max(1, r["capture"]["bytes"])
    dominant = {c["id"]: c for c in conns
                if (c["dirs"]["c2s"]["data_bytes"] + c["dirs"]["s2c"]["data_bytes"]) >= max(1_000_000, 0.3 * cap_bytes)}
    on_dominant = sum(d["retrans_real"] for c, _, d in affected if c["id"] in dominant)
    saturation = bool(dominant) and on_dominant >= 0.8 * total
    if saturation:
        dom = max((c for c, _, _ in affected if c["id"] in dominant),
                  key=lambda c: c["dirs"]["c2s"]["data_bytes"] + c["dirs"]["s2c"]["data_bytes"])
        sat_text = (f"{100 * on_dominant / total:.0f}% of the retransmissions are on the largest transfer "
                    f"({dom['service']} with {(dom.get('tls') or {}).get('sni') or dom['server']}, "
                    f"{dom['throughput_mbps'] or 0:.0f} Mbit/s average). TCP pushes a bulk transfer until the "
                    "bottleneck queue overflows, so some loss there is normal congestion control.")
        summary += " " + sat_text
        sev = "warning"          # loss while saturating a link is expected behaviour, not an outage
        if conf == "high":
            conf = "medium"

    # Candidate causes, tested against the specification
    causes = []
    multi_server = len(aff_servers) >= 2
    causes.append({
        "cause": f"Loss on a link shared by all affected connections: most often the local link of "
                 f"{aff_clients.most_common(1)[0][0]} (Wi-Fi signal/interference, bad cable, duplex mismatch, "
                 "overloaded home router), or its access/VPN link",
        "explains_is": multi_server,
        "contradicts": (f"{len(same_client_clean)} other busy connections from the same client to other "
                        "servers show no loss" if same_client_clean and not multi_server else ""),
        # a faulty link is an extra assumption when normal congestion already explains the loss
        "assumptions": 1 if multi_server and not saturation else 2,
    })
    for srv, n in aff_servers.most_common(2):
        causes.append({
            "cause": f"Congestion or loss on the path to {srv}, or at that server (ISP peering, "
                     "overloaded server/link at the remote end)",
            "explains_is": not multi_server,
            "contradicts": (f"loss also seen towards {len(aff_servers) - 1} other unrelated server(s)"
                            if multi_server else ""),
            # a path fault is an extra assumption when normal congestion explains it
            "assumptions": (2 if saturation else 1) if not multi_server else len(aff_servers),
        })
    causes.append({
        "cause": "The bulk transfer itself filling the bottleneck link (TCP congestion control; possibly "
                 "deepened by bufferbloat or ISP rate limiting)",
        "explains_is": saturation,
        "contradicts": ("" if saturation else
                        ("no single transfer dominates the capture" if not dominant else
                         "most retransmissions are not on the largest transfers")),
        "assumptions": 1,
    })
    _rank(causes)

    kt = {
        "problem": "TCP segments are being retransmitted (packet loss)",
        "spec": {
            "what": (f"{total} retransmissions ({worst}% worst case)"
                     + (f", {dupacks} duplicate ACKs" if dupacks else ""),
                     "not a receiver-window stall or a refused connection (checked separately)"),
            "where": (_where_list(aff_clients, aff_servers),
                      (f"{len(clean)} busy connections to {len(clean_servers)} other server(s) are clean"
                       if clean else "no comparable clean connections in this capture")),
            "when": (when_is, when_not),
            "extent": (f"{len(aff_ids)} of {len(_comparable(conns, th)) or len(conns)} data-carrying connections",
                       f"{len(clean)} comparable connections unaffected"),
        },
        "distinctions": [x for x in [
            (f"All affected connections go to {next(iter(aff_servers))}" if not multi_server else
             f"Affected connections go to {len(aff_servers)} different servers"),
            (f"All affected connections come from {next(iter(aff_clients))}" if len(aff_clients) == 1 else ""),
            loc_text,
            sat_text if saturation else "",
        ] if x],
        "causes": causes,
        "verify": _loss_verify(multi_server, aff_clients, aff_servers),
        "incident_fix": ("Move the client to a wired connection or closer to the access point and re-test."
                         if multi_server else
                         f"If the service matters, try an alternative path to {next(iter(aff_servers))} "
                         "(VPN off/on, another ISP) to confirm it is path-specific."),
        "permanent_fix": ("Fix the local link (Wi-Fi channel/placement, replace cable, check switch port "
                          "errors) and confirm the retransmission rate drops below 1%."
                          if multi_server else
                          "Raise a ticket with the remote side or ISP with this report attached (frames, "
                          "times, rates)."),
    }
    if saturation:
        kt["verify"] = [
            "Run the same download wired (Ethernet) and compare the retransmission rate: if it drops sharply, "
            "the Wi-Fi link is the bottleneck; if not, it is the ISP/access link.",
            "Run a bufferbloat test (e.g. the Waveform or Cloudflare speed test 'loaded latency') to see how much "
            "delay builds up while the link is full.",
            "Check whether other traffic suffered at the same time; if not, no action is needed.",
        ]
        kt["incident_fix"] = "None needed if throughput is acceptable: this is how TCP finds the link capacity."
        kt["permanent_fix"] = ("If interactive traffic suffers during big downloads, enable SQM/QoS (smart queue "
                               "management) on the router to cut bufferbloat.")
    F.append(_f("tcp_loss", "tcp", sev, conf, "Packet loss: TCP retransmissions", summary, ev,
                kt["verify"], metrics={"retransmissions": total, "connections": len(aff_ids),
                                       "worst_pct": worst, "dup_acks": dupacks,
                                       "fast_retransmissions": fast, "spurious": spurious,
                                       "gaps": gaps},
                kt=kt, wfilter="tcp.analysis.retransmission || tcp.analysis.fast_retransmission || "
                               "tcp.analysis.duplicate_ack"))


def _where_list(clients: Counter, servers: Counter) -> str:
    cl = ", ".join(c for c, _ in clients.most_common(3))
    sv = ", ".join(s for s, _ in servers.most_common(4))
    more = f" (+{len(servers) - 4} more)" if len(servers) > 4 else ""
    return f"client(s) {cl} talking to {sv}{more}"


def _loss_verify(multi, clients, servers):
    cl = clients.most_common(1)[0][0]
    sv = servers.most_common(1)[0][0]
    if multi:
        return [f"On {cl}: `ping -n 100 <default-gateway>`. Loss to your own gateway proves a local-link problem.",
                "On Windows Wi-Fi: `netsh wlan show interfaces` and check Signal (aim for >70%) and "
                "Receive/Transmit rate.",
                "If wired: check the switch port for CRC/input errors and duplex (`show interfaces`).",
                "Re-capture on a wired connection; if the retransmissions disappear, the local link is confirmed."]
    return [f"`pathping {sv}` (Windows) or `mtr {sv}` to see at which hop loss starts.",
            f"`ping -n 100 <default-gateway>` from {cl}: no loss there rules out the local link.",
            f"Test {sv} from a different network (mobile hotspot). Loss that follows the server is remote."]


def _rank(causes):
    for c in causes:
        c["verdict"] = ("eliminated" if c["contradicts"] or not c["explains_is"] else "possible")
    survivors = [c for c in causes if c["verdict"] == "possible"]
    if survivors:
        best = min(survivors, key=lambda c: c["assumptions"])
        best["verdict"] = "most probable"
    causes.sort(key=lambda c: ({"most probable": 0, "possible": 1, "eliminated": 2}[c["verdict"]],
                               c["assumptions"]))


# --------------------------------------------------------------------- windows
def _window_findings(r, th, F):
    conns = r["tcp"]["connections"]
    duration = r["capture"]["duration_s"]
    zw = []
    for c in conns:
        for label in ("c2s", "s2c"):
            d = c["dirs"][label]
            n = d["flags"].get("zero_window", 0)
            if n:
                zw.append((c, label, d, n))
    if zw:
        hosts = Counter(d["sender"] for _, _, d, _ in zw)
        total_s = sum(d["zero_window_total_s"] for _, _, d, _ in zw)
        max_s = max(d["zero_window_max_s"] for _, _, d, _ in zw)
        n = sum(x[3] for x in zw)
        sev = "critical" if max_s >= th.zero_window_crit_s else "warning"
        ev, times = [], []
        for c, label, d, k in zw[:8]:
            ex = [e for e in c["examples"].get("zero_window", [])]
            times += [e["time"] for e in ex]
            if ex:
                ev.append(_ev(ex[0]["frame"], ex[0]["time"],
                              f"{d['sender']} advertised window 0 ({k}x, stalled {d['zero_window_total_s']:.3f}s "
                              f"in total) on {c['service']} with {c['server'] if d['sender'] == c['client'] else c['client']}"))
        probes = sum(c["counts"].get("zero_window_probe", 0) for c, *_ in zw)
        aff_ids = {c["id"] for c, *_ in zw}
        clean = [c for c in _comparable(conns, th) if c["id"] not in aff_ids]
        h = hosts.most_common(1)[0][0]
        when_is, when_not = _times_text(times, duration)
        causes = [
            {"cause": f"The application on {h} is not reading data fast enough (busy CPU, slow disk, "
                      "blocked or paused application)",
             "explains_is": True, "contradicts": "", "assumptions": 1},
            {"cause": "Network congestion or packet loss",
             "explains_is": False,
             "contradicts": "a zero window is the receiver's own buffer filling up; the network "
                            "delivered the data", "assumptions": 2},
            {"cause": f"Receive buffer on {h} too small for the path (tuning)",
             "explains_is": True, "contradicts": "", "assumptions": 2},
        ]
        _rank(causes)
        kt = {
            "problem": f"{h} repeatedly tells the sender to stop (TCP zero window)",
            "spec": {
                "what": (f"{n} zero-window advertisements, {probes} zero-window probes, longest stall "
                         f"{max_s:.3f}s", "not packet loss: the data arrived and filled the receiver's buffer"),
                "where": (", ".join(f"{x} ({k}x)" for x, k in hosts.most_common(4)),
                          f"{len(clean)} other busy connections never advertise zero window" if clean
                          else "no comparable connections"),
                "when": (when_is, when_not),
                "extent": (f"{len(aff_ids)} connection(s), {total_s:.3f}s stalled in total",
                           f"{len(clean)} connections unaffected"),
            },
            "distinctions": [f"The zero windows come from the receiving host {h}, not from the network"],
            "causes": causes,
            "verify": [f"Watch CPU, disk and memory on {h} while the transfer stalls (Task Manager > Performance).",
                       "Check the receiving application's logs for pauses at the times listed.",
                       f"Wireshark: `tcp.analysis.zero_window && ip.src=={h}` and look at Statistics > TCP Stream "
                       "Graphs > Window Scaling to see the buffer drain."],
            "incident_fix": f"Free resources on {h} (close heavy apps, check disk) and repeat the transfer.",
            "permanent_fix": "Fix the slow consumer in the application, or give it more resources.",
        }
        F.append(_f("tcp_zero_window", "tcp", sev, "high" if n >= 3 else "medium",
                    "Receiver stalls: TCP zero window",
                    f"{h} told its peer to stop sending {n} times (window = 0), stalling transfers for up to "
                    f"{max_s:.3f}s. A zero window means the receiving application is not reading data as fast "
                    "as it arrives. It is an end-host problem, not a network fault.",
                    ev, kt["verify"], metrics={"zero_windows": n, "max_stall_s": max_s, "probes": probes},
                    kt=kt, wfilter="tcp.analysis.zero_window || tcp.analysis.zero_window_probe"))

    wf = [(c, sum(c["dirs"][x]["flags"].get("window_full", 0) for x in ("c2s", "s2c"))) for c in conns]
    wf = [(c, n) for c, n in wf if n >= 3]
    if wf:
        n = sum(k for _, k in wf)
        ev = [_ev(e["frame"], e["time"], f"{c['service']} {c['client']} ↔ {c['server']}: {e['detail']}")
              for c, _ in wf[:5] for e in c["examples"].get("window_full", [])[:2]]
        F.append(_f("tcp_window_full", "tcp", "info" if not zw else "warning", "medium",
                    "Sender limited by the receiver's window",
                    f"{n} segments filled the receiver's advertised window exactly on {len(wf)} connection(s). "
                    "The sender had to wait for ACKs before sending more, so throughput is limited by "
                    "window size / RTT, not by link bandwidth. Common on long-RTT paths with small buffers.",
                    ev, ["Check window scaling is negotiated (SYN options) and receive buffers are large "
                         "enough for bandwidth × RTT."],
                    metrics={"window_full": n}))


# --------------------------------------------------------------------- handshakes
def _handshake_findings(r, th, F):
    conns = r["tcp"]["connections"]
    refused = [c for c in conns if c["outcome"] == "refused"]
    noans = [c for c in conns if c["outcome"] == "no_answer"]
    ok_by_server = defaultdict(int)
    for c in conns:
        if c["handshake"].get("synack_frame"):
            ok_by_server[(c["server"], c["server_port"])] += 1
    if refused or noans:
        ev = []
        for c in refused[:6]:
            ev.append(_ev(c["rst"]["frame"], c["rst"]["time"],
                          f"{_ep(c['server'], c['server_port'])} answered the SYN from {c['client']} with RST "
                          "(nothing listening, or a firewall rejecting)"))
        for c in noans[:6]:
            ev.append(_ev(c["handshake"]["syn_frame"], c["start"],
                          f"{_ep(c['server'], c['server_port'])}: {c['handshake']['syn_count']} SYN(s) "
                          "from " + c["client"] + ", no reply"))
        targets = Counter(_ep(c["server"], c["server_port"]) for c in refused + noans)
        works_elsewhere = sum(1 for k, v in ok_by_server.items() if v)
        causes = []
        if refused:
            causes.append({"cause": "Service not running/listening on the refused port(s), or a firewall "
                                    "configured to reject", "explains_is": True, "contradicts": "",
                           "assumptions": 1})
        if noans:
            causes.append({"cause": "A firewall or ACL silently dropping the SYNs, or the host is down/unreachable",
                           "explains_is": True, "contradicts": "", "assumptions": 1})
        causes.append({"cause": "General network outage on the client side",
                       "explains_is": False,
                       "contradicts": (f"{works_elsewhere} other server:port pair(s) completed handshakes"
                                       if works_elsewhere else ""),
                       "assumptions": 2})
        _rank(causes)
        kt = {
            "problem": "TCP connections fail to establish",
            "spec": {
                "what": (f"{len(refused)} refused (RST), {len(noans)} unanswered SYN",
                         "not slow: these never connected"),
                "where": (", ".join(f"{t} ({n}x)" for t, n in targets.most_common(5)),
                          f"{works_elsewhere} other server:port pair(s) accept connections"),
                "when": ("at t=" + ", ".join(f"{c['start']:.2f}s" for c in (refused + noans)[:5]), ""),
                "extent": (f"{len(refused) + len(noans)} connection attempts",
                           f"{sum(ok_by_server.values())} successful handshakes"),
            },
            "distinctions": [("RST = something answered and refused" if refused else ""),
                             ("Silence = something dropped the SYN" if noans else "")],
            "causes": causes,
            "verify": [f"`Test-NetConnection {t.rsplit(':', 1)[0].strip('[]')} -Port {t.rsplit(':', 1)[1]}` "
                       "(PowerShell)" for t, _ in targets.most_common(2)]
                      + ["On the server: `netstat -ano | findstr LISTENING` to confirm the service is listening.",
                         "Check firewall logs for drops at the listed times."],
            "incident_fix": "Start the service or open the port (with change approval).",
            "permanent_fix": "Correct the firewall rule or service configuration and document it.",
        }
        kt["distinctions"] = [d for d in kt["distinctions"] if d]
        F.append(_f("tcp_connect_fail", "tcp", "critical" if noans else "warning",
                    "high" if (refused or any(c["handshake"]["syn_count"] >= 2 for c in noans)) else "medium",
                    "Connections refused or not answered",
                    f"{len(refused)} connection attempt(s) were refused with a TCP reset and {len(noans)} got no "
                    "answer at all. A reset means the host is reachable but nothing accepts that port; "
                    "silence usually means a firewall drops the packets or the host is down.",
                    ev, kt["verify"], metrics={"refused": len(refused), "no_answer": len(noans)}, kt=kt,
                    wfilter="tcp.flags.syn==1 && tcp.flags.ack==0 || tcp.flags.reset==1"))

    # resets after data (informational: browsers and Windows often close with RST)
    mid_rst = [c for c in conns if c["rst"] and c["rst"]["phase"] == "data"]
    if mid_rst:
        by = Counter(c["rst"]["by"] for c in mid_rst)
        ev = [_ev(c["rst"]["frame"], c["rst"]["time"],
                  f"{c['rst']['by']} reset {c['service']} {c['client']} ↔ {c['server']}") for c in mid_rst[:8]]
        F.append(_f("tcp_resets", "tcp", "info", "low",
                    "Connections ended with a reset",
                    f"{len(mid_rst)} established connection(s) ended with RST ({by.get('client', 0)} by client, "
                    f"{by.get('server', 0)} by server). Browsers and many apps close idle connections this "
                    "way, so this is usually normal. It matters only if it lines up with a user-visible error.",
                    ev, ["Correlate the reset times with the reported error. Repeated server resets right after "
                         "a request point at the server or a middlebox (IPS/load balancer idle timeout)."],
                    metrics={"resets": len(mid_rst)}))

    rtts = [c for c in conns if c["handshake"].get("irtt_ms") is not None]
    if rtts:
        high = [c for c in rtts if c["handshake"]["irtt_ms"] >= th.high_rtt_ms]
        if high:
            ev = [_ev(c["handshake"]["syn_frame"], c["start"],
                      f"{_ep(c['server'], c['server_port'])}: handshake RTT {c['handshake']['irtt_ms']:.1f} ms")
                  for c in sorted(high, key=lambda c: -c["handshake"]["irtt_ms"])[:8]]
            low = [c for c in rtts if c["handshake"]["irtt_ms"] < th.high_rtt_ms / 3]
            servers = Counter(c["server"] for c in high)
            all_high = len(high) == len(rtts) and len(servers) >= 2
            causes = [
                {"cause": "Long physical distance to the server (e.g. Malaysia to US/Europe is 180-300 ms) "
                          "or a VPN/proxy detour", "explains_is": not all_high or len(servers) == 1,
                 "contradicts": "", "assumptions": 1},
                {"cause": "Latency added on the local link or access network (congested Wi-Fi/uplink, "
                          "bufferbloat)",
                 "explains_is": all_high,
                 "contradicts": (f"{len(low)} handshakes to other servers are fast (<{th.high_rtt_ms / 3:.0f} ms)"
                                 if low else ""), "assumptions": 1 if all_high else 2},
            ]
            _rank(causes)
            med = median(c["handshake"]["irtt_ms"] for c in high)
            kt = {
                "problem": "High round-trip time to some servers",
                "spec": {
                    "what": (f"{len(high)} handshakes ≥ {th.high_rtt_ms:.0f} ms (median {med:.0f} ms)",
                             "not loss: high RTT alone does not drop packets"),
                    "where": (", ".join(s for s, _ in servers.most_common(5)),
                              f"{len(low)} handshakes to other servers are fast" if low else "all servers slow"),
                    "when": ("throughout the capture", ""),
                    "extent": (f"{len(high)} of {len(rtts)} handshakes", f"{len(rtts) - len(high)} normal"),
                },
                "distinctions": (["Every server is slow, including any nearby ones"] if all_high else
                                 ["Only specific servers are slow: distance or path, not the local link"]),
                "causes": causes,
                "verify": [f"`tracert {servers.most_common(1)[0][0]}` to see where the delay is added.",
                           "`ping -n 20 <default-gateway>`: more than a few ms on the LAN points at the local link."],
                "incident_fix": "None needed if the latency matches the distance.",
                "permanent_fix": "Use a closer server/CDN region, or fix local queueing if the gateway ping is slow.",
            }
            F.append(_f("tcp_high_rtt", "tcp", "warning" if all_high else "info",
                        "high" if len(high) >= 3 else "medium",
                        "High network latency (handshake RTT)",
                        f"{len(high)} of {len(rtts)} TCP handshakes took {th.high_rtt_ms:.0f} ms or more "
                        f"(median {med:.0f} ms). Every request on these connections pays this delay at least "
                        "once. It is normal for distant servers; it is a problem if the server is local.",
                        ev, kt["verify"], metrics={"high_rtt_handshakes": len(high), "median_ms": med},
                        kt=kt if all_high else None))


# --------------------------------------------------------------------- responses
def _response_findings(r, th, F):
    conns = r["tcp"]["connections"]
    slow = [(c, s) for c in conns for s in c["responses"]["slow"]]
    if not slow:
        return
    servers = Counter(_ep(c["server"], c["server_port"]) for c, _ in slow)
    ev = [_ev(s["response_frame"], s["time"],
              f"{_ep(c['server'], c['server_port'])}"
              + (f" ({c['tls']['sni']})" if c.get("tls") and c["tls"].get("sni") else "")
              + f": answered {s['response_ms']:.0f} ms after request frame {s['request_frame']}; network RTT "
                f"only {c['handshake'].get('server_side_ms') or 0:.1f} ms, so ≈{s['think_ms']:.0f} ms server time")
          for c, s in sorted(slow, key=lambda x: -x[1]["think_ms"])[:10]]
    fast_same = [c for c in conns if c["responses"]["turns"] and not c["responses"]["slow"]
                 and _ep(c["server"], c["server_port"]) in servers]
    other_fast = [c for c in conns if c["responses"]["turns"] and not c["responses"]["slow"]
                  and _ep(c["server"], c["server_port"]) not in servers]
    worst = max(s["think_ms"] for _, s in slow)
    causes = [
        {"cause": "Server or application processing time (slow backend, database, cold cache, overload)",
         "explains_is": True, "contradicts": "", "assumptions": 1},
        {"cause": "Network latency or loss",
         "explains_is": False,
         "contradicts": "the same connections completed their TCP handshake quickly; the delay is between "
                        "request and response, after the network round trip", "assumptions": 2},
    ]
    _rank(causes)
    kt = {
        "problem": "Server takes a long time to answer requests",
        "spec": {
            "what": (f"{len(slow)} request→response gaps with ≥{th.slow_response_ms:.0f} ms server time "
                     f"(worst {worst:.0f} ms)", "not the network: handshake RTTs are short"),
            "where": (", ".join(f"{s} ({n}x)" for s, n in servers.most_common(4)),
                      f"{len(other_fast)} connections to other servers answer promptly" if other_fast
                      else "no other servers to compare"),
            "when": (_times_text([s["time"] for _, s in slow], r["capture"]["duration_s"])),
            "extent": (f"{len(slow)} slow turns", f"{len(fast_same)} connection(s) to the same server were fast"),
        },
        "distinctions": ["Delay sits between the request leaving and the first response byte, after a fast handshake"],
        "causes": causes,
        "verify": ["Check server/application logs or APM for requests at the listed times.",
                   "`curl -o NUL -s -w \"connect=%{time_connect} ttfb=%{time_starttransfer}\\n\" https://<host>/` "
                   "- TTFB much larger than connect time confirms server-side delay."],
        "incident_fix": "Restart or scale the slow service only with the service owner's approval.",
        "permanent_fix": "Profile the application/backend; add caching or capacity.",
    }
    F.append(_f("tcp_slow_response", "tcp", "warning", "high" if len(slow) >= 3 else "medium",
                "Slow server responses (application delay)",
                f"{len(slow)} request(s) waited at least {th.slow_response_ms:.0f} ms for the first response byte "
                f"even though the network round trip was short (worst ≈{worst:.0f} ms of server time). "
                "The time is being spent inside the server or application, not on the network. Gaps longer "
                f"than {th.long_poll_s:.0f}s are ignored as long-polling or idle connections.",
                ev, kt["verify"], metrics={"slow_turns": len(slow), "worst_think_ms": worst}, kt=kt))


# --------------------------------------------------------------------- DNS
def _dns_findings(r, th, F):
    tx = r["dns"]["transactions"]
    if not tx:
        return
    duration = r["capture"]["duration_s"]
    fails = [t for t in tx if t["status"] in ("servfail", "refused", "error")]
    timeouts = [t for t in tx if t["status"] == "timeout"]
    nx = [t for t in tx if t["status"] == "nxdomain"]
    nx_real = [t for t in nx if not nxdomain_is_benign(t["name"])]
    slow = [t for t in tx if t["latency_ms"] is not None and t["latency_ms"] >= th.dns_slow_ms]
    servers = {s["server"]: s for s in r["dns"]["servers"]}

    if fails or timeouts:
        bad = fails + timeouts
        by_server = Counter(t["server"] for t in bad)
        by_name = Counter(t["name"] for t in bad)
        good_names = {t["name"] for t in tx if t["status"] == "ok"}
        good_servers = {t["server"] for t in tx if t["status"] == "ok"}
        ev = [_ev(t["query_frame"], t["time"],
                  f"{t['qtype']} {t['name']} via {t['server']}: "
                  + (t["rcode"] if t["status"] != "timeout" else f"no answer (timeout, {t['retries']} retries)"))
              for t in bad[:12]]
        one_resolver = len(by_server) == 1
        resolver = by_server.most_common(1)[0][0]
        resolver_ok = sum(1 for t in tx if t["server"] == resolver and t["status"] == "ok")
        causes = [
            {"cause": f"Resolver {resolver} is failing or overloaded",
             "explains_is": one_resolver,
             "contradicts": (f"the same resolver answered {resolver_ok} other lookups successfully"
                             if resolver_ok >= 3 and len(by_name) <= 2 else ""),
             "assumptions": 1},
            {"cause": "The domain(s) themselves are broken (authoritative servers down, DNSSEC failure)",
             "explains_is": len(by_name) <= 3,
             "contradicts": ("failures span many unrelated names" if len(by_name) > 3 else ""),
             "assumptions": 1},
            {"cause": "Path to the resolver is losing packets (only timeouts)",
             "explains_is": bool(timeouts) and not fails,
             "contradicts": ("the resolver answered with explicit errors, so it was reachable" if fails else ""),
             "assumptions": 2},
        ]
        _rank(causes)
        kt = {
            "problem": "DNS lookups failing",
            "spec": {
                "what": (f"{len(fails)} error responses (SERVFAIL/REFUSED), {len(timeouts)} timeouts",
                         f"{sum(1 for t in tx if t['status'] == 'ok')} lookups succeeded"),
                "where": ("resolver(s) " + ", ".join(f"{s} ({n}x)" for s, n in by_server.most_common(3))
                          + "; names " + ", ".join(n for n, _ in by_name.most_common(4)),
                          ("other resolvers worked: " + ", ".join(sorted(good_servers - set(by_server))))
                          if good_servers - set(by_server) else
                          f"{len(good_names)} other names resolved through the same resolver"),
                "when": _times_text([t["time"] for t in bad], duration),
                "extent": (f"{len(bad)} of {len(tx)} lookups", f"{len(tx) - len(bad)} fine"),
            },
            "distinctions": [
                f"Failures concentrate on {len(by_name)} name(s)" if len(by_name) <= 3 else
                f"Failures spread over {len(by_name)} different names",
            ],
            "causes": causes,
            "verify": [f"`Resolve-DnsName {by_name.most_common(1)[0][0]} -Server {resolver}` and again with "
                       "`-Server 1.1.1.1`. Fails on both = the domain; fails only on yours = the resolver.",
                       "`nslookup -debug <name> <resolver>` to see the full response."],
            "incident_fix": "Point the client at a working resolver temporarily (e.g. 1.1.1.1) if the resolver is at fault.",
            "permanent_fix": "Fix or replace the failing resolver, or contact the domain owner.",
        }
        # A name that failed once but resolved in another lookup (A vs AAAA, a retry,
        # another resolver) probably caused no user-visible problem.
        recovered = [t for t in bad if t["name"] in good_names]
        unrecovered = [t for t in bad if t["name"] not in good_names]
        rate = len(bad) / len(tx)
        if len(unrecovered) >= 3:
            sev, conf = "critical", "high"
        elif len(unrecovered) >= 2 or (len(bad) >= 2 and rate >= 0.05):
            sev, conf = "warning", "medium"
        else:
            sev, conf = "info", "low"
        rec_text = (f" {len(recovered)} of them resolved successfully in another lookup, so they probably did "
                    "not affect users." if recovered else "")
        if sev == "info":
            F.append(_f("dns_failures", "dns", "info", "low", "Isolated DNS failure",
                        f"{len(bad)} of {len(tx)} DNS lookups failed ({len(fails)} errors, {len(timeouts)} without "
                        f"an answer within {th.dns_timeout_s:.0f}s). One-off failures happen (a lost UDP packet, "
                        "a resolver hiccup) and the client normally retries." + rec_text,
                        ev, kt["verify"], metrics={"errors": len(fails), "timeouts": len(timeouts),
                                                   "recovered": len(recovered)},
                        wfilter="dns.flags.rcode != 0 || (dns.flags.response == 0 && !dns.response_in)"))
        else:
            F.append(_f("dns_failures", "dns", sev, conf, "DNS lookups failing",
                        f"{len(fails)} DNS queries got an error (SERVFAIL/REFUSED) and {len(timeouts)} got no answer "
                        f"within {th.dns_timeout_s:.0f}s. Applications cannot connect to a name they cannot "
                        "resolve, so users see 'site can't be reached' even when the network itself works."
                        + rec_text,
                        ev, kt["verify"], metrics={"errors": len(fails), "timeouts": len(timeouts),
                                                   "recovered": len(recovered)}, kt=kt,
                        wfilter="dns.flags.rcode != 0 || (dns.flags.response == 0 && !dns.response_in)"))

    if nx:
        benign = len(nx) - len(nx_real)
        ev = [_ev(t["query_frame"], t["time"], f"{t['qtype']} {t['name']} via {t['server']}: NXDOMAIN"
                  + (f" ({nxdomain_is_benign(t['name'])})" if nxdomain_is_benign(t["name"]) else ""))
              for t in (nx_real + [t for t in nx if t not in nx_real])[:10]]
        F.append(_f("dns_nxdomain", "dns", "warning" if len(nx_real) >= 3 else "info",
                    "medium" if nx_real else "high",
                    "DNS names that do not exist (NXDOMAIN)",
                    f"{len(nx)} lookups returned NXDOMAIN ('no such name'). {benign} look like normal client "
                    "behaviour (browser probes, search-list or local names). "
                    + (f"{len(nx_real)} are ordinary names: check for typos, a removed DNS record, or a wrong "
                       "DNS suffix." if nx_real else "None look like real faults."),
                    ev, ["Check the names listed against what the user typed or the app is configured with."],
                    metrics={"nxdomain": len(nx), "benign": benign}))

    slow_resolvers = [s for s in servers.values()
                      if s["median_ms"] is not None and s["median_ms"] >= th.dns_resolver_median_ms
                      and s["answered"] >= 3]
    if slow or slow_resolvers:
        ev = [_ev(t["query_frame"], t["time"], f"{t['qtype']} {t['name']} via {t['server']}: {t['latency_ms']:.0f} ms")
              for t in sorted(slow, key=lambda t: -t["latency_ms"])[:10]]
        fast_servers = [s for s in servers.values() if s["median_ms"] is not None
                        and s["median_ms"] < th.dns_resolver_median_ms / 2]
        rs = ", ".join(f"{s['server']} (median {s['median_ms']:.0f} ms, p95 {s['p95_ms']:.0f} ms)"
                       for s in slow_resolvers) if slow_resolvers else ""
        F.append(_f("dns_slow", "dns", "warning" if slow_resolvers or len(slow) >= 3 else "info",
                    "high" if len(slow) >= 5 else "medium" if len(slow) >= 2 else "low",
                    "Slow DNS responses",
                    f"{len(slow)} lookups took {th.dns_slow_ms:.0f} ms or longer. "
                    + (f"Slow resolver(s): {rs}. " if rs else "")
                    + "Every new hostname costs this delay before the connection even starts. A single slow "
                      "lookup is often a cache miss (the resolver had to ask the internet); consistently slow "
                      "lookups point at the resolver or the path to it."
                    + (f" For comparison, {', '.join(s['server'] for s in fast_servers)} answered quickly."
                       if fast_servers else ""),
                    ev, ["`Measure-Command { Resolve-DnsName example.com -Server <resolver> -DnsOnly }` "
                         "a few times; compare with 1.1.1.1 or 8.8.8.8.",
                         "Check the resolver's load and its upstream forwarders."],
                    metrics={"slow_lookups": len(slow), "slow_resolvers": [s["server"] for s in slow_resolvers]}))


# --------------------------------------------------------------------- TLS
def _tls_findings(r, th, F):
    sess = r["tls"]["sessions"]
    if not sess:
        return
    alerts = [s for s in sess if s["alert"]]
    if alerts:
        hints = {"unknown_ca": "the client does not trust the certificate chain (missing intermediate "
                               "certificate, self-signed cert, or TLS inspection by a firewall)",
                 "certificate_unknown": "certificate rejected by the client (untrusted, wrong name)",
                 "bad_certificate": "certificate rejected as invalid",
                 "certificate_expired": "the certificate has expired (or the client clock is wrong)",
                 "handshake_failure": "no cipher suite/parameters in common, or SNI not accepted",
                 "protocol_version": "TLS version mismatch (e.g. server only supports TLS 1.0)",
                 "unrecognized_name": "server does not host the requested name (SNI)",
                 "no_application_protocol": "ALPN mismatch (e.g. HTTP/2 only)"}
        ev = [_ev(s["alert_frame"], s["time"],
                  f"{s['alert_by']} sent '{s['alert']}' for {s['sni'] or s['server']}"
                  + (f": {hints[s['alert']]}" if s["alert"] in hints else "")) for s in alerts[:10]]
        ok = [s for s in sess if not s["alert"] and (s["setup_ms"] is not None or s["server_hello_ms"] is not None)]
        names = Counter(s["sni"] or s["server"] for s in alerts)
        kinds = Counter(s["alert"] for s in alerts)
        top = kinds.most_common(1)[0][0]
        trust = (top in ("unknown_ca", "certificate_unknown", "bad_certificate", "certificate_expired")
                 or top.startswith("encrypted alert"))
        causes = [
            {"cause": "Certificate problem: chain not trusted by the client (missing intermediate, self-signed, "
                      "expired, or replaced by a TLS-inspecting firewall)",
             "explains_is": trust, "contradicts": "" if trust else f"the alert is '{top}', not a certificate alert",
             "assumptions": 1},
            {"cause": "Protocol/cipher mismatch between client and server",
             "explains_is": top in ("handshake_failure", "protocol_version", "insufficient_security",
                                    "no_application_protocol"),
             "contradicts": "" if not trust else "a certificate alert means the handshake got as far as the "
                                                 "certificate, so version and cipher were agreed",
             "assumptions": 1},
            {"cause": "Network fault",
             "explains_is": False,
             "contradicts": "an alert is a deliberate message from one endpoint; the network delivered it",
             "assumptions": 2},
        ]
        _rank(causes)
        tls_kt = {
            "problem": "TLS handshakes are rejected",
            "spec": {
                "what": (", ".join(f"{k} ({v}x)" for k, v in kinds.items()),
                         "not a TCP failure: the TCP connections were established"),
                "where": (", ".join(f"{n} ({v}x)" for n, v in names.most_common(4)),
                          f"{len(ok)} other TLS sessions complete normally" if ok else "no other TLS sessions"),
                "when": _times_text([s["time"] for s in alerts], r["capture"]["duration_s"]),
                "extent": (f"{len(alerts)} handshake(s)", f"{len(ok)} successful"),
            },
            "distinctions": [f"Alerts sent by the {Counter(s['alert_by'] for s in alerts).most_common(1)[0][0]}"],
            "causes": causes,
            "verify": ["`openssl s_client -connect <host>:443 -servername <host> -showcerts` to see the chain.",
                       "Open the site in a browser and inspect the certificate (issuer, dates, name)."],
            "incident_fix": "Install the missing intermediate certificate / renew the certificate on the server.",
            "permanent_fix": "Monitor certificate expiry and chain completeness.",
        }
        F.append(_f("tls_alerts", "tls", "critical", "high",
                    "TLS handshakes failing",
                    f"{len(alerts)} TLS handshake(s) were aborted with an alert before encryption started. "
                    "The TCP connection worked; the secure session did not, so the application fails.",
                    ev, ["`openssl s_client -connect <host>:443 -servername <host>` shows the certificate "
                         "chain and the negotiated version.",
                         "Check the certificate dates and chain on the server, and the client's clock."],
                    metrics={"alerts": len(alerts)}, kt=tls_kt))
    slow = [s for s in sess if s["setup_ms"] is not None and s["setup_ms"] >= th.tls_slow_ms]
    if slow:
        ev = [_ev(s["client_hello_frame"], s["time"],
                  f"{s['sni'] or s['server']}: TLS setup {s['setup_ms']:.0f} ms (ServerHello after "
                  f"{s['server_hello_ms'] or 0:.0f} ms)") for s in sorted(slow, key=lambda s: -s["setup_ms"])[:8]]
        F.append(_f("tls_slow", "tls", "warning", "medium",
                    "Slow TLS handshakes",
                    f"{len(slow)} TLS handshake(s) took {th.tls_slow_ms:.0f} ms or more. If the ServerHello itself "
                    "is slow, the server is busy (or doing OCSP/CRL checks); if the gap is after it, the client "
                    "is slow (certificate validation, proxy).", ev,
                    ["Compare the ServerHello delay with the TCP handshake RTT of the same connection."],
                    metrics={"slow_handshakes": len(slow)}))
    old = [s for s in sess if s["version"] in ("SSL 3.0", "TLS 1.0", "TLS 1.1")]
    if old:
        ev = [_ev(s["server_hello_frame"], s["time"], f"{s['sni'] or s['server']}: negotiated {s['version']}")
              for s in old[:8]]
        F.append(_f("tls_old_version", "tls", "warning", "high",
                    "Outdated TLS versions in use",
                    f"{len(old)} session(s) negotiated a deprecated protocol (TLS 1.1 or older). Not a "
                    "performance problem, but a security finding that most audits flag.",
                    ev, ["Enable TLS 1.2/1.3 on the server and disable older versions."]))


# --------------------------------------------------------------------- ICMP
def _icmp_findings(r, F):
    rows = r["traffic"]["icmp"]
    mtu = [x for x in rows if (x["proto"], x["type"], x["code"]) == ("ICMP", 3, 4)
           or (x["proto"], x["type"]) == ("ICMPv6", 2)]
    unreach = [x for x in rows if (x["proto"] == "ICMP" and x["type"] == 3 and x["code"] != 4)
               or (x["proto"], x["type"]) == ("ICMPv6", 1)]
    ttl = [x for x in rows if (x["proto"], x["type"]) in (("ICMP", 11), ("ICMPv6", 3))]
    if mtu:
        n = sum(x["count"] for x in mtu)
        ev = [_ev(e["frame"], e["time"], f"{e['src']} says MTU {e.get('mtu', '?')} towards {e.get('orig_dst', '?')}")
              for x in mtu for e in x["examples"]][:8]
        F.append(_f("icmp_mtu", "icmp", "warning", "high",
                    "Path MTU smaller than the packets being sent",
                    f"{n} 'fragmentation needed' / 'packet too big' messages: a router on the path cannot forward "
                    "packets this large. This is Path MTU Discovery working; if these ICMP messages were blocked, "
                    "large transfers would hang while small ones work (the classic MTU black hole). Common with "
                    "VPNs and PPPoE.",
                    ev, ["`ping -f -l 1472 <host>` (Windows) and lower the size until it passes to find the "
                         "path MTU.", "Check MTU/MSS clamping on the VPN or PPPoE interface."],
                    metrics={"messages": n}))
    if unreach:
        n = sum(x["count"] for x in unreach)
        kinds = ", ".join(f"{x['name']} ({x['count']})" for x in unreach[:4])
        ev = [_ev(e["frame"], e["time"], f"{e['src']} → {e['dst']}: {x['name']} for {e.get('orig_dst', '?')}")
              for x in unreach for e in x["examples"]][:8]
        F.append(_f("icmp_unreachable", "icmp", "info", "high",
                    "ICMP destination unreachable messages",
                    f"{n} 'destination unreachable' messages ({kinds}). Port unreachable after a UDP packet means "
                    "nothing listens on that port; host/network unreachable or administratively prohibited come "
                    "from routers and firewalls.",
                    ev, ["Check the listed destinations and ports against what should be reachable."],
                    metrics={"messages": n}))
    if ttl:
        n = sum(x["count"] for x in ttl)
        ev = [_ev(e["frame"], e["time"], f"from {e['src']} to {e['dst']}") for x in ttl for e in x["examples"]][:5]
        F.append(_f("icmp_ttl", "icmp", "info", "medium", "TTL expired messages",
                    f"{n} 'time exceeded' messages. Normal if someone ran traceroute; repeated ones for ordinary "
                    "traffic suggest a routing loop.", ev,
                    ["Check whether a traceroute was running at the time."], metrics={"messages": n}))


# --------------------------------------------------------------------- assemble
def _checked_clean(r, F):
    keys = {f["key"] for f in F if not f["artefact"]}
    conns = r["tcp"]["connections"]
    tx = r["dns"]["transactions"]
    sess = r["tls"]["sessions"]
    data_segs = sum(c["dirs"][x]["data_segments"] for c in conns for x in ("c2s", "s2c"))
    retx = sum(c["dirs"][x]["retrans_real"] for c in conns for x in ("c2s", "s2c"))
    out = []
    if conns and "tcp_loss" not in keys:
        out.append(f"TCP loss: {retx} retransmissions in {data_segs:,} data segments "
                   f"({100 * retx / data_segs:.2f}%)" if data_segs else "TCP loss: no data segments")
    if conns and "tcp_zero_window" not in keys:
        out.append("Receiver windows: no zero-window stalls")
    if conns and "tcp_connect_fail" not in keys:
        hs = sum(1 for c in conns if c["handshake"].get("synack_frame"))
        out.append(f"Connection setup: {hs} handshakes completed, none refused or unanswered")
    if conns and "tcp_slow_response" not in keys:
        out.append("Server response time: no slow request/response turns")
    if tx and not keys & {"dns_failures"}:
        ok = [t for t in tx if t["latency_ms"] is not None]
        med = median(t["latency_ms"] for t in ok) if ok else None
        out.append(f"DNS: {len(tx)} lookups, no errors or timeouts"
                   + (f", median {med:.0f} ms" if med is not None else ""))
    if sess and "tls_alerts" not in keys:
        out.append(f"TLS: {len(sess)} handshakes, none aborted")
    return out


def _limitations(r):
    cap = r["capture"]
    lim = ["One capture point: problems elsewhere on the path are inferred, not seen directly."]
    if cap["duration_s"] < 10:
        lim.append(f"Short capture ({cap['duration_s']:.1f}s): intermittent problems may be missed.")
    svc = {s["service"]: s["bytes"] for s in r["traffic"]["services"]}
    if svc.get("QUIC") and cap["bytes"]:
        share = 100 * svc["QUIC"] / cap["bytes"]
        lim.append(f"{share:.0f}% of bytes are QUIC (HTTP/3 over UDP 443). QUIC is fully encrypted, so loss "
                   "and handshake timing are not measured for it.")
    if r["dns"]["dot_packets"]:
        lim.append("DNS-over-TLS (port 853) is in use; those lookups are encrypted and not analysed.")
    if r["tls"]["sessions"]:
        lim.append("Encrypted payloads are not decrypted: only TLS handshakes and TCP behaviour are analysed.")
    if cap["stopped_early"]:
        lim.append("Analysis stopped early (--max-packets); later frames were not read.")
    for w in cap["warnings"]:
        if w not in lim:
            lim.append(w)
    return lim


def diagnose(r, th):
    F = []
    _capture_findings(r, th, F)
    _loss_findings(r, th, F)
    _window_findings(r, th, F)
    _handshake_findings(r, th, F)
    _response_findings(r, th, F)
    _dns_findings(r, th, F)
    _tls_findings(r, th, F)
    _icmp_findings(r, F)
    F.sort(key=lambda f: (f["artefact"], SEV_RANK[f["severity"]], CONF_RANK[f["confidence"]]))
    for i, f in enumerate(F, 1):
        f["id"] = f"F{i}"

    problems = []
    for f in F:
        if f["kt"] and not f["artefact"] and f["severity"] in ("critical", "warning"):
            k = dict(f["kt"])
            k["finding"] = f["id"]
            k["severity"] = f["severity"]
            k["confidence"] = f["confidence"]
            best = next((c for c in k["causes"] if c["verdict"] == "most probable"), None)
            k["most_probable"] = best["cause"] if best else "Not determined: no candidate survived all tests"
            if best is None:
                k["confidence"] = "low"
            problems.append(k)
    real = [f for f in F if not f["artefact"]]
    if any(f["severity"] == "critical" for f in real):
        health = "problems"
    elif any(f["severity"] == "warning" for f in real):
        health = "attention"
    else:
        health = "healthy"
    if problems:
        p = problems[0]
        headline = f"{p['problem']}. Most probable cause ({p['confidence']} confidence): {p['most_probable']}."
    elif health in ("problems", "attention"):
        w = next(f for f in real if f["severity"] in ("critical", "warning"))
        headline = f"{w['title']}. {w['summary'].split('. ')[0].rstrip('.')}."
    else:
        headline = ("No network problems found in this capture. If users still report trouble, the cause is "
                    "probably outside what this capture saw (another path, the endpoint, or a different time).")
    quic = next((x["bytes"] for x in r["traffic"]["services"] if x["service"] == "QUIC"), 0)
    if health == "healthy" and r["capture"]["bytes"] and quic / r["capture"]["bytes"] >= 0.3:
        headline += (f" Note: {100 * quic / r['capture']['bytes']:.0f}% of the traffic is QUIC (encrypted UDP), "
                     "which this tool cannot check for loss or delay.")
    if r["capture"]["stopped_early"]:
        headline = f"(Only the first {r['capture']['packets']:,} frames were analysed.) " + headline
    artefacts = [f["title"] for f in F if f["artefact"]]
    if artefacts and health == "healthy":
        headline += (f" {len(artefacts)} capture-point artefact(s) were found and kept out of the diagnosis; "
                     "see the findings.")
    diagnosis = {"health": health, "headline": headline, "problems": problems,
                 "checked_clean": _checked_clean(r, F), "artefacts": artefacts,
                 "limitations": _limitations(r),
                 "capture_point": r["tcp"]["capture_point"]["text"]}
    return F, diagnosis
