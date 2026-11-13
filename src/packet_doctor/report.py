"""Render results as a self-contained HTML report, JSON and CSV files."""
from __future__ import annotations

import csv
import io
import json
import os

import re

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup, escape

from . import charts

JSON_FRAME_CAP = 5000
EMBED_LIMIT = 8 * 1024 * 1024     # bytes of export data embedded in the HTML


_CODE = re.compile(r"`([^`]+)`")
_EM = re.compile(r"\*([^*\s][^*]*)\*")


def md_inline(text) -> Markup:
    """Escape, then render `code` and *emphasis* (the only markup findings use)."""
    s = str(escape(text if text is not None else ""))
    s = _CODE.sub(r"<code>\1</code>", s)
    s = _EM.sub(r"<em>\1</em>", s)
    return Markup(s)


def _env() -> Environment:
    env = Environment(loader=PackageLoader("packet_doctor", "templates"),
                      autoescape=select_autoescape(["html", "j2"]), trim_blocks=True, lstrip_blocks=True)
    env.filters["bytes"] = human_bytes
    env.filters["md"] = md_inline
    env.filters["num"] = lambda v: f"{v:,}" if isinstance(v, int) else v
    env.filters["ms"] = lambda v: "–" if v is None else (f"{v:.1f} ms" if v < 1000 else f"{v / 1000:.2f} s")
    return env


def human_bytes(n) -> str:
    if n is None:
        return "–"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            break
        n /= 1024
    return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"


def export_json(result: dict) -> str:
    """JSON export. Per-flag frame lists are capped so huge captures stay usable."""
    out = {k: v for k, v in result.items() if not k.startswith("_")}
    tcp = dict(out["tcp"])
    tcp["flag_frames"] = {k: v[:JSON_FRAME_CAP] for k, v in tcp["flag_frames"].items()}
    tcp["rst_frames"] = tcp["rst_frames"][:JSON_FRAME_CAP]
    out["tcp"] = tcp
    return json.dumps(out, indent=1, default=str)


def _csv(rows: list, header: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def findings_csv(result: dict) -> str:
    rows = []
    for f in result["findings"]:
        frames = " ".join(str(e["frame"]) for e in f["evidence"] if e.get("frame"))
        rows.append([f["id"], f["severity"], f["confidence"], "yes" if f["artefact"] else "no", f["category"],
                     f["key"], f["title"], f["summary"], frames, f["wireshark_filter"]])
    return _csv(rows, ["id", "severity", "confidence", "capture_artefact", "category", "key", "title",
                       "summary", "evidence_frames", "wireshark_filter"])


def connections_csv(result: dict) -> str:
    rows = []
    for c in result["tcp"]["connections"]:
        h, cs, sc = c["handshake"], c["dirs"]["c2s"], c["dirs"]["s2c"]
        rows.append([c["id"], c["client"], c["client_port"], c["server"], c["server_port"], c["service"],
                     (c.get("tls") or {}).get("sni", ""), c["outcome"], c["start"], c["duration_s"], c["frames"],
                     cs["data_bytes"], sc["data_bytes"], h.get("irtt_ms"), h.get("server_side_ms"),
                     h.get("client_side_ms"), cs["retrans_real"], cs["retrans_pct"], sc["retrans_real"],
                     sc["retrans_pct"], c["counts"].get("duplicate_ack", 0), c["counts"].get("zero_window", 0),
                     c["counts"].get("out_of_order", 0), c["responses"]["median_ms"], c["responses"]["slow_count"],
                     (c.get("tls") or {}).get("setup_ms"), c["throughput_mbps"], c["filter"]])
    return _csv(rows, ["id", "client", "client_port", "server", "server_port", "service", "sni", "outcome",
                       "start_s", "duration_s", "frames", "bytes_client_to_server", "bytes_server_to_client",
                       "handshake_rtt_ms", "server_side_rtt_ms", "client_side_rtt_ms", "retrans_c2s",
                       "retrans_pct_c2s", "retrans_s2c", "retrans_pct_s2c", "dup_acks", "zero_windows",
                       "out_of_order", "median_response_ms", "slow_responses", "tls_setup_ms",
                       "throughput_mbps", "wireshark_filter"])


def dns_csv(result: dict) -> str:
    rows = [[t["time"], t["query_frame"], t["response_frame"], t["client"], t["server"], t["name"], t["qtype"],
             t["status"], t["rcode"], t["latency_ms"], t["retries"]] for t in result["dns"]["transactions"]]
    return _csv(rows, ["time_s", "query_frame", "response_frame", "client", "server", "name", "type", "status",
                       "rcode", "latency_ms", "retries"])


def _events(result: dict) -> list:
    ev = []
    for f in result["findings"]:
        if f["artefact"] or f["severity"] == "info":
            continue
        for e in f["evidence"]:
            if e.get("time") is not None:
                ev.append((e["time"], f["severity"], f"{f['title']}: {e['text']}"))
    # every retransmission / zero window frame we kept as an example
    for c in result["tcp"]["connections"]:
        for k, sev, label in (("retransmission", "warning", "retransmission"),
                              ("fast_retransmission", "warning", "fast retransmission"),
                              ("zero_window", "critical", "zero window")):
            for e in c["examples"].get(k, []):
                ev.append((e["time"], sev, f"{label}, frame {e['frame']} ({c['server']})"))
    for t in result["dns"]["transactions"]:
        if t["status"] in ("servfail", "refused", "timeout", "error"):
            ev.append((t["time"], "critical", f"DNS {t['status']} {t['name']} (frame {t['query_frame']})"))
    ev.sort()
    return ev


def build_charts(result: dict) -> dict:
    out = {"throughput": charts.throughput_chart(result["traffic"]["timeline"], _events(result))}
    # handshake RTT by server (median over that server's connections)
    by_srv = {}
    for c in result["tcp"]["connections"]:
        v = c["handshake"].get("irtt_ms")
        if v is not None:
            key = (c.get("tls") or {}).get("sni") or c["server"]
            by_srv.setdefault(key, []).append(v)
    rows = []
    for k, vals in by_srv.items():
        vals.sort()
        med = vals[len(vals) // 2]
        rows.append((k, med, f"{k}: median handshake RTT {med:.1f} ms over {len(vals)} connection(s)"))
    rows.sort(key=lambda r: -r[1])
    out["rtt"] = charts.hbar_chart(rows[:15], unit=" ms", mark_threshold=result["thresholds"]["high_rtt_ms"]) \
        if rows else ""
    talkers = result["traffic"]["top_talkers"]
    trows = [(t["host"], t["total_bytes"], f"{t['host']}: sent {human_bytes(t['tx_bytes'])}, "
              f"received {human_bytes(t['rx_bytes'])}") for t in talkers]
    out["talkers"] = charts.hbar_chart(trows, value_fmt=human_bytes) if trows else ""
    loss = []
    for c in result["tcp"]["connections"]:
        for lab in ("c2s", "s2c"):
            d = c["dirs"][lab]
            if d["retrans_real"]:
                name = f"{d['sender']} → {c['server'] if d['sender'] == c['client'] else c['client']}"
                loss.append((name, d["retrans_pct"], f"{name}: {d['retrans_real']} of {d['data_segments']} "
                                                     f"data segments retransmitted"))
    loss.sort(key=lambda r: -r[1])
    out["loss"] = charts.hbar_chart(loss[:15], unit=" %", mark_threshold=result["thresholds"]["retrans_warn_pct"]) \
        if loss else ""
    return out


def render_html(result: dict, judge: dict | None = None) -> str:
    env = _env()
    tpl = env.get_template("report.html.j2")
    conns = sorted(result["tcp"]["connections"],
                   key=lambda c: -(c["dirs"]["c2s"]["data_bytes"] + c["dirs"]["s2c"]["data_bytes"]))
    dns = sorted(result["dns"]["transactions"],
                 key=lambda t: (t["status"] == "ok", -(t["latency_ms"] or 0)))
    exports = {"json": export_json(result), "findings": findings_csv(result),
               "connections": connections_csv(result), "dns": dns_csv(result)}
    if sum(len(v) for v in exports.values()) > EMBED_LIMIT:
        exports = None     # too big to embed: the CLI writes them as separate files
    return tpl.render(r=result, charts=build_charts(result), conns=conns[:100], n_conns=len(conns),
                      dns=dns[:200], judge=judge, exports=exports,
                      stem=result["capture"]["file"])


def write_outputs(result: dict, out_dir: str, judge: dict | None = None) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    stem = result["capture"]["file"]
    paths = {
        "html": os.path.join(out_dir, f"{stem}.report.html"),
        "json": os.path.join(out_dir, f"{stem}.report.json"),
        "findings_csv": os.path.join(out_dir, f"{stem}.findings.csv"),
        "connections_csv": os.path.join(out_dir, f"{stem}.connections.csv"),
        "dns_csv": os.path.join(out_dir, f"{stem}.dns.csv"),
    }
    with open(paths["html"], "w", encoding="utf-8") as f:
        f.write(render_html(result, judge))
    with open(paths["json"], "w", encoding="utf-8") as f:
        f.write(export_json(result))
    for key, fn in (("findings_csv", findings_csv), ("connections_csv", connections_csv), ("dns_csv", dns_csv)):
        with open(paths[key], "w", encoding="utf-8", newline="") as f:
            f.write(fn(result))
    return paths
