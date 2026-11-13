"""Command-line interface: ``packet-doctor analyse|serve|judge|make-samples|demo``."""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import webbrowser
from pathlib import Path

from . import __version__

SEV_ICON = {"critical": "[X]", "warning": "[!]", "info": "[i]"}
BIG_FILE_MB = 1024


def _utf8_stdout():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _print_summary(r: dict, paths: dict | None = None) -> None:
    d = r["diagnosis"]
    cap = r["capture"]
    label = {"healthy": "HEALTHY", "attention": "NEEDS ATTENTION", "problems": "PROBLEMS FOUND"}[d["health"]]
    print(f"\n{cap['file']}: {cap['packets']:,} frames, {cap['duration_s']:.1f}s, "
          f"analysed in {cap['analysis_seconds']}s")
    print(f"\n  {label}: {d['headline']}\n")
    for f in r["findings"]:
        tag = "artefact" if f["artefact"] else f["severity"]
        print(f"  {SEV_ICON[f['severity']]} {f['id']} {f['title']}  ({tag}, {f['confidence']} confidence)")
    if not r["findings"]:
        print("  No findings.")
    for w in cap["warnings"]:
        print(f"\n  WARNING: {w}")
    if paths:
        print("\nReport files:")
        for k, p in paths.items():
            print(f"  {k:16} {os.path.abspath(p)}")


def cmd_analyse(a) -> int:
    from .analyse import Thresholds, analyse
    from .reader import CaptureError
    from .report import write_outputs
    rc = 0
    for path in a.files:
        if not os.path.isfile(path):
            print(f"error: {path}: file not found", file=sys.stderr)
            rc = 2
            continue
        size_mb = os.path.getsize(path) / 1e6
        if size_mb > a.max_size_mb:
            print(f"error: {path} is {size_mb:,.0f} MB, above --max-size-mb {a.max_size_mb}. Split it with "
                  "`editcap -c 1000000 in.pcapng part.pcapng` or raise the limit.", file=sys.stderr)
            rc = 2
            continue
        if size_mb > BIG_FILE_MB:
            print(f"note: {size_mb:,.0f} MB capture; reading is streamed, expect roughly a minute per "
                  "million frames.", file=sys.stderr)
        th = Thresholds()
        if a.retrans_warn is not None:
            th.retrans_warn_pct = a.retrans_warn
        if a.high_rtt is not None:
            th.high_rtt_ms = a.high_rtt
        try:
            r = analyse(path, max_packets=a.max_packets, thresholds=th)
        except CaptureError as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            rc = 2
            continue
        except OSError as exc:
            print(f"error: {path}: cannot read file: {exc}", file=sys.stderr)
            rc = 2
            continue
        j = None
        if a.judge and a.max_packets:
            print("note: --judge skipped because --max-packets analysed only part of the file", file=sys.stderr)
        elif a.judge:
            from .judge import judge
            j = judge(path, result=r)
            if not j.get("available"):
                print(f"note: {j['reason']}", file=sys.stderr)
                j = None
        try:
            paths = write_outputs(r, a.out, judge=j)
        except OSError as exc:
            print(f"error: cannot write reports to {a.out}: {exc}", file=sys.stderr)
            return 2
        _print_summary(r, paths)
        if j:
            print(f"\nWireshark cross-check: {j['overall_flag_agreement_pct']}% agreement on TCP expert flags")
        if a.open:
            webbrowser.open(Path(paths["html"]).resolve().as_uri())
        if r["diagnosis"]["health"] == "problems" and a.fail_on_problems:
            rc = max(rc, 1)
        if r["capture"]["warnings"] and not r["capture"]["stopped_early"]:
            rc = max(rc, 3)          # analysed, but the file was damaged or partly unreadable
    return rc


def cmd_judge(a) -> int:
    from .judge import find_tshark, judge, judge_csv, judge_table
    if not find_tshark():
        print("tshark not found: install Wireshark (with TShark) or set PACKET_DOCTOR_TSHARK.", file=sys.stderr)
        return 2
    from .reader import CaptureError
    results, rc = [], 0
    for path in a.files:
        try:
            j = judge(path)
        except (CaptureError, OSError, RuntimeError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            rc = 2
            continue
        results.append(j)
        print(judge_table(j))
        print()
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=1)
    if a.csv:
        with open(a.csv, "w", encoding="utf-8", newline="") as f:
            f.write(judge_csv(results))
    return rc


def cmd_samples(a) -> int:
    from .synth import make_samples
    for p in make_samples(a.directory):
        print(p)
    return 0


def cmd_validate(a) -> int:
    """Score the analyser against the synthetic corpus's ground truth."""
    from .scoring import markdown_table, score_corpus
    from .synth import make_samples
    if not glob.glob(os.path.join(a.samples, "*.truth.json")):
        make_samples(a.samples)
    scores = score_corpus(a.samples)
    print(markdown_table(scores))
    bad = [s for s in scores if s["findings_missing"] or s["findings_forbidden_present"]
           or s["cause_ok"] is False or any(r["missed"] or r["false"] for r in s["events"])]
    return 1 if bad else 0


def cmd_demo(a) -> int:
    """Generate the synthetic corpus (if missing) and write a report for each file."""
    from .analyse import analyse
    from .report import write_outputs
    from .synth import make_samples
    if not glob.glob(os.path.join(a.samples, "*.pcap*")):
        make_samples(a.samples)
    files = sorted(glob.glob(os.path.join(a.samples, "*.pcap")) + glob.glob(os.path.join(a.samples, "*.pcapng")))
    for p in files:
        r = analyse(p)
        write_outputs(r, a.out)
        print(f"{r['diagnosis']['health']:9}  {os.path.basename(p):32} {r['diagnosis']['headline'][:90]}")
    print(f"\nReports written to {os.path.abspath(a.out)}")
    return 0


def cmd_serve(a) -> int:
    from .web import create_app
    app = create_app(max_upload_mb=a.max_upload_mb)
    url = f"http://127.0.0.1:{a.port}/"
    print(f"Packet Doctor is running at {url}  (only this computer can reach it; Ctrl+C to stop)")
    if not a.no_browser:
        webbrowser.open(url)
    app.run(host="127.0.0.1", port=a.port, debug=False, use_reloader=False)
    return 0


def _positive_int(v: str) -> int:
    n = int(v)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="packet-doctor",
                                description="Plain-English diagnosis of pcap/pcapng captures.")
    p.add_argument("--version", action="version", version=f"packet-doctor {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("analyse", aliases=["analyze"], help="analyse capture file(s) and write reports")
    s.add_argument("files", nargs="+")
    s.add_argument("-o", "--out", default="reports", help="output folder (default: reports)")
    s.add_argument("--max-packets", type=_positive_int, help="stop after this many frames")
    s.add_argument("--max-size-mb", type=float, default=4000, help="refuse files larger than this (default 4000)")
    s.add_argument("--judge", action="store_true", help="also cross-check against Wireshark's tshark")
    s.add_argument("--open", action="store_true", help="open the HTML report in the browser")
    s.add_argument("--retrans-warn", type=float, help="retransmission %% that counts as a problem (default 1)")
    s.add_argument("--high-rtt", type=float, help="handshake RTT in ms considered high (default 300)")
    s.add_argument("--fail-on-problems", action="store_true", help="exit code 1 if critical problems are found")
    s.set_defaults(func=cmd_analyse)

    s = sub.add_parser("serve", help="start the local upload page")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--max-upload-mb", type=int, default=200)
    s.add_argument("--no-browser", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("judge", help="compare Packet Doctor's TCP flags with Wireshark (needs tshark)")
    s.add_argument("files", nargs="+")
    s.add_argument("--json", help="write full results to this JSON file")
    s.add_argument("--csv", help="write the agreement table to this CSV file")
    s.set_defaults(func=cmd_judge)

    s = sub.add_parser("make-samples", help="write the synthetic test captures and their ground truth")
    s.add_argument("directory", nargs="?", default="samples")
    s.set_defaults(func=cmd_samples)

    s = sub.add_parser("validate", help="print the detection table (found/missed/false) for the synthetic corpus")
    s.add_argument("samples", nargs="?", default="samples")
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("demo", help="analyse every sample capture and write reports")
    s.add_argument("--samples", default="samples")
    s.add_argument("--out", default="sample_reports")
    s.set_defaults(func=cmd_demo)
    return p


def main(argv=None) -> int:
    _utf8_stdout()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
