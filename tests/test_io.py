"""Reader robustness, report safety, CLI and web upload."""
import json
import os

import dpkt
import pytest

from packet_doctor.analyse import analyse
from packet_doctor.cli import main
from packet_doctor.reader import CaptureError, iter_packets
from packet_doctor.report import render_html
from packet_doctor.synth import Capture, dns_exchange

PCAP_MAGIC_LE = bytes([0xD4, 0xC3, 0xB2, 0xA1])




def test_pcap_and_pcapng_give_identical_results(corpus):
    # Timestamps can differ by 1 microsecond (the two writers round differently),
    # so compare everything that does not depend on sub-microsecond timing.
    a = corpus["loss_one_server"][2]
    b = corpus["loss_one_server_pcapng"][2]
    assert a["tcp"]["flag_frames"] == b["tcp"]["flag_frames"]
    assert [(f["key"], f["severity"], f["confidence"]) for f in a["findings"]] == \
           [(f["key"], f["severity"], f["confidence"]) for f in b["findings"]]
    assert a["diagnosis"]["headline"] == b["diagnosis"]["headline"]
    assert a["capture"]["packets"] == b["capture"]["packets"]
    assert a["capture"]["bytes"] == b["capture"]["bytes"]


def test_not_a_capture(tmp_path):
    p = tmp_path / "notes.pcap"
    p.write_text("hello")
    with pytest.raises(CaptureError):
        list(iter_packets(str(p)))


def test_truncated_file_keeps_earlier_frames(corpus, tmp_path):
    src = corpus["loss_one_server"][0]
    data = open(src, "rb").read()
    p = tmp_path / "cut.pcap"
    p.write_bytes(data[: len(data) - 700])
    r = analyse(str(p))
    assert 0 < r["capture"]["packets"] < corpus["loss_one_server"][2]["capture"]["packets"]
    assert any("cut off" in w for w in r["capture"]["warnings"])


def test_max_packets(corpus):
    r = analyse(corpus["loss_local_link"][0], max_packets=50)
    assert r["capture"]["packets"] == 50 and r["capture"]["stopped_early"]


def test_ipv6_parsed(corpus):
    r = corpus["healthy_browsing"][2]
    assert any(":" in c["client"] for c in r["tcp"]["connections"])


def test_html_escapes_hostile_names(tmp_path):
    cap = Capture("xss", "hostile DNS name")
    dns_exchange(cap, 1_700_000_000.0, "<img src=x onerror=alert(1)>.example", 1, None)
    dns_exchange(cap, 1_700_000_005.0, "ok.example", 2, 0.01)
    path = cap.write(str(tmp_path))
    html = render_html(analyse(path))
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_cli_writes_all_outputs(corpus, tmp_path, capsys):
    rc = main(["analyse", corpus["zero_window"][0], "-o", str(tmp_path), "--fail-on-problems"])
    assert rc == 1                       # critical problem -> non-zero with --fail-on-problems
    names = sorted(os.listdir(tmp_path))
    stem = "zero_window.pcap"
    assert names == sorted([f"{stem}.report.html", f"{stem}.report.json", f"{stem}.findings.csv",
                            f"{stem}.connections.csv", f"{stem}.dns.csv"])
    data = json.load(open(tmp_path / f"{stem}.report.json", encoding="utf-8"))
    assert data["diagnosis"]["health"] == "problems"
    assert "PROBLEMS FOUND" in capsys.readouterr().out


def test_web_upload(corpus):
    import io
    import re
    from packet_doctor.web import create_app
    app = create_app(max_upload_mb=5)
    client = app.test_client()
    page = client.get("/")
    assert page.status_code == 200
    tok = re.search(r'name="token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    with open(corpus["slow_server"][0], "rb") as f:
        resp = client.post("/analyse", data={"token": tok, "capture": (f, "slow_server.pcap")},
                           content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"Slow server responses" in resp.data
    resp = client.post("/analyse", data={"token": tok, "capture": (io.BytesIO(b"not a capture"), "x.pcap")},
                       content_type="multipart/form-data")
    assert resp.status_code == 400 and b"not a pcap" in resp.data
    resp = client.post("/analyse", data={"token": tok,
                                         "capture": (io.BytesIO(PCAP_MAGIC_LE + b"0" * (6 * 1024 * 1024)),
                                                     "big.pcap")}, content_type="multipart/form-data")
    assert resp.status_code == 413


def test_unsupported_linktype(tmp_path):
    p = tmp_path / "wifi.pcap"
    with open(p, "wb") as f:
        w = dpkt.pcap.Writer(f, linktype=127)   # 802.11 radiotap
        w.writepkt(b"\x00" * 40, ts=1.0)
    with pytest.raises(CaptureError):
        analyse(str(p))
