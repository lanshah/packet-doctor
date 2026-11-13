"""Regression tests for the defects found by the multi-judge code review."""
import io
import os
import re
import struct

import dpkt
import pytest

from packet_doctor.analyse import analyse
from packet_doctor.cli import main
from packet_doctor.reader import CaptureError, iter_packets
from packet_doctor.synth import (CLIENT, T0, TCP, Capture, client_hello, dns_exchange,
                                 server_hello)

AP = dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH


def _write(cap, tmp_path, fmt="pcap"):
    return cap.write(str(tmp_path), fmt)


def keys(r):
    return {f["key"] for f in r["findings"]}


# --------------------------------------------------------------- TCP / timing
def test_zero_window_stall_ends_at_reset(tmp_path):
    cap = Capture("zw_rst", "zero window then RST, capture continues 30 s")
    c = TCP(cap, CLIENT, 40000, "198.51.100.9", 80, wscale=None)
    t = c.handshake(T0)
    c.send(t + 0.001, False, b"x" * 1000)
    c.ack(t + 0.01, True, win=0)
    c.seg(t + 0.15, True, dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK, win=0)
    dns_exchange(cap, t + 30, "late.example", 7, 0.01)     # keeps the capture running
    r = analyse(_write(cap, tmp_path))
    d = r["tcp"]["connections"][0]["dirs"]["c2s"]
    assert d["zero_window_total_s"] == pytest.approx(0.14, abs=0.01)
    assert not any(f["key"] == "tcp_zero_window" and f["severity"] == "critical" for f in r["findings"])


def test_push_after_small_reply_is_not_a_slow_server(tmp_path):
    cap = Capture("push", "plain request, quick small reply, unsolicited push 2 s later")
    c = TCP(cap, CLIENT, 40001, "198.51.100.10", 8080)
    t = c.handshake(T0)
    c.send(t + 0.001, True, b"GET /events HTTP/1.1\r\n\r\n")
    c.send(t + 0.03, False, b"y" * 200)
    c.ack(t + 0.031, True)
    c.send(t + 2.03, False, b"z" * 300)                      # server push, no request
    c.ack(t + 2.031, True)
    r = analyse(_write(cap, tmp_path))
    assert "tcp_slow_response" not in keys(r)


def test_retransmitted_request_is_timed_from_the_retransmission(tmp_path):
    cap = Capture("req_retx", "request lost once, re-sent after 1 s, answered quickly")
    c = TCP(cap, CLIENT, 40002, "198.51.100.11", 80)
    t = c.handshake(T0)
    req = b"GET / HTTP/1.1\r\n\r\n"
    seq = c.cseq
    c.send(t + 0.001, True, req)
    c.seg(t + 1.001, True, AP, payload=req, seq=seq)        # retransmission
    c.send(t + 1.03, False, b"HTTP/1.1 200 OK\r\n\r\n")
    c.ack(t + 1.031, True)
    r = analyse(_write(cap, tmp_path))
    assert "tcp_slow_response" not in keys(r)


def test_ipv6_mirror_duplicates_are_not_loss(tmp_path):
    cap = Capture("v6dup", "IPv6 download where every 10th frame is captured twice")
    c = TCP(cap, "2001:db8:1::50", 40003, "2001:db8:2::99", 443)
    t = c.handshake(T0)
    for i in range(60):
        seq = c.sseq
        tt = t + 0.01 + i * 0.0005
        c.seg(tt, False, dpkt.tcp.TH_ACK, payload=b"d" * 1200, seq=seq)
        if i % 10 == 5:
            c.seg(tt + 0.000003, False, dpkt.tcp.TH_ACK, payload=b"d" * 1200, seq=seq)
        c.sseq += 1200
        c.c_ack = c.sseq
        if i % 2:
            c.ack(tt + 0.0001, True)
    r = analyse(_write(cap, tmp_path))
    assert r["tcp"]["connections"][0]["duplicate_frames"] == 6
    assert "tcp_loss" not in keys(r)
    assert "capture_duplicates" in keys(r)


def test_sequence_wraparound_gives_same_flags():
    """The loss scenario with ISNs just below 2^32 must flag the same frames."""
    from packet_doctor import synth
    a = synth.sc_loss_one_server()
    orig = synth.TCP.__init__

    def wrapped(self, *args, **kw):
        orig(self, *args, **kw)
        self.c_isn = self.cseq = (0xFFFFFF00 + self.c_isn) & 0xFFFFFFFF
        self.s_isn = self.sseq = (0xFFFFF000 + self.s_isn) & 0xFFFFFFFF
    synth.TCP.__init__ = wrapped
    try:
        b = synth.sc_loss_one_server()
    finally:
        synth.TCP.__init__ = orig
    import tempfile
    d = tempfile.mkdtemp()
    a.name, b.name = "plain", "wrapped"
    ra, rb = analyse(a.write(d)), analyse(b.write(d))
    assert ra["tcp"]["flag_frames"] == rb["tcp"]["flag_frames"]
    assert ra["tcp"]["flag_totals"]["retransmission"] == 5


def test_handshake_split_uses_most_recent_syn(tmp_path):
    cap = Capture("synretry", "first SYN lost, retried after 1 s")
    c = TCP(cap, CLIENT, 40004, "198.51.100.12", 443, rtt=0.02)
    c.seg(T0, True, dpkt.tcp.TH_SYN, seq=c.c_isn, ack=0, win=64240, opts=TCP._syn_opts(1460, 6))
    c.handshake(T0 + 1.0)
    r = analyse(_write(cap, tmp_path))
    hs = r["tcp"]["connections"][0]["handshake"]
    assert hs["server_side_ms"] == pytest.approx(20, abs=0.5)
    assert hs["irtt_ms"] == pytest.approx(20.3, abs=0.5)


def test_bulk_transfer_loss_is_attributed_to_congestion(tmp_path):
    cap = Capture("bulk", "one big download with loss plus small clean connections")
    t = T0
    big = TCP(cap, CLIENT, 40005, "203.0.113.200", 443, rtt=0.02)
    t = big.handshake(t)
    t = big.download(t + 0.001, 900, lose=tuple(range(55, 900, 60)))     # 15 lost = 1.7%
    small_ip = ["198.51.100.%d" % i for i in range(20, 26)]
    for k, ip in enumerate(small_ip):
        s = TCP(cap, CLIENT, 41000 + k, ip, 443, rtt=0.02, c_isn=500 + k, s_isn=9000 + k * 3)
        t = s.handshake(t + 0.01)
        t = s.download(t + 0.001, 30)
    r = analyse(_write(cap, tmp_path))
    loss = next(f for f in r["findings"] if f["key"] == "tcp_loss")
    assert loss["severity"] == "warning"
    assert "bulk transfer" in r["diagnosis"]["problems"][0]["most_probable"]


# --------------------------------------------------------------- TLS
def _tls13_handshake(cap, port, client_record):
    c = TCP(cap, CLIENT, port, "198.51.100.30", 443)
    t = c.handshake(T0)
    c.send(t + 0.001, True, client_hello("secure.example.com"))
    c.send(t + 0.03, False, server_hello(0x0304))
    c.send(t + 0.031, True, b"\x14\x03\x03\x00\x01\x01" + client_record)
    c.close(t + 0.05)


def test_tls13_encrypted_alert_is_a_failure(tmp_path):
    cap = Capture("tls13alert", "client rejects the certificate with an encrypted alert")
    _tls13_handshake(cap, 40010, b"\x17\x03\x03\x00\x13" + b"\xaa" * 19)
    r = analyse(_write(cap, tmp_path))
    s = r["tls"]["sessions"][0]
    assert s["alert"] and s["setup_ms"] is None
    assert "tls_alerts" in keys(r)


def test_warning_level_alert_is_not_a_failure(tmp_path):
    cap = Capture("tlswarn", "plaintext warning-level user_canceled alert")
    c = TCP(cap, CLIENT, 40011, "198.51.100.31", 443)
    t = c.handshake(T0)
    c.send(t + 0.001, True, client_hello("x.example.com"))
    c.send(t + 0.03, False, server_hello(0x0303, 0xc02f))
    c.send(t + 0.031, True, b"\x15\x03\x03\x00\x02\x01\x5a")   # level 1 (warning), user_canceled
    c.close(t + 0.05)
    r = analyse(_write(cap, tmp_path))
    assert "tls_alerts" not in keys(r)


# --------------------------------------------------------------- DNS / ICMP
def test_isolated_dns_failure_is_info_and_report_is_consistent(tmp_path):
    cap = Capture("dns1", "one SERVFAIL among many good lookups")
    for k in range(20):
        dns_exchange(cap, T0 + k * 0.1, f"ok{k}.example.com", k + 1, 0.01, sport=50000 + k)
    dns_exchange(cap, T0 + 3, "bad.example.com", 999, 0.02, rcode=2, sport=51000)
    r = analyse(_write(cap, tmp_path))
    f = next(f for f in r["findings"] if f["key"] == "dns_failures")
    assert f["severity"] == "info"
    assert not any(line.startswith("DNS:") and "no errors" in line for line in r["diagnosis"]["checked_clean"])


def test_icmp_counts(tmp_path):
    cap = Capture("icmp", "eight fragmentation-needed messages")
    for i in range(8):
        inner = dpkt.ip.IP(src=b"\xc0\xa8\x01\x32", dst=b"\xcb\x00\x71\x01", p=6, data=b"\x00" * 8)
        icmp = dpkt.icmp.ICMP(type=3, code=4, data=dpkt.icmp.ICMP.Unreach(mtu=1400, data=inner))
        frame, _ = cap.ip_packet("192.0.2.1", CLIENT, icmp, dpkt.ip.IP_PROTO_ICMP)
        cap.add(T0 + i * 0.1, frame)
    dns_exchange(cap, T0 + 1, "a.example", 1, 0.01)
    r = analyse(_write(cap, tmp_path))
    mtu = next(f for f in r["findings"] if f["key"] == "icmp_mtu")
    assert mtu["metrics"]["messages"] == 8
    assert "icmp_unreachable" not in keys(r)


# --------------------------------------------------------------- reader
def test_header_only_capture_is_an_error(tmp_path):
    p = tmp_path / "empty.pcap"
    with open(p, "wb") as f:
        dpkt.pcap.Writer(f)
    with pytest.raises(CaptureError):
        analyse(str(p))


def test_pcapng_garbage_after_header_is_an_error(tmp_path):
    p = tmp_path / "junk.pcapng"
    with open(p, "wb") as f:
        dpkt.pcapng.Writer(f)
        f.write(os.urandom(300))
    with pytest.raises(CaptureError):
        analyse(str(p))


def _block(btype, body):
    body += b"\x00" * (-len(body) % 4)
    n = 12 + len(body)
    return struct.pack("<II", btype, n) + body + struct.pack("<I", n)


def test_pcapng_multi_interface_and_drop_counters(tmp_path):
    """Ethernet interface (µs) + raw-IP interface (ns) + statistics block with drops."""
    cap = Capture("tmp", "")
    c = TCP(cap, CLIENT, 40020, "198.51.100.40", 80)
    c.handshake(T0)
    eth_frames = [fr for _, fr in cap.frames]
    raw_ip = bytes(dpkt.ethernet.Ethernet(eth_frames[0]).data)
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb0 = _block(1, struct.pack("<HHI", 1, 0, 65535))
    tsresol9 = struct.pack("<HHB", 9, 1, 9) + b"\x00\x00\x00" + struct.pack("<HH", 0, 0)
    idb1 = _block(1, struct.pack("<HHI", 101, 0, 65535) + tsresol9)

    def epb(iface, ts_units, data):
        return _block(6, struct.pack("<IIIII", iface, ts_units >> 32, ts_units & 0xFFFFFFFF,
                                     len(data), len(data)) + data)
    us = int(T0 * 1e6)
    ns = int((T0 + 0.5) * 1e9)
    isb = _block(5, struct.pack("<III", 0, 0, 0) + struct.pack("<HHQ", 5, 8, 42) + struct.pack("<HH", 0, 0))
    data = shb + idb0 + idb1 + epb(0, us, eth_frames[1]) + epb(1, ns, raw_ip) + isb
    p = tmp_path / "multi.pcapng"
    p.write_bytes(data)
    pkts = list(iter_packets(str(p)))
    assert [x.proto for x in pkts] == ["TCP", "TCP"]
    assert pkts[1].ts == pytest.approx(T0 + 0.5, abs=1e-6)
    r = analyse(str(p))
    assert r["capture"]["reported_drops"] == 42
    assert "capture_tool_drops" in keys(r)


# --------------------------------------------------------------- CLI / web
def test_cli_error_paths(tmp_path, capsys):
    empty = tmp_path / "empty.pcap"
    with open(empty, "wb") as f:
        dpkt.pcap.Writer(f)
    assert main(["judge", str(empty)]) in (2,)  # tshark missing also returns 2
    blocker = tmp_path / "notadir"
    blocker.write_text("x")
    cap = Capture("ok", "")
    dns_exchange(cap, T0, "a.example", 1, 0.01)
    good = _write(cap, tmp_path)
    assert main(["analyse", good, "-o", str(blocker)]) == 2
    with pytest.raises(SystemExit):
        main(["analyse", good, "--max-packets", "-3"])


def test_report_names_keep_extension(corpus, tmp_path):
    assert main(["analyse", corpus["loss_one_server"][0], corpus["loss_one_server_pcapng"][0],
                 "-o", str(tmp_path)]) == 0
    names = os.listdir(tmp_path)
    assert "loss_one_server.pcap.report.html" in names
    assert "loss_one_server_pcapng.pcapng.report.html" in names


def _token(client):
    html = client.get("/").get_data(as_text=True)
    return re.search(r'name="token" value="([^"]+)"', html).group(1)


def test_upload_page_security(corpus):
    from packet_doctor.web import create_app
    client = create_app(max_upload_mb=5).test_client()
    tok = _token(client)
    # hostile file name is escaped in the error message
    resp = client.post("/analyse", data={"token": tok,
                                         "capture": (io.BytesIO(b"nope"), "<img src=x onerror=alert(1)>.pcap")},
                       content_type="multipart/form-data")
    assert resp.status_code == 400
    assert b"<img src=x" not in resp.data and b"&lt;img src=x" in resp.data
    # no token / foreign origin / foreign Host are refused
    with open(corpus["slow_server"][0], "rb") as f:
        assert client.post("/analyse", data={"capture": (f, "a.pcap")},
                           content_type="multipart/form-data").status_code == 403
    with open(corpus["slow_server"][0], "rb") as f:
        assert client.post("/analyse", data={"token": tok, "capture": (f, "a.pcap")},
                           headers={"Origin": "https://evil.example"},
                           content_type="multipart/form-data").status_code == 403
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 403
