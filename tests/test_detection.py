"""Packet Doctor against the synthetic corpus's ground truth."""
import pytest

from packet_doctor.scoring import score
from packet_doctor.synth import SCENARIOS

SCENARIO_NAMES = [fn().name for fn in SCENARIOS] + ["loss_one_server_pcapng"]


@pytest.mark.parametrize("name", SCENARIO_NAMES)
def test_events_found_without_false_detections(corpus, name):
    _, truth, result = corpus[name]
    s = score(result, truth)
    for row in s["events"]:
        assert not row["missed"], f"{name}: missed {row['event']} frames {row['missed']}"
        assert not row["false"], f"{name}: false {row['event']} frames {row['false']}"


@pytest.mark.parametrize("name", SCENARIO_NAMES)
def test_expected_findings_and_no_unwanted_ones(corpus, name):
    _, truth, result = corpus[name]
    s = score(result, truth)
    assert not s["findings_missing"], s["findings_missing"]
    assert not s["findings_forbidden_present"], s["findings_forbidden_present"]
    if s["cause_ok"] is not None:
        assert s["cause_ok"], result["diagnosis"]["problems"][0]["most_probable"]
    if s["health_ok"] is not None:
        assert s["health_ok"]


def test_every_finding_cites_evidence_or_explains(corpus):
    for name, (_, _, result) in corpus.items():
        for f in result["findings"]:
            assert f["summary"]
            if f["severity"] in ("critical", "warning"):
                assert f["evidence"], f"{name}/{f['key']} has no evidence"
                assert all(e.get("frame") for e in f["evidence"]), f"{name}/{f['key']} evidence without frame"


def test_kt_records_are_complete(corpus):
    for name, (_, _, result) in corpus.items():
        for p in result["diagnosis"]["problems"]:
            assert set(p["spec"]) == {"what", "where", "when", "extent"}
            assert p["causes"] and p["verify"]
            verdicts = [c["verdict"] for c in p["causes"]]
            assert verdicts.count("most probable") <= 1
            # a cause contradicted by the IS-NOT side can never be the answer
            for c in p["causes"]:
                if c["contradicts"]:
                    assert c["verdict"] == "eliminated"


def test_artefacts_not_counted_as_loss(corpus):
    _, _, r = corpus["capture_artefacts"]
    retx = sum(c["dirs"][d]["retrans_real"] for c in r["tcp"]["connections"] for d in ("c2s", "s2c"))
    assert retx == 0
    assert r["diagnosis"]["health"] == "healthy"
    assert all(f["artefact"] for f in r["findings"])


def test_capture_point_inferred_from_handshakes(corpus):
    _, _, r = corpus["loss_one_server"]
    assert r["tcp"]["capture_point"]["position"] == "client"


def test_handshake_and_tls_values(corpus):
    _, truth, r = corpus["healthy_browsing"]
    rtts = sorted(round(c["handshake"]["irtt_ms"]) for c in r["tcp"]["connections"])
    assert rtts == [12, 15, 18, 24]
    assert sorted(s["sni"] for s in r["tls"]["sessions"]) == sorted(truth["tls_sni"])
    assert all(s["version"] == "TLS 1.3" for s in r["tls"]["sessions"])


def test_dns_latency_measured(corpus):
    _, _, r = corpus["dns_problems"]
    far = next(t for t in r["dns"]["transactions"] if t["name"] == "far.example.com")
    assert far["latency_ms"] == pytest.approx(650, abs=0.01)
    timeout = next(t for t in r["dns"]["transactions"] if t["name"] == "slow.example.org")
    assert timeout["status"] == "timeout" and timeout["retries"] == 1


def test_benign_nxdomain_not_blamed(corpus):
    _, _, r = corpus["dns_problems"]
    f = next(f for f in r["findings"] if f["key"] == "dns_nxdomain")
    assert f["metrics"]["benign"] == 1


def test_zero_window_duration(corpus):
    _, _, r = corpus["zero_window"]
    d = r["tcp"]["connections"][0]["dirs"]["c2s"]
    assert d["zero_window_total_s"] == pytest.approx(1.6, abs=0.01)
