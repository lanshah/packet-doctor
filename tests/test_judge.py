"""Outside judge: Packet Doctor's TCP flags must agree with Wireshark's on every sample."""
import pytest

from packet_doctor.judge import find_tshark, judge

pytestmark = pytest.mark.skipif(find_tshark() is None, reason="tshark (Wireshark) not installed")


def test_flags_agree_with_wireshark(corpus):
    for name, (path, _, result) in corpus.items():
        j = judge(path, result=result)
        assert j["available"]
        for flag, v in j["tcp_flags"].items():
            assert v["agreement_pct"] == 100.0, (
                f"{name}/{flag}: only PD {v['only_packet_doctor']} only Wireshark {v['only_wireshark']}")
        assert j["tcp_stream_numbering"]["matched"] == j["tcp_stream_numbering"]["of"]
        if j["handshake_rtt"]["compared"]:
            assert j["handshake_rtt"]["max_abs_diff_ms"] < 0.01
        if j["dns"]["compared"]:
            assert j["dns"]["rcode_agree"] == j["dns"]["compared"]
            assert j["dns"]["max_abs_latency_diff_ms"] < 0.01
        assert j["tls_sni"]["agree"] == j["tls_sni"]["compared"]
