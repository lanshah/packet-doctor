"""Outside judge: Packet Doctor's TCP flags must agree with Wireshark's on every sample."""
import re

import pytest

from packet_doctor.judge import find_tshark, judge, tshark_version


def _version_tuple():
    t = find_tshark()
    if t is None:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", tshark_version(t))
    return tuple(int(x) for x in m.groups()) if m else None


_VER = _version_tuple()
# Packet Doctor mirrors Wireshark 4.6's TCP analysis rules (SACK handling and other
# details changed in earlier releases), so only 4.6+ is a fair frame-by-frame judge.
pytestmark = [
    pytest.mark.skipif(_VER is None, reason="tshark (Wireshark) not installed"),
    pytest.mark.skipif(_VER is not None and _VER < (4, 6, 0),
                       reason=f"tshark {_VER} is older than 4.6; its TCP analysis rules differ"),
]


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
