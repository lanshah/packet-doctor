import glob
import json
import os

import pytest

from packet_doctor.analyse import analyse
from packet_doctor.synth import make_samples


@pytest.fixture(scope="session")
def corpus(tmp_path_factory):
    """Freshly generated synthetic corpus: {scenario: (path, truth, result)}."""
    d = tmp_path_factory.mktemp("corpus")
    make_samples(str(d))
    out = {}
    for tp in sorted(glob.glob(os.path.join(d, "*.truth.json"))):
        with open(tp, encoding="utf-8") as f:
            truth = json.load(f)
        base = tp[:-len(".truth.json")]
        path = next(base + e for e in (".pcap", ".pcapng") if os.path.exists(base + e))
        out[truth["scenario"]] = (path, truth, analyse(path))
    return out
