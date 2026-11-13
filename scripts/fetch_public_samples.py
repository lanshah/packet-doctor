"""Download a few public sample captures from the Wireshark wiki for extra testing.

These files are NOT included in this repository. The wiki's own text is GPL,
but the SampleCaptures page does not state the licence of the uploaded capture
files, so they are fetched on demand into public_samples/ (git-ignored) and
never redistributed. Checked on 14 Nov 2026: https://wiki.wireshark.org/SampleCaptures
and https://wiki.wireshark.org/License

Usage:
    python scripts/fetch_public_samples.py
    packet-doctor judge public_samples/*
"""
from __future__ import annotations

import os
import sys
import urllib.request

SAMPLES = {
    "http.cap": "https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap",
    "dns.cap": "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap",
    "tcp-ecn-sample.pcap":
        "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/tcp-ecn-sample.pcap",
}
MAX_BYTES = 20 * 1024 * 1024


def main() -> int:
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "public_samples")
    os.makedirs(out, exist_ok=True)
    for name, url in SAMPLES.items():
        dest = os.path.join(out, name)
        if os.path.exists(dest):
            print(f"have  {dest}")
            continue
        req = urllib.request.Request(url, headers={"User-Agent": "packet-doctor-sample-fetch"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            print(f"skip  {name}: larger than {MAX_BYTES} bytes", file=sys.stderr)
            continue
        if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a",
                            b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            print(f"skip  {name}: not a pcap/pcapng file (the URL may have moved)", file=sys.stderr)
            continue
        with open(dest, "wb") as f:
            f.write(data)
        print(f"saved {dest} ({len(data):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
