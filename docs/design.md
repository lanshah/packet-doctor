# Design notes

## Goal

Read a packet capture the way a senior network engineer reads it in Wireshark, and write down what they would conclude: what is wrong, where, how sure we are, and what to check next. Every statement points to frames you can open in Wireshark.

## Depth pass (how a top analyst would approach this)

| Question | Answer used in this project |
|---|---|
| What would a top professional do that a basic tool does not? | Separate network round trip from server time. Work out where the capture was taken (client side, server side or in the middle) from handshake timing. Treat capture-point artefacts (offload, mirror-port duplicates, capture drops) as artefacts, not faults. Say what the capture *cannot* show. |
| What is the rawest material? | The frames themselves. Packet Doctor decodes the bytes with its own code instead of reusing tshark's output, so Wireshark can act as an independent judge. |
| Which methods and tools? | A per-connection TCP state machine that applies the same rules as Wireshark 4.6 (`tcp_analyze_sequence_number`, including SACK handling and the unacknowledged-segment list). Kepner-Tregoe Problem Analysis (IS / IS NOT, distinctions, testing each cause against the whole specification). Percentiles instead of averages for latency. |
| What shows the result is right, other than me? | (1) Synthetic captures with injected faults and a ground truth written while the frames are generated. (2) Frame-by-frame comparison with Wireshark's own expert analysis on the synthetic corpus, a real Wi-Fi capture and a 326k-frame stress file. (3) curl's independent timings for the two slow servers found in the real capture. |

**Hard targets set at the start:** 100% detection with no false detections on the synthetic corpus, at least 99% frame-level agreement with Wireshark on real traffic, and 1 million frames in under 60 seconds on a laptop. The results against these targets are in [validation.md](validation.md).

## Parser choice: dpkt

| Option | Speed | Dependency | Verdict |
|---|---|---|---|
| **dpkt** | About 24k frames/s end to end in this tool (pure Python) | One small pure-Python package | **Chosen**: streams frame by frame, reads pcap and pcapng, and does not depend on Wireshark, so Wireshark can judge it |
| scapy | Roughly 10x slower per packet | Large | Too slow for multi-million-frame captures |
| pyshark / tshark | Fast dissection, but slow to move results into Python | Needs Wireshark installed | Using it would make the Wireshark comparison circular |

In the end, Packet Doctor reads both file formats with small readers of its own (`reader._pcap_records`, `reader._pcapng_records`), and uses dpkt to decode the packets inside them. The readers report a cut-off last frame, return each frame's original length, and handle pcapng files with several interfaces (for example Wi-Fi plus loopback on Windows). They also pick up the capture tool's own dropped-packet counters and timestamp offsets. dpkt's readers do none of this.

## Architecture

```
capture file ──► reader (streaming, one frame at a time)
                    │  Packet records (no frames kept in memory)
     ┌──────────────┼───────────────┬───────────────┐
     ▼              ▼               ▼               ▼
  TCPAnalyzer   DNSAnalyzer   TrafficStats     (TLSAnalyzer fed by the
  (Wireshark    (query ↔      (timeline,        TCP reassembler: first
   rules, RTT,   response      top talkers,      16 KB of each stream)
   turns, zero   matching)     ICMP)
   window)
     └──────────────┴───────────────┴───────────────┘
                    ▼
            result dict (JSON-safe)
                    ▼
            diagnose: findings + Kepner-Tregoe records
                    ▼
     report: HTML (one self-contained file) · JSON · CSV
     judge: tshark comparison      web: local upload page
```

Memory does not grow with packet count: per-connection state only, capped example lists, a capped unacknowledged-segment list (10,000, the same cap Wireshark uses), and throughput bins that coarsen automatically. A 326,570-frame file peaked at 8 MB. It does grow with the number of TCP connections (about 15 KB each), and report detail is capped at the 20,000 busiest or flagged connections.

## Diagnosis rules (summary)

* **Loss**: a sender is *affected* when at least 2 segments and at least 1% of its data segments were retransmitted. A single stray retransmission makes a connection neither affected nor clean. Causes tested: local link (loss towards several unrelated servers), path or server (loss towards one server while other busy connections are clean), and the bulk transfer itself filling the bottleneck (at least 80% of the loss sits on a transfer that carries at least 30% of the capture's bytes). Normal congestion control needs no fault, so it counts as the simpler explanation, and the severity is capped at *warning*.
* **Server time**: the delay from a request to the first response byte, minus the server-side handshake RTT. It is only judged when the handshake was captured. Timer-driven pushes (several near-identical gaps) and gaps of 10 s or more are ignored. A small preamble such as TLS 1.3 session tickets does not hide a late reply.
* **DNS**: a failure only counts as a problem if it repeats, or if the same name never resolved in another lookup.
* **Artefacts**: TSO/GSO (a segment larger than the MSS, or an IPv4 length of 0), the same frame twice (same non-zero IP ID), capture drops (an ACK for data never seen), snaplen truncation, timestamps going backwards, and many mid-stream connections.
