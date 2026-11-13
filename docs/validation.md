# Validation

How do we know Packet Doctor is right? Three references other than Packet Doctor itself:

1. **Ground truth.** Synthetic captures in which each fault was injected on purpose, with the frame numbers recorded while the file was written.
2. **Wireshark.** tshark 4.6.2 analyses the same files, and every TCP expert flag is compared frame by frame.
3. **curl.** Its own timing for the slow servers found in the real capture.

All numbers below were measured on 14 Nov 2026 on a Windows 11 laptop (Python 3.14). Rerun them with `packet-doctor validate samples`, `packet-doctor judge samples/*.pcap samples/*.pcapng` and `pytest -v`.

## 1. Detection table (synthetic corpus, 13 files)

The truth files list every TCP expert event the generator injected. Any *other* TCP flag that Packet Doctor raises in a file counts as a false detection, so "False" really means false.

| Scenario | Injected event | Expected | Found | Missed | False |
|---|---|---:|---:|---:|---:|
| capture_artefacts | ack_lost_segment | 2 | 2 | 0 | 0 |
| capture_artefacts | capture_duplicate | 2 | 2 | 0 | 0 |
| capture_artefacts | lost_segment | 2 | 2 | 0 | 0 |
| capture_artefacts | retransmission (the duplicates, as Wireshark labels them) | 2 | 2 | 0 | 0 |
| capture_artefacts | tso_oversize | 8 | 8 | 0 | 0 |
| connection_failures | refused | 1 | 1 | 0 | 0 |
| connection_failures | retransmission (SYN retries) | 2 | 2 | 0 | 0 |
| connection_failures | syn_unanswered | 3 | 3 | 0 | 0 |
| dns_problems | dns_nxdomain | 2 | 2 | 0 | 0 |
| dns_problems | dns_servfail | 2 | 2 | 0 | 0 |
| dns_problems | dns_slow | 1 | 1 | 0 | 0 |
| dns_problems | dns_timeout | 1 | 1 | 0 | 0 |
| loss_local_link | duplicate_ack | 42 | 42 | 0 | 0 |
| loss_local_link | lost_segment | 8 | 8 | 0 | 0 |
| loss_local_link | retransmission | 10 | 10 | 0 | 0 |
| loss_local_link | spurious_retransmission | 1 | 1 | 0 | 0 |
| loss_one_server (+ pcapng copy) | duplicate_ack | 17 + 17 | 34 | 0 | 0 |
| loss_one_server (+ pcapng copy) | lost_segment | 4 + 4 | 8 | 0 | 0 |
| loss_one_server (+ pcapng copy) | retransmission | 5 + 5 | 10 | 0 | 0 |
| reordering | duplicate_ack | 1 | 1 | 0 | 0 |
| reordering | lost_segment | 3 | 3 | 0 | 0 |
| reordering | out_of_order | 3 | 3 | 0 | 0 |
| slow_server | slow_response (incl. a reply hidden behind TLS 1.3 tickets) | 2 | 2 | 0 | 0 |
| tls_failure | tls_alert | 1 | 1 | 0 | 0 |
| upload_fast_retransmit | duplicate_ack | 4 | 4 | 0 | 0 |
| upload_fast_retransmit | fast_retransmission | 1 | 1 | 0 | 0 |
| upload_fast_retransmit | retransmission | 1 | 1 | 0 | 0 |
| zero_window | window_full | 2 | 2 | 0 | 0 |
| zero_window | window_update | 1 | 1 | 0 | 0 |
| zero_window | zero_window | 4 | 4 | 0 | 0 |
| zero_window | zero_window_probe | 3 | 3 | 0 | 0 |
| zero_window | zero_window_probe_ack | 3 | 3 | 0 | 0 |
| **Total** | | **169** | **169** | **0** | **0** |

**Diagnosis level.** Every expected finding was raised and no unwanted finding appeared, in all 13 files. Where a scenario has one expected cause, the cause picked was right in all 7: one server's path, the local link, the receiving application (zero window), server processing, the broken domain (not the resolver), a service not listening, and the certificate (TLS). The healthy capture is rated healthy, and the artefact capture reports only artefacts, no loss.

**Honest limits of this corpus.** The synthetic generator writes both the traffic and the truth. That is why Wireshark is the second, independent judge. The diagnosis scenarios also sit fairly close to their rule boundaries. Real captures (section 3) are the stronger test.

**The truth caught my own mistakes.** Three times Packet Doctor and Wireshark agreed with each other but not with my labels: a fourth duplicate ACK, a second window-full segment, and a redundant ACK in the reordering scenario. Each time the label was wrong, and I fixed the generator.

## 2. Wireshark agreement on the synthetic corpus

Sum over all 13 files (tshark 4.6.2, TCP analysis preferences pinned with `-o`):

| Flag | Packet Doctor | Wireshark | Both |
|---|---:|---:|---:|
| retransmission (all kinds) | 25 | 25 | 25 |
| fast_retransmission | 1 | 1 | 1 |
| spurious_retransmission | 1 | 1 | 1 |
| out_of_order | 3 | 3 | 3 |
| lost_segment (previous segment not captured) | 21 | 21 | 21 |
| ack_lost_segment (ACKed unseen segment) | 2 | 2 | 2 |
| duplicate_ack | 80 | 80 | 80 |
| zero_window | 4 | 4 | 4 |
| zero_window_probe | 3 | 3 | 3 |
| zero_window_probe_ack | 3 | 3 | 3 |
| window_full | 2 | 2 | 2 |
| window_update | 1 | 1 | 1 |
| RST | 1 | 1 | 1 |

That is 100% frame-level agreement in every file. TCP stream numbers match `tcp.stream`. Handshake RTT, DNS response time and rcode, and TLS SNI also match.

## 3. Real capture (my own Wi-Fi, with consent)

One 30-second capture on the laptop's Wi-Fi while opening eight public websites and a 25 MB speed-test download: 32,657 frames, 100 TCP connections, 50 DNS lookups, 39 TLS handshakes. The capture file stays on the laptop (git-ignored) because it contains private addresses.

### Wireshark agreement

| Flag | Packet Doctor | Wireshark | Both | Agreement |
|---|---:|---:|---:|---:|
| retransmission (all kinds) | 1,416 | 1,416 | 1,416 | 100% |
| fast_retransmission | 1,275 | 1,275 | 1,275 | 100% |
| spurious_retransmission | 1 | 1 | 1 | 100% |
| out_of_order | 141 | 141 | 141 | 100% |
| lost_segment | 425 | 425 | 425 | 100% |
| duplicate_ack | 1,163 | 1,163 | 1,163 | 100% |
| window_update | 9 | 9 | 9 | 100% |
| keep_alive | 168 | 168 | 168 | 100% |
| keep_alive_ack | 165 | 165 | 165 | 100% |
| RST | 13 | 13 | 13 | 100% |

Stream numbering 100/100. Handshake RTT on 47 connections within 0.005 ms. DNS: 49/49 rcodes agree, latency within 0.005 ms. TLS SNI 39/39.

### How it got to 100%: the first version was wrong

| Version | Agreement on this capture | What was wrong |
|---|---:|---|
| First run | **51.05%** | I had written Wireshark's rules from memory, without SACK. Wireshark labelled 1,275 gap-filling segments "fast retransmission" where I said "out-of-order". |
| SACK added | 89.67% | My SACK rule fired too often, and window updates carrying SACK blocks are re-labelled by Wireshark as duplicate ACKs. |
| Rules taken from Wireshark 4.6.2's source (`packet-tcp.c`) | **100%** | The out-of-order and fast-retransmission tests measure time since the *peer's* last segment, keep a list of unacknowledged segments, and handle a pure-ACK special case. A reused port starts a new conversation after FIN/RST. |

A 326,570-frame stress file (the real capture concatenated 10 times, so the same connections repeat) then exposed one more rule: a SYN reusing a closed conversation's ports. After fixing it: **100%**, with 217/217 stream numbers matching.

### What Packet Doctor concluded

| Finding | Verdict | Cross-check |
|---|---|---|
| Packet loss: 1,394 retransmissions, 7.2% of the sender's segments, all on one connection | **Warning, medium confidence.** Most probable cause: the bulk transfer itself filling the bottleneck (TCP congestion control). The loss sat on the 190 Mbit/s speed-test download; 24 other busy connections were clean. The only other retransmissions were two single strays, which are reported as normal-level. | The download was deliberate. Loss while a link is saturated is expected behaviour. |
| Slow server responses on 2 sites | ≈629 ms (www.tm.com.my) and ≈537 ms (www.speedtest.net) of server time, after 8.6 ms and 16.3 ms network RTT | curl, run at the same moment, measured time to first byte 0.700 s and 0.643 s against 0.034 s and 0.038 s to connect. Consistent. |
| One DNS lookup unanswered | Info, low confidence ("isolated") | 49 of 50 answered; one-off. |
| Timestamps went backwards 9 times; many connections already open | Capture artefacts | Normal for a Windows Wi-Fi capture started mid-session. |

**The review that changed the verdict.** The first version of the diagnosis blamed my Wi-Fi ("local link, high confidence, critical"). Two connections with *one* retransmission each made the loss look as if it was spread across three servers. A single retransmission is not evidence, and normal congestion control needs fewer assumptions than a faulty link. The rules were changed, and both changes are covered by tests.

## 4. Independent code review

Three separate reviewers (requirements, architecture, code quality) examined the code, tried to break it, and reported issues with reproductions. All verified issues were fixed and are covered by `tests/test_regressions.py`:

* zero-window stall counted to the end of the capture after a reset
* empty or corrupt files reported as healthy (they now fail with a clear error)
* pcapng files with several interfaces decoded with the first interface's link type (now our own pcapng reader, which also reads capture-tool drop counters and `if_tsoffset`)
* TLS 1.3 encrypted alerts counted as successful handshakes; warning-level alerts counted as failures
* mirror-port duplicates on IPv6 (no IP ID) counted as loss
* a retransmitted request or an unsolicited server push mistaken for a slow server
* handshake RTT split measured from the first SYN instead of the most recent one
* the loss-cause tie-break could pick "local link" while the summary said "normal congestion"
* reflected HTML injection on the upload page; plus Host/Origin checks and a CSRF token against cross-site uploads
* ICMP counts, report self-contradictions, output-file name collisions, huge reports for port scans, CLI tracebacks

## 5. Performance and memory

| File | Frames | Time | Rate | Peak memory |
|---|---:|---:|---:|---:|
| Real Wi-Fi capture | 32,657 | 1.2 s | ≈27,000 frames/s | — |
| Stress file (real ×10) | 326,570 | 13.3 s | ≈24,500 frames/s | 8 MB |
| 5,000 short TLS connections | 40,000 | — | — | 74 MB (≈15 KB per connection) |

Memory does not grow with the number of packets, but it does grow with the number of TCP connections (about 15 KB each). A port scan with 200,000 connections would need a few GB. Per-connection detail in the report is capped at the 20,000 busiest or flagged connections, so report files stay usable.
