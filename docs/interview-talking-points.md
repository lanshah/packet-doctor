# Interview talking points: Packet Doctor

## 30-second pitch

"I built a tool that reads a Wireshark capture and writes the diagnosis a senior engineer would: packet loss, slow servers, DNS failures, TLS errors. Every claim comes with frame numbers. I checked it against Wireshark itself: it agrees frame for frame on TCP expert flags, on synthetic test captures and on a real capture I took on my own Wi-Fi. It also uses Kepner-Tregoe, the structured troubleshooting method many NOCs use, so it says what is and isn't affected before naming a cause."

## Things worth telling, with numbers you can defend

* **Outside judge.** At first my TCP analysis agreed with Wireshark on only 51% of flags for a real capture. Reading Wireshark's source showed my rules were wrong in several places, including how SACK affects fast-retransmission and window-update labelling, which clock the out-of-order test uses, and when a reused port starts a new conversation. After the fix: 100% on the real capture and on a 326k-frame stress file. *Lesson: test against reality, not just your own test data.*
* **Not overclaiming.** On my real capture the first version blamed my Wi-Fi for packet loss. In fact 1,394 of the 1,396 retransmissions were on a 190 Mbit/s speed-test download, which is normal TCP congestion control. I changed the logic so a single stray retransmission doesn't count as evidence, and "the bulk transfer filled the link" counts as the simpler explanation.
* **Independent corroboration.** The two slow servers it found in the real capture (≈630 ms and ≈540 ms of server time) match curl's own time-to-first-byte measurements taken at the same moment.
* **Ground truth that caught my own mistakes.** The synthetic generator records the injected faults. Three times the tool and Wireshark agreed with each other but disagreed with my labels, and each time the labels were wrong.

## Likely questions

| Question | Short answer |
|---|---|
| What's the difference between a retransmission and a fast retransmission? | A plain retransmission happens after the retransmission timer expires. A fast retransmission is triggered by duplicate ACKs (or SACK) before the timer, so it recovers faster. |
| Why can duplicate ACKs appear without loss? | Reordering: a later segment arrives first. That's why out-of-order is reported separately and doesn't count as loss. |
| What is a zero window? | The receiver's buffer is full: its application isn't reading fast enough. It's an end-host problem, not a network one. |
| How do you know where the capture was taken? | Handshake timing. If the SYN/ACK→ACK step is about 0 ms, the capture is on the client; if SYN→SYN/ACK is about 0 ms, it's on the server. |
| What is TSO and why does it matter? | TCP segmentation offload: the NIC splits large segments, so a capture on the sending host shows "impossible" 64 KB packets. Not a fault. |
| How does this help a NOC? | Faster first-line triage, a consistent write-up for escalation tickets, and fewer wrong escalations (it won't call capture artefacts "packet loss"). |
| What would you add next? | QUIC timing (needs decryption keys), multi-point capture correlation, and a Grafana/Power BI feed from the CSV exports. |
| Limitations? | One capture point, encrypted payloads, QUIC not analysed, thresholds are rules of thumb (configurable). |

## Skills this shows (for the CV)

Python (streaming parsers, Flask, pytest, CI) · TCP/IP internals (sequence analysis, SACK, windowing, RTT) · DNS and TLS · Wireshark/tshark · structured troubleshooting (Kepner-Tregoe) · validation against ground truth and an independent reference · technical writing.
