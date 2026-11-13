# Packet Doctor: 2-minute demo video script

**Record with:** OBS Studio (free) or Xbox Game Bar (Win + G, then the record button). 1920×1080, browser zoom 110%, close other tabs and notifications. Use only the synthetic sample captures on screen. Never show the real capture: it contains private IP addresses.

**Before recording:** run `packet-doctor demo` once so `sample_reports/` exists. Open a terminal in the project folder with the venv active.

| Time | On screen | What you say |
|---|---|---|
| 0:00–0:12 | README title, then the healthy and problem report headers side by side | "This is Packet Doctor. You give it a Wireshark capture and it tells you, in plain English, what's wrong with the network, with the frame numbers to prove it." |
| 0:12–0:30 | Terminal: `packet-doctor analyse samples/loss_one_server.pcap --open` | "Here's a capture where downloads from one server are slow. It reads the file in about a second…" |
| 0:30–0:55 | Report: verdict banner, then the Kepner-Tregoe table | "The verdict is packet loss. The table is the Kepner-Tregoe method we use in NOC troubleshooting: what IS affected (one server) and what IS NOT (three other busy servers are clean). That rules out my own Wi-Fi and points to the path to that server." |
| 0:55–1:10 | Scroll to evidence; click **Copy** on the Wireshark filter, paste it in Wireshark | "Every finding cites frames. One click copies a Wireshark filter, and these are exactly the frames Wireshark flags too." |
| 1:10–1:25 | Open `samples/capture_artefacts` report | "It also knows when *not* to blame the network. This capture has offload artefacts and capture drops. A beginner would call that packet loss, but Packet Doctor files them as capture artefacts." |
| 1:25–1:45 | Terminal: `packet-doctor judge samples/*.pcap`, showing the 100% lines | "How do I know it's right? I compare it frame by frame with Wireshark's own analysis: 100% agreement on the test captures and on a real Wi-Fi capture of my own." |
| 1:45–2:00 | Browser: `packet-doctor serve` upload page, drag a sample in | "There's also a local upload page for colleagues who don't use the command line. It all runs on your own machine, and the code, tests and CI are on my GitHub." |

**Closing card (3 s):** "Packet Doctor · Python · TCP/IP · Wireshark · Kepner-Tregoe" plus your GitHub URL.
