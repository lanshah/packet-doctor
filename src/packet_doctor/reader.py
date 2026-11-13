"""Streaming capture reader.

Reads pcap and pcapng files one frame at a time with dpkt and turns each frame
into a small :class:`Packet` record. Nothing is kept in memory after a packet is
yielded, so multi-gigabyte captures can be analysed with flat memory use.

Why dpkt (and not tshark/pyshark or scapy):
  * it is fast for pure Python and streams frame by frame;
  * it has no dependency on Wireshark, so Wireshark's own analysis can be used
    as an *independent* judge of our results (see ``judge.py``);
  * scapy is roughly 10x slower per packet and pyshark needs tshark installed.
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, field
from typing import Iterator, Optional

import dpkt

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # microsecond, both byte orders
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # nanosecond
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Link-layer types we can decode (values from the tcpdump LINKTYPE registry).
LINK_ETHERNET = 1
LINK_NULL = 0
LINK_LOOP = 108
LINK_RAW = {12, 14, 101}
LINK_IPV4 = 228
LINK_IPV6 = 229
LINK_SLL = 113
LINK_SLL2 = 276

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80)


class CaptureError(Exception):
    """Raised for files that are not readable captures."""


@dataclass(slots=True)
class Packet:
    no: int                 # 1-based frame number, same numbering as Wireshark
    ts: float               # absolute epoch seconds
    length: int             # bytes on the wire (best estimate)
    src: str = ""
    dst: str = ""
    proto: str = "OTHER"    # TCP / UDP / ICMP / ICMPv6 / OTHER / NON-IP
    ip_id: Optional[int] = None
    ip_len: int = 0          # IP total length from the header (0 = TSO artefact)
    ttl: int = 0
    truncated: bool = False  # captured bytes < IP total length (snaplen)
    fragment: bool = False   # non-first IP fragment or first fragment with MF
    sport: int = 0
    dport: int = 0
    # TCP
    flags: int = 0
    seq: int = 0
    ack: int = 0
    win: int = 0
    seglen: int = 0          # TCP payload length from IP header arithmetic
    mss: Optional[int] = None
    wscale: Optional[int] = None
    sack_perm: bool = False
    sack: tuple = ()         # SACK blocks (left, right) carried by this segment
    payload: bytes = b""     # TCP/UDP payload as captured (may be shorter than seglen)
    # ICMP
    icmp_type: int = -1
    icmp_code: int = -1
    icmp_info: dict = field(default_factory=dict)


@dataclass
class CaptureInfo:
    path: str
    file_format: str
    linktype: int
    file_size: int
    packets: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    warnings: list = field(default_factory=list)
    undecoded_frames: int = 0
    non_ip_frames: int = 0
    time_went_backwards: int = 0
    stopped_early: bool = False
    reported_drops: int = 0          # drops counted by the capture tool (pcapng ISB)
    extra_linktypes: list = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


_addr_cache: dict = {}


def _ip_str(raw: bytes) -> str:
    s = _addr_cache.get(raw)
    if s is None:
        fam = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
        s = socket.inet_ntop(fam, raw)
        if len(_addr_cache) < 200_000:
            _addr_cache[raw] = s
    return s


def sniff_format(path: str) -> str:
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureError(
        "Not a pcap or pcapng file (unrecognised magic bytes). "
        "Save the capture from Wireshark as .pcap or .pcapng; compressed (.gz) "
        "or .etl/.cap (NetMon) files are not supported.")


def _tcp_options(opts: bytes):
    mss = wscale = None
    sack = False
    blocks = ()
    try:
        for kind, data in dpkt.tcp.parse_opts(opts):
            if kind == dpkt.tcp.TCP_OPT_MSS and len(data) == 2:
                mss = struct.unpack("!H", data)[0]
            elif kind == dpkt.tcp.TCP_OPT_WSCALE and len(data) == 1:
                wscale = min(data[0], 14)
            elif kind == dpkt.tcp.TCP_OPT_SACKOK:
                sack = True
            elif kind == dpkt.tcp.TCP_OPT_SACK and len(data) >= 8:
                n = len(data) // 8
                vals = struct.unpack("!" + "II" * n, data[:8 * n])
                blocks = tuple(zip(vals[0::2], vals[1::2]))
    except Exception:  # malformed options: ignore, keep the packet
        pass
    return mss, wscale, sack, blocks


def _to_ip(linktype: int, buf: bytes):
    """Return a dpkt IP/IP6 object, or a string tag for non-IP frames."""
    if linktype == LINK_ETHERNET:
        eth = dpkt.ethernet.Ethernet(buf)
        return eth.data
    if linktype in LINK_RAW or linktype in (LINK_IPV4, LINK_IPV6):
        if not buf:
            return None
        v = buf[0] >> 4
        return dpkt.ip.IP(buf) if v == 4 else dpkt.ip6.IP6(buf) if v == 6 else None
    if linktype in (LINK_NULL, LINK_LOOP):
        return dpkt.loopback.Loopback(buf).data
    if linktype == LINK_SLL:
        return dpkt.sll.SLL(buf).data
    if linktype == LINK_SLL2:
        return dpkt.sll2.SLL2(buf).data
    raise CaptureError(f"Unsupported link-layer type {linktype}. Supported: Ethernet, "
                       "raw IP, Linux cooked (SLL/SLL2), loopback.")


def decode(no: int, ts: float, buf: bytes, linktype: int) -> Packet:
    """Decode one frame. Never raises for malformed packets; returns proto OTHER/NON-IP."""
    pkt = Packet(no=no, ts=ts, length=len(buf))
    try:
        ip = _to_ip(linktype, buf)
    except CaptureError:
        raise
    except Exception:
        pkt.proto = "NON-IP"
        return pkt
    if isinstance(ip, dpkt.ip.IP):
        pkt.src, pkt.dst = _ip_str(ip.src), _ip_str(ip.dst)
        pkt.ip_id, pkt.ttl, pkt.ip_len = ip.id, ip.ttl, ip.len
        hdr = ip.hl * 4
        frag_off = ip.offset
        if frag_off or ip.mf:
            pkt.fragment = True
        # l4_len None means the total-length field was 0: TSO/LRO on the capture host.
        l4_len = (ip.len - hdr) if ip.len else None
        ip_captured = len(ip)
        if frag_off:
            pkt.proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.p, "OTHER")
            return pkt
    elif isinstance(ip, dpkt.ip6.IP6):
        pkt.src, pkt.dst = _ip_str(ip.src), _ip_str(ip.dst)
        pkt.ttl = ip.hlim
        ext_len = sum(getattr(e, "length", 0) for e in getattr(ip, "all_extension_headers", []))
        pkt.ip_len = 40 + ip.plen if ip.plen else 0
        l4_len = (ip.plen - ext_len) if ip.plen else None
        ip_captured = 40 + len(ip.data) if isinstance(ip.data, (bytes, bytearray)) else len(ip)
        frag = getattr(ip, "extension_hdrs", {}).get(44)
        if frag is not None:
            pkt.fragment = True
            if getattr(frag, "frag_off", 0):
                return pkt
    else:
        pkt.proto = "NON-IP"
        return pkt
    l4 = ip.data

    # If the IP header says the packet is longer than what was captured, the
    # frame was cut short by the capture snaplen.
    if pkt.ip_len and pkt.ip_len > ip_captured:
        pkt.truncated = True
        pkt.length += pkt.ip_len - ip_captured

    if isinstance(l4, dpkt.tcp.TCP):
        pkt.proto = "TCP"
        pkt.sport, pkt.dport = l4.sport, l4.dport
        pkt.flags, pkt.seq, pkt.ack, pkt.win = l4.flags, l4.seq, l4.ack, l4.win
        thl = l4.off * 4
        payload = bytes(l4.data)
        pkt.payload = payload
        if l4_len is not None and l4_len >= thl:
            pkt.seglen = l4_len - thl
        else:
            pkt.seglen = len(payload)
        if l4.opts:
            pkt.mss, pkt.wscale, pkt.sack_perm, pkt.sack = _tcp_options(bytes(l4.opts))
    elif isinstance(l4, dpkt.udp.UDP):
        pkt.proto = "UDP"
        pkt.sport, pkt.dport = l4.sport, l4.dport
        pkt.payload = bytes(l4.data)
    elif isinstance(l4, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
        pkt.proto = "ICMP" if isinstance(l4, dpkt.icmp.ICMP) else "ICMPv6"
        pkt.icmp_type, pkt.icmp_code = l4.type, l4.code
        if pkt.proto == "ICMP" and l4.type == 3 and l4.code == 4:
            # Fragmentation needed: next-hop MTU lives in bytes 6-7 of the ICMP header
            raw = bytes(l4)
            if len(raw) >= 8:
                pkt.icmp_info["mtu"] = struct.unpack("!H", raw[6:8])[0]
        if pkt.proto == "ICMPv6" and l4.type == 2:
            raw = bytes(l4)
            if len(raw) >= 8:
                pkt.icmp_info["mtu"] = struct.unpack("!I", raw[4:8])[0]
        inner = getattr(l4.data, "data", None)
        if isinstance(inner, (dpkt.ip.IP, dpkt.ip6.IP6)):
            try:
                pkt.icmp_info["orig_dst"] = _ip_str(inner.dst)
                pkt.icmp_info["orig_proto"] = inner.p if isinstance(inner, dpkt.ip.IP) else inner.nxt
            except Exception:
                pass
    else:
        pkt.proto = "OTHER"
        pkt.payload = b""
    return pkt


def _pcap_records(f):
    """Minimal classic-pcap reader that, unlike dpkt's, reports a cut-off last
    record and returns the original (on-the-wire) length of each frame."""
    gh = f.read(24)
    if len(gh) < 24:
        raise CaptureError("File is too short to be a pcap capture.")
    magic = gh[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", gh[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    div = 1e9 if nano else 1e6

    def gen():
        while True:
            hdr = f.read(16)
            if not hdr:
                return
            if len(hdr) < 16:
                raise CaptureError("last record header is incomplete")
            sec, frac, incl, orig = rec.unpack(hdr)
            if incl > 262_144 * 4:
                raise CaptureError(f"record length {incl} is implausible (corrupt file)")
            buf = f.read(incl)
            if len(buf) < incl:
                raise CaptureError("last frame is incomplete")
            yield sec + frac / div, buf, orig, linktype

    return linktype, gen()


def _pcapng_records(f, info: "CaptureInfo"):
    """pcapng reader with per-interface link types and timestamp resolution.

    dpkt's reader assumes every packet uses the first interface's link type,
    which breaks common Windows captures (Wi-Fi + Npcap loopback). This reader
    also collects the capture tool's own drop counters from Interface
    Statistics Blocks and reports a cut-off or corrupt block.
    """
    head = f.read(12)
    if len(head) < 12 or head[:4] != PCAPNG_MAGIC:
        raise CaptureError("File is too short to be a pcapng capture.")
    bom = head[8:12]
    if bom == b"\x4d\x3c\x2b\x1a":
        e = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":
        e = ">"
    else:
        raise CaptureError("pcapng section header has an invalid byte-order mark.")
    f.seek(0)
    ifaces: list = []      # (linktype, ts_divisor)
    drops: dict = {}

    def options(body: bytes, pos: int):
        while pos + 4 <= len(body):
            code, ln = struct.unpack(e + "HH", body[pos:pos + 4])
            if code == 0:
                return
            yield code, body[pos + 4:pos + 4 + ln]
            pos += 4 + ln + (-ln % 4)

    def gen():
        nonlocal e, ifaces
        last_ts = 0.0
        while True:
            hdr = f.read(8)
            if not hdr:
                return
            if len(hdr) < 8:
                raise CaptureError("last block header is incomplete")
            btype = struct.unpack(e + "I", hdr[:4])[0]
            if btype == 0x0A0D0D0A:          # new section: byte order may change
                bom = f.read(4)
                e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                blen = struct.unpack(e + "I", hdr[4:8])[0]
                rest = 4
                ifaces = []
            else:
                blen = struct.unpack(e + "I", hdr[4:8])[0]
                rest = 0
            if blen < 12 or blen % 4 or blen > 64 * 1024 * 1024:
                raise CaptureError(f"block length {blen} is invalid (corrupt file)")
            body = f.read(blen - 12 - rest)
            tail = f.read(4)
            if len(body) < blen - 12 - rest or len(tail) < 4:
                raise CaptureError("last block is incomplete")
            if btype == 1:                    # Interface Description Block
                lt = struct.unpack(e + "H", body[:2])[0]
                div, off = 1e6, 0
                for code, val in options(body, 8):
                    if code == 9 and val:     # if_tsresol
                        v = val[0]
                        div = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                    elif code == 14 and len(val) == 8:   # if_tsoffset (seconds)
                        off = struct.unpack(e + "q", val)[0]
                ifaces.append((lt, div, off))
            elif btype in (6, 2):             # Enhanced / obsolete Packet Block
                if btype == 6:
                    iface, hi, lo, cap, orig = struct.unpack(e + "IIIII", body[:20])
                    data_at = 20
                else:
                    iface, _drops, hi, lo, cap, orig = struct.unpack(e + "HHIIII", body[:20])
                    data_at = 20
                if iface >= len(ifaces):
                    raise CaptureError(f"packet refers to unknown interface {iface}")
                lt, div, off = ifaces[iface]
                ts = ((hi << 32) | lo) / div + off
                last_ts = ts
                yield ts, body[data_at:data_at + cap], orig, lt
            elif btype == 3:                  # Simple Packet Block: no timestamp
                if not ifaces:
                    raise CaptureError("packet before any interface description")
                orig = struct.unpack(e + "I", body[:4])[0]
                yield last_ts, body[4:4 + min(orig, len(body) - 4)], orig, ifaces[0][0]
            elif btype == 5:                  # Interface Statistics Block
                iface = struct.unpack(e + "I", body[:4])[0]
                for code, val in options(body, 12):
                    if code in (5, 7) and len(val) == 8:   # isb_ifdrop / isb_osdrop
                        drops[(iface, code)] = struct.unpack(e + "Q", val)[0]
                info.reported_drops = sum(drops.values())
            # other block types (name resolution, custom, ...) are skipped

    return gen()


def iter_packets(path: str, info: Optional[CaptureInfo] = None,
                 max_packets: Optional[int] = None) -> Iterator[Packet]:
    """Yield decoded packets from a pcap/pcapng file, streaming."""
    fmt = sniff_format(path)
    if info is None:
        info = CaptureInfo(path=path, file_format=fmt, linktype=-1,
                           file_size=os.path.getsize(path))
    with open(path, "rb") as f:
        try:
            if fmt == "pcap":
                linktype, it = _pcap_records(f)
                info.linktype = linktype
            else:
                it = _pcapng_records(f, info)
        except CaptureError:
            raise
        except Exception as exc:
            raise CaptureError(f"Could not read capture header: {exc}") from exc
        no = 0
        last_ts = None
        while True:
            try:
                ts, buf, orig_len, linktype = next(it)
            except StopIteration:
                break
            except Exception as exc:  # truncated final record, corrupt block
                info.warnings.append(
                    f"Capture file is damaged or was cut off after frame {no}: {exc}. "
                    "Frames up to that point were analysed.")
                break
            if info.linktype == -1:
                info.linktype = linktype
            elif linktype != info.linktype and linktype not in info.extra_linktypes:
                info.extra_linktypes.append(linktype)
            no += 1
            ts = float(ts)
            if no == 1:
                info.first_ts = ts
            if last_ts is not None and ts < last_ts:
                info.time_went_backwards += 1
            last_ts = ts
            info.last_ts = max(info.last_ts, ts)
            try:
                pkt = decode(no, ts, buf, linktype)
            except CaptureError:
                if linktype == info.linktype:
                    raise
                # a second interface we cannot decode (e.g. 802.11 radiotap)
                msg = f"Frames from an interface with link type {linktype} were skipped (unsupported)."
                if msg not in info.warnings:
                    info.warnings.append(msg)
                pkt = Packet(no=no, ts=ts, length=len(buf), proto="NON-IP")
            if orig_len and orig_len > len(buf):     # cut by the capture snaplen
                pkt.truncated = True
                pkt.length = max(pkt.length, orig_len)
            if pkt.proto == "NON-IP":
                info.non_ip_frames += 1
            info.packets = no
            yield pkt
            if max_packets and no >= max_packets:
                info.stopped_early = True
                info.warnings.append(
                    f"Stopped after {max_packets:,} frames (--max-packets). "
                    "Results cover only the start of the capture.")
                break
        if no == 0:
            why = " " + " ".join(info.warnings) if info.warnings else ""
            raise CaptureError("The capture contains no readable packets." + why)
