"""TLS handshake timing from the first bytes of each TCP stream.

Only the unencrypted part of the handshake is parsed: record headers,
ClientHello (SNI, ALPN, offered versions), ServerHello (chosen version and
cipher) and plaintext alerts. Timing:

* ``server_hello_ms``: ClientHello -> ServerHello (one network RTT plus
  server processing).
* ``setup_ms``: ClientHello -> handshake complete. TLS 1.3: the client's first
  encrypted record after the ServerHello (its Finished). TLS 1.2: the server's
  ChangeCipherSpec, which follows the client's Finished.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
          40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
          44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
          47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error",
          51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
          80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
          109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
          116: "certificate_required", 120: "no_application_protocol"}


@dataclass
class TLSSession:
    conn_index: int
    client: str
    server: str
    server_port: int
    sni: str = ""
    alpn: list = field(default_factory=list)
    offered: list = field(default_factory=list)
    version: str = ""
    cipher: Optional[int] = None
    ch_frame: int = 0
    ch_ts: Optional[float] = None
    sh_frame: int = 0
    sh_ts: Optional[float] = None
    done_frame: int = 0
    done_ts: Optional[float] = None
    alert: Optional[str] = None
    alert_frame: int = 0
    alert_by: str = ""
    _buf: dict = field(default_factory=lambda: {True: bytearray(), False: bytearray()})
    _encrypted: dict = field(default_factory=lambda: {True: False, False: False})

    @property
    def server_hello_ms(self) -> Optional[float]:
        if self.ch_ts is None or self.sh_ts is None:
            return None
        return (self.sh_ts - self.ch_ts) * 1000

    @property
    def setup_ms(self) -> Optional[float]:
        if self.ch_ts is None or self.done_ts is None:
            return None
        return (self.done_ts - self.ch_ts) * 1000


class TLSAnalyzer:
    def __init__(self):
        self.sessions: dict = {}     # conn index -> TLSSession
        self.not_tls: set = set()

    def feed(self, conn, is_client: bool, chunk: bytes, pkt) -> bool:
        """Callback from the TCP reassembler. Return False to stop feeding."""
        idx = conn.index
        if idx in self.not_tls:
            return False
        s = self.sessions.get(idx)
        if s is None:
            # Must start with a handshake record carrying a ClientHello.
            if not (is_client and len(chunk) >= 6 and chunk[0] == 22 and chunk[1] == 3
                    and chunk[5] == 1):
                self.not_tls.add(idx)
                return False
            srv = conn.server
            s = TLSSession(conn_index=idx, client=pkt.src, server=pkt.dst,
                           server_port=srv.port if srv else pkt.dport)
            self.sessions[idx] = s
        buf = s._buf[is_client]
        buf.extend(chunk)
        self._parse(s, is_client, pkt)
        # Stop once the handshake is complete (or failed) in this direction.
        if s.done_ts is not None or s.alert is not None:
            s._buf[is_client] = bytearray()       # release the reassembly buffer
            return False
        return True

    def _parse(self, s: TLSSession, is_client: bool, pkt) -> None:
        buf = s._buf[is_client]
        while len(buf) >= 5:
            ctype, ver, length = buf[0], struct.unpack("!H", buf[1:3])[0], struct.unpack("!H", buf[3:5])[0]
            if ctype not in (20, 21, 22, 23) or (ver >> 8) != 3:
                buf.clear()     # lost sync, not TLS any more
                return
            if len(buf) < 5 + length:
                # Mark the ClientHello time on the frame that *starts* it.
                if ctype == 22 and length and len(buf) > 5:
                    self._first_bytes(s, is_client, buf[5], pkt)
                return
            body = bytes(buf[5:5 + length])
            del buf[:5 + length]
            self._record(s, is_client, ctype, body, pkt)

    def _first_bytes(self, s, is_client, hs_type, pkt):
        if is_client and hs_type == 1 and s.ch_ts is None and not s._encrypted[True]:
            s.ch_frame, s.ch_ts = pkt.no, pkt.ts
        if (not is_client) and hs_type == 2 and s.sh_ts is None and not s._encrypted[False]:
            s.sh_frame, s.sh_ts = pkt.no, pkt.ts

    def _record(self, s: TLSSession, is_client: bool, ctype: int, body: bytes, pkt) -> None:
        if ctype == 22 and not s._encrypted[is_client]:
            if not body:
                return
            hs_type = body[0]
            self._first_bytes(s, is_client, hs_type, pkt)
            if hs_type == 1 and is_client:
                self._client_hello(s, body)
            elif hs_type == 2 and not is_client:
                self._server_hello(s, body)
        elif ctype == 20:
            s._encrypted[is_client] = True
            if not is_client and s.version and s.version != "TLS 1.3" and s.done_ts is None:
                s.done_frame, s.done_ts = pkt.no, pkt.ts
        elif ctype == 21 and not s._encrypted[is_client] and len(body) >= 2:
            # Level 2 = fatal. Warning-level alerts (close_notify, user_canceled) are
            # a normal way to end or abandon a session, not a failure.
            if s.alert is None and body[0] == 2:
                s.alert = ALERTS.get(body[1], f"alert {body[1]}")
                s.alert_frame = pkt.no
                s.alert_by = "client" if is_client else "server"
        elif ctype == 23:
            if (is_client and s.version == "TLS 1.3" and s.sh_ts is not None
                    and s.done_ts is None and s.alert is None):
                if len(body) == 19:
                    # An encrypted alert is 2 bytes + content type + 16-byte AEAD tag = 19.
                    # The client's Finished is never that short, so the client most likely
                    # rejected the server (typically its certificate) instead of finishing.
                    s.alert = "encrypted alert (handshake rejected, probably the certificate)"
                    s.alert_frame, s.alert_by = pkt.no, "client"
                else:
                    s.done_frame, s.done_ts = pkt.no, pkt.ts
            s._encrypted[is_client] = True

    @staticmethod
    def _extensions(body: bytes, pos: int):
        if pos + 2 > len(body):
            return
        end = min(len(body), pos + 2 + struct.unpack("!H", body[pos:pos + 2])[0])
        pos += 2
        while pos + 4 <= end:
            etype, elen = struct.unpack("!HH", body[pos:pos + 4])
            yield etype, body[pos + 4:pos + 4 + elen]
            pos += 4 + elen

    def _client_hello(self, s: TLSSession, body: bytes) -> None:
        try:
            pos = 4 + 2 + 32
            sid_len = body[pos]; pos += 1 + sid_len
            cs_len = struct.unpack("!H", body[pos:pos + 2])[0]; pos += 2 + cs_len
            comp_len = body[pos]; pos += 1 + comp_len
            for etype, data in self._extensions(body, pos):
                if etype == 0 and len(data) > 5:          # server_name
                    nlen = struct.unpack("!H", data[3:5])[0]
                    s.sni = data[5:5 + nlen].decode("ascii", "replace")
                elif etype == 16 and len(data) > 2:       # ALPN
                    p, out = 2, []
                    while p < len(data):
                        ln = data[p]; out.append(data[p + 1:p + 1 + ln].decode("ascii", "replace")); p += 1 + ln
                    s.alpn = out
                elif etype == 43 and data:                # supported_versions
                    n = data[0]
                    vs = [struct.unpack("!H", data[1 + i:3 + i])[0] for i in range(0, n, 2)]
                    s.offered = [VERSIONS[v] for v in vs if v in VERSIONS]
        except (IndexError, struct.error):
            pass

    def _server_hello(self, s: TLSSession, body: bytes) -> None:
        try:
            legacy = struct.unpack("!H", body[4:6])[0]
            pos = 4 + 2 + 32
            sid_len = body[pos]; pos += 1 + sid_len
            s.cipher = struct.unpack("!H", body[pos:pos + 2])[0]; pos += 2 + 1
            version = legacy
            for etype, data in self._extensions(body, pos):
                if etype == 43 and len(data) == 2:
                    version = struct.unpack("!H", data)[0]
            s.version = VERSIONS.get(version, hex(version))
        except (IndexError, struct.error):
            pass

    def results(self) -> list:
        return [s for s in self.sessions.values() if s.ch_ts is not None]
