"""Wireshark-style packet capture and analysis using only the standard library.

Layers, kept apart on purpose:

* Parsers (`parse_ipv4`, `parse_tcp`, `decode_dns`, ...) are pure functions over
  bytes. They never touch the network, so they are testable with hand-built
  packets.
* Files: `PcapWriter` / `read_pcap` use the classic libpcap format, so captures
  open in Wireshark and Wireshark captures can be analysed here without any
  special privileges.
* Analysis: `compile_filter` (tcpdump-like expressions), `CaptureStats`,
  `Deduplicator`.
* `PacketSniffer` opens a raw socket. This needs Administrator (Windows) or
  root (Linux) and only works on networks you own or may monitor.

IPv6 is decoded everywhere (pcap files, Linux live capture). Live IPv6 capture
on Windows is NOT supported: the IPv4 raw socket used there never sees it.
Files: classic pcap and pcapng are read (Ethernet incl. VLAN, raw IP, Linux
SLL/SLL2, BSD/Npcap loopback); captures are written as classic pcap.
On Windows a raw socket sees IP-level traffic of a single interface.
"""

import ipaddress
import socket
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass, field

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
ICMPV6_TYPES = {1: "dest-unreachable", 3: "time-exceeded", 128: "echo-request",
                129: "echo-reply", 133: "router-solicit", 134: "router-advert",
                135: "neighbor-solicit", 136: "neighbor-advert"}
_ETHERTYPES_IP = (b"\x08\x00", b"\x86\xdd")  # IPv4, IPv6
TCP_FLAGS = (("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
             ("ACK", 0x10), ("URG", 0x20))
ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request",
              11: "time-exceeded"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}


class SniffError(Exception):
    """Capture could not start (usually missing privileges)."""


class FilterError(ValueError):
    """A capture filter expression could not be understood."""


@dataclass
class Packet:
    src: str
    dst: str
    protocol: str
    length: int
    version: int = 4
    ttl: int = 0
    ident: int = 0
    src_port: int = 0
    dst_port: int = 0
    flags: str = ""
    seq: int = 0
    ack: int = 0
    info: str = ""
    timestamp: float = 0.0
    payload: bytes = field(default=b"", repr=False)
    raw: bytes = field(default=b"", repr=False)

    def summary(self):
        if self.src_port or self.dst_port:
            left, right = self.endpoint(self.src, self.src_port), self.endpoint(self.dst, self.dst_port)
        else:
            left, right = self.src, self.dst
        flags = f" [{self.flags}]" if self.flags else ""
        info = f" {self.info}" if self.info else ""
        return f"{self.protocol:<6} {left:>21} -> {right:<21} len={self.length}{flags}{info}"

    @staticmethod
    def endpoint(address, port):
        """'1.2.3.4:80' or, for IPv6, '[::1]:80'."""
        return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


# --- pure parsers ----------------------------------------------------------
def parse_ipv4(data):
    """Return (header dict, payload bytes). Raises ValueError if malformed."""
    if len(data) < 20:
        raise ValueError("too short for an IPv4 header")
    version_ihl, _tos, total_length, ident, _frag, ttl, proto, _csum, src, dst = \
        struct.unpack("!BBHHHBBH4s4s", data[:20])
    if version_ihl >> 4 != 4:
        raise ValueError("not an IPv4 packet")
    header_len = (version_ihl & 0x0F) * 4
    if header_len < 20 or len(data) < header_len:
        raise ValueError("bad IPv4 header length")
    header = {
        "ttl": ttl,
        "ident": ident,
        "protocol": proto,
        "src": socket.inet_ntoa(src),
        "dst": socket.inet_ntoa(dst),
        "total_length": total_length,
    }
    return header, data[header_len:]


_EXTENSION_HEADERS = {0, 43, 60}  # hop-by-hop, routing, destination options


def parse_ipv6(data):
    """Return (header dict, payload bytes). Skips extension headers.

    header["protocol"] is the upper-layer protocol number. For a non-first
    fragment the upper layer cannot be decoded, so protocol is set to 44.
    Raises ValueError if malformed.
    """
    if len(data) < 40:
        raise ValueError("too short for an IPv6 header")
    first, payload_length, next_header, hop_limit = struct.unpack("!IHBB", data[:8])
    if first >> 28 != 6:
        raise ValueError("not an IPv6 packet")
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    payload = data[40:40 + payload_length]
    for _ in range(8):  # extension header chain (bounded)
        if next_header in _EXTENSION_HEADERS or next_header == 51:
            if len(payload) < 8:
                raise ValueError("truncated IPv6 extension header")
            length = (payload[1] + 2) * 4 if next_header == 51 else (payload[1] + 1) * 8
            next_header, payload = payload[0], payload[length:]
        elif next_header == 44:  # fragment
            if len(payload) < 8:
                raise ValueError("truncated IPv6 fragment header")
            offset = struct.unpack("!H", payload[2:4])[0] >> 3
            if offset:
                return {"ttl": hop_limit, "ident": 0, "protocol": 44, "src": src, "dst": dst,
                        "total_length": 40 + payload_length}, b""
            next_header, payload = payload[0], payload[8:]
        else:
            break
    return {"ttl": hop_limit, "ident": 0, "protocol": next_header, "src": src, "dst": dst,
            "total_length": 40 + payload_length}, payload


def tcp_flag_names(flags):
    return "|".join(name for name, bit in TCP_FLAGS if flags & bit)


def parse_tcp(data):
    if len(data) < 20:
        raise ValueError("too short for a TCP header")
    src, dst, seq, ack, offset_byte, flags, window = struct.unpack("!HHLLBBH", data[:16])
    offset = (offset_byte >> 4) * 4
    if offset < 20 or len(data) < offset:
        raise ValueError("bad TCP header length")
    return {"src_port": src, "dst_port": dst, "seq": seq, "ack": ack,
            "flags": tcp_flag_names(flags), "window": window}, data[offset:]


def parse_udp(data):
    if len(data) < 8:
        raise ValueError("too short for a UDP header")
    src, dst, length, _csum = struct.unpack("!HHHH", data[:8])
    return {"src_port": src, "dst_port": dst, "length": length}, data[8:]


def parse_icmp(data):
    if len(data) < 4:
        raise ValueError("too short for an ICMP header")
    icmp_type, code, _csum = struct.unpack("!BBH", data[:4])
    return {"type": icmp_type, "code": code}, data[4:]


# --- DNS -------------------------------------------------------------------
def _read_name(data, offset):
    """Read a DNS name (with compression). Returns (name, offset after name)."""
    labels, end, hops = [], None, 0
    while True:
        if offset >= len(data):
            raise ValueError("DNS name runs past the packet")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            hops += 1
            if hops > 20:
                raise ValueError("DNS compression loop")
            continue
        if length & 0xC0:
            raise ValueError("bad DNS label")
        offset += 1
        if offset + length > len(data):
            raise ValueError("DNS label runs past the packet")
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), (end if end is not None else offset)


def decode_dns(payload):
    """Decode a DNS message into a dict. Raises ValueError if malformed."""
    if len(payload) < 12:
        raise ValueError("too short for a DNS header")
    ident, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    offset = 12
    questions, answers = [], []
    for _ in range(min(qdcount, 20)):
        name, offset = _read_name(payload, offset)
        if offset + 4 > len(payload):
            raise ValueError("truncated DNS question")
        qtype, _qclass = struct.unpack("!HH", payload[offset:offset + 4])
        offset += 4
        questions.append((name, DNS_TYPES.get(qtype, str(qtype))))
    for _ in range(min(ancount, 50)):
        name, offset = _read_name(payload, offset)
        if offset + 10 > len(payload):
            raise ValueError("truncated DNS answer")
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", payload[offset:offset + 10])
        offset += 10
        rdata = payload[offset:offset + rdlen]
        if len(rdata) < rdlen:
            raise ValueError("truncated DNS record data")
        if rtype == 1 and rdlen == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == 28 and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5):
            value = _read_name(payload, offset)[0]
        else:
            value = f"<{rdlen} bytes>"
        offset += rdlen
        answers.append((name, DNS_TYPES.get(rtype, str(rtype)), value))
    return {"id": ident, "response": bool(flags & 0x8000),
            "questions": questions, "answers": answers}


def dns_summary(payload):
    try:
        message = decode_dns(payload)
    except ValueError:
        return "DNS?"
    question = message["questions"][0] if message["questions"] else ("?", "?")
    if not message["response"]:
        return f"DNS query {question[1]} {question[0]}"
    values = ", ".join(value for _name, _type, value in message["answers"][:3])
    return f"DNS response {question[0]} -> {values or 'no answer'}"


# --- packet decoding -------------------------------------------------------
def printable_preview(payload, limit=60):
    """First line of the payload if it looks like text, else ''."""
    chunk = payload[:limit]
    if not chunk:
        return ""
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in chunk)
    if printable / len(chunk) < 0.9:
        return ""
    return chunk.decode("ascii", errors="replace").splitlines()[0] if chunk.strip() else ""


def parse_packet(data, timestamp=0.0):
    """Decode a raw IPv4 or IPv6 packet into a Packet. Raises ValueError if malformed."""
    if not data:
        raise ValueError("empty packet")
    version = data[0] >> 4
    if version == 6:
        ip, rest = parse_ipv6(data)
    else:
        ip, rest = parse_ipv4(data)
    name = PROTOCOLS.get(ip["protocol"], f"IP/{ip['protocol']}")
    packet = Packet(src=ip["src"], dst=ip["dst"], protocol=name, version=version,
                    length=ip["total_length"], ttl=ip["ttl"], ident=ip["ident"],
                    timestamp=timestamp, raw=data)
    if name == "TCP":
        tcp, payload = parse_tcp(rest)
        packet.src_port, packet.dst_port = tcp["src_port"], tcp["dst_port"]
        packet.flags, packet.seq, packet.payload = tcp["flags"], tcp["seq"], payload
        packet.ack = tcp["ack"]
        packet.info = printable_preview(payload)
    elif name == "UDP":
        udp, payload = parse_udp(rest)
        packet.src_port, packet.dst_port = udp["src_port"], udp["dst_port"]
        packet.payload = payload
        if 53 in (udp["src_port"], udp["dst_port"]):
            packet.info = dns_summary(payload)
    elif name in ("ICMP", "ICMPv6"):
        icmp, payload = parse_icmp(rest)
        types = ICMPV6_TYPES if name == "ICMPv6" else ICMP_TYPES
        packet.info = types.get(icmp["type"], f"type={icmp['type']}")
        packet.payload = payload
    return packet


def matches(packet, protocol=None, port=None, host=None):
    """Simple capture filter: protocol name, port (either side), host IP."""
    if protocol and packet.protocol.lower() != protocol.lower():
        return False
    if port and port not in (packet.src_port, packet.dst_port):
        return False
    if host and host not in (packet.src, packet.dst):
        return False
    return True


# --- filter expressions (tcpdump-like subset) -------------------------------
def compile_filter(expression):
    """Compile e.g. 'tcp and (port 80 or port 443) and not host 10.0.0.1'.

    Supported: tcp udp icmp dns, [src|dst] host IP, [src|dst] port N,
    and / or / not, parentheses. Returns a function Packet -> bool.
    Raises FilterError on a bad expression.
    """
    tokens = expression.replace("(", " ( ").replace(")", " ) ").lower().split()
    if not tokens:
        return lambda packet: True
    parser = _FilterParser(tokens)
    predicate = parser.parse()
    return predicate


class _FilterParser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    def parse(self):
        predicate = self._or()
        if self.pos != len(self.tokens):
            raise FilterError(f"unexpected '{self.tokens[self.pos]}'")
        return predicate

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self, what="more input"):
        token = self._peek()
        if token is None:
            raise FilterError(f"expected {what}")
        self.pos += 1
        return token

    def _or(self):
        left = self._and()
        while self._peek() == "or":
            self.pos += 1
            right = self._and()
            left = (lambda a, b: lambda p: a(p) or b(p))(left, right)
        return left

    def _and(self):
        left = self._not()
        while self._peek() == "and":
            self.pos += 1
            right = self._not()
            left = (lambda a, b: lambda p: a(p) and b(p))(left, right)
        return left

    def _not(self):
        if self._peek() == "not":
            self.pos += 1
            inner = self._not()
            return lambda p: not inner(p)
        return self._atom()

    def _atom(self):
        token = self._take("a filter term")
        if token == "(":
            inner = self._or()
            if self._take("')'") != ")":
                raise FilterError("missing ')'")
            return inner
        if token in ("tcp", "udp", "icmp"):
            name = token.upper()
            return lambda p: p.protocol == name
        if token in ("icmp6", "icmpv6"):
            return lambda p: p.protocol == "ICMPv6"
        if token in ("ip", "ip4", "ipv4"):
            return lambda p: p.version == 4
        if token in ("ip6", "ipv6"):
            return lambda p: p.version == 6
        if token == "dns":
            return lambda p: p.protocol == "UDP" and 53 in (p.src_port, p.dst_port)
        direction = None
        if token in ("src", "dst"):
            direction, token = token, self._take("'host' or 'port'")
        if token == "host":
            text = self._take("an IP address")
            try:
                ip = str(ipaddress.ip_address(text))  # normalised, same form as decoded packets
            except ValueError:
                raise FilterError(f"'{text}' is not an IP address") from None
            if direction == "src":
                return lambda p: p.src == ip
            if direction == "dst":
                return lambda p: p.dst == ip
            return lambda p: ip in (p.src, p.dst)
        if token == "port":
            text = self._take("a port number")
            if not text.isdigit() or not 0 < int(text) < 65536:
                raise FilterError(f"'{text}' is not a valid port")
            number = int(text)
            if direction == "src":
                return lambda p: p.src_port == number
            if direction == "dst":
                return lambda p: p.dst_port == number
            return lambda p: number in (p.src_port, p.dst_port)
        raise FilterError(f"unknown term '{token}'")


# --- statistics ------------------------------------------------------------
class CaptureStats:
    """Protocol counts, top talkers and conversations (Wireshark's Statistics menu)."""

    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.protocols = Counter()
        self.ip_bytes = Counter()
        self.conversations = Counter()
        self.first = None
        self.last = None

    def add(self, packet):
        self.packets += 1
        self.bytes += packet.length
        self.protocols[packet.protocol] += 1
        self.ip_bytes[packet.src] += packet.length
        self.ip_bytes[packet.dst] += packet.length
        a = f"{packet.src}:{packet.src_port}" if packet.src_port else packet.src
        b = f"{packet.dst}:{packet.dst_port}" if packet.dst_port else packet.dst
        self.conversations[(packet.protocol,) + tuple(sorted((a, b)))] += 1
        if packet.timestamp:
            self.first = packet.timestamp if self.first is None else min(self.first, packet.timestamp)
            self.last = packet.timestamp if self.last is None else max(self.last, packet.timestamp)

    def report(self, top=5):
        lines = [f"Packets: {self.packets}   Bytes: {self.bytes}"]
        if self.first is not None and self.last is not None and self.last > self.first:
            lines.append(f"Duration: {self.last - self.first:.2f}s")
        lines.append("\nProtocols:")
        for name, count in self.protocols.most_common():
            lines.append(f"  {name:<8}{count:>7}  ({100 * count / self.packets:.0f}%)")
        lines.append("\nTop talkers (bytes):")
        for ip, size in self.ip_bytes.most_common(top):
            lines.append(f"  {ip:<18}{size:>10}")
        lines.append("\nTop conversations (packets):")
        for (proto, a, b), count in self.conversations.most_common(top):
            lines.append(f"  {proto:<5} {a} <-> {b}  {count}")
        return "\n".join(lines)


# --- TCP streams ("Follow TCP Stream") ---------------------------------------
@dataclass
class StreamChunk:
    direction: str          # "client" or "server"
    timestamp: float
    data: bytes = b""
    missing: int = 0        # bytes lost before this chunk (capture gap), data is empty then


class TcpStream:
    """All packets of one TCP conversation, reassembled per direction."""

    def __init__(self, key):
        self.key = key
        self.packets = []

    def add(self, packet):
        self.packets.append(packet)

    @property
    def client(self):
        """Endpoint that opened the connection (first bare SYN), else first sender."""
        for packet in self.packets:
            if packet.flags == "SYN":
                return (packet.src, packet.src_port)
        first = self.packets[0]
        return (first.src, first.src_port)

    @property
    def server(self):
        return next(ep for ep in self.key if ep != self.client) if len(set(self.key)) > 1 else self.client

    def label(self):
        c, s = self.client, self.server
        return f"{Packet.endpoint(*c)} <-> {Packet.endpoint(*s)}"

    def byte_counts(self):
        counts = {"client": 0, "server": 0}
        for chunk in self.chunks():
            counts[chunk.direction] += len(chunk.data)
        return counts

    def guess_protocol(self):
        for chunk in self.chunks():
            head = chunk.data[:8]
            if head.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"HTTP/", b"DELE", b"OPTI")):
                return "http"
            if head.startswith(b"\x16\x03"):
                return "tls"
            if head.startswith(b"SSH-"):
                return "ssh"
            if head[:4] in (b"220 ", b"EHLO", b"HELO"):
                return "smtp/ftp"
            return ""
        return ""

    def chunks(self):
        """Reassembled data in time order. Retransmissions are dropped and gaps
        are reported as chunks with `missing` set."""
        client = self.client
        by_direction = {"client": [], "server": []}
        syn = {"client": None, "server": None}
        for packet in self.packets:
            key = "client" if (packet.src, packet.src_port) == client else "server"
            if syn[key] is None and "SYN" in packet.flags.split("|"):
                syn[key] = packet
            if packet.payload:
                by_direction[key].append(packet)

        chunks = []
        for direction, packets in by_direction.items():
            if not packets:
                continue
            # With the SYN we know where the data starts (ISN + 1), so loss at the
            # very beginning of a stream is detectable too.
            base = syn[direction].seq if syn[direction] else packets[0].seq

            def relative(p, base=base):  # signed distance, safe across 32-bit wrap
                return ((p.seq - base + 2 ** 31) & 0xFFFFFFFF) - 2 ** 31

            expected = 1 if syn[direction] else None
            latest = 0.0
            for packet in sorted(packets, key=relative):
                seq, data = relative(packet), packet.payload
                if expected is None:
                    expected = seq
                if seq + len(data) <= expected:
                    continue  # retransmission of data we already have
                if seq < expected:
                    data, seq = data[expected - seq:], expected
                # Data is ordered by sequence number; make timestamps follow that
                # order, otherwise the time-sort below would undo the reordering.
                latest = max(latest, packet.timestamp)
                if seq > expected:
                    chunks.append(StreamChunk(direction, latest, b"", seq - expected))
                chunks.append(StreamChunk(direction, latest, data))
                expected = seq + len(data)
        return sorted(chunks, key=lambda c: (c.timestamp, c.direction))

    def render(self, limit=100_000):
        """Readable text: one block per direction change; non-printable bytes as '.'."""
        lines, current, buffer, total = [], None, [], 0

        def flush():
            if buffer:
                text = b"".join(buffer).decode("latin-1")
                text = "".join(ch if ch == "\n" or " " <= ch <= "~" else "." for ch in text.replace("\r", ""))
                arrow = "client -> server" if current == "client" else "server -> client"
                lines.append(f"--- {arrow} ({sum(len(b) for b in buffer)} bytes) ---")
                lines.append(text)
            buffer.clear()

        for chunk in self.chunks():
            if chunk.missing:
                flush()
                lines.append(f"[... {chunk.missing} byte(s) missing from capture ...]")
                current = None
                continue
            if chunk.direction != current:
                flush()
                current = chunk.direction
            buffer.append(chunk.data)
            total += len(chunk.data)
            if total >= limit:
                flush()
                lines.append(f"[... output truncated at {limit} bytes ...]")
                return "\n".join(lines)
        flush()
        return "\n".join(lines) if lines else "(no payload data in this stream)"


def tcp_streams(packets):
    """Group TCP packets into streams, in order of first appearance."""
    streams = {}
    for packet in packets:
        if packet.protocol != "TCP":
            continue
        key = tuple(sorted(((packet.src, packet.src_port), (packet.dst, packet.dst_port))))
        streams.setdefault(key, TcpStream(key)).add(packet)
    return list(streams.values())


def drop_exact_copies(packets, window=0.05):
    """Remove byte-identical copies of a packet logged within `window` seconds.

    Some capture tools (Windows pktmon) record each packet once per network
    component it passes, so one packet can appear 5-10 times in the file.
    Returns (kept packets, number dropped).
    """
    kept, dropped, last_seen = [], 0, {}
    for packet in packets:
        previous = last_seen.get(packet.raw)
        last_seen[packet.raw] = packet.timestamp
        if previous is not None and abs(packet.timestamp - previous) <= window:
            dropped += 1
            continue
        kept.append(packet)
    return kept, dropped


class Deduplicator:
    """Drop packets seen twice within a short window.

    Some Windows setups deliver an outgoing packet twice to a raw socket. The
    IP identification field plus TCP sequence number tell a duplicate apart
    from a genuine retransmission (a retransmission gets a new IP id).
    Some stacks (e.g. Windows SYN packets) leave the IP id at 0; for those the
    window is much tighter (`zero_id_window`), because a real TCP retransmission
    is never sent within a few milliseconds of the original.
    """

    def __init__(self, window=0.05, zero_id_window=0.005):
        self.window = window
        self.zero_id_window = zero_id_window
        self._seen = {}

    def is_duplicate(self, packet, now=None):
        now = packet.timestamp if now is None else now
        window = self.window if packet.ident else self.zero_id_window
        # Everything that distinguishes two genuinely different packets must be in
        # the key (ack number and payload too), otherwise a burst of ACKs or
        # same-sized datagrams with IP id 0 (all of IPv6) would be dropped.
        key = (packet.src, packet.dst, packet.protocol, packet.ident, packet.seq,
               packet.ack, packet.src_port, packet.dst_port, packet.length,
               packet.flags, hash(packet.payload))
        previous = self._seen.get(key)
        self._seen[key] = now
        if len(self._seen) > 2000:
            self._seen = {k: t for k, t in self._seen.items() if now - t <= self.window}
        return previous is not None and now - previous <= window


# --- pcap files ------------------------------------------------------------
_PCAP_MAGIC = 0xA1B2C3D4
_LINKTYPE_ETHERNET, _LINKTYPE_RAW, _LINKTYPE_LINUX_SLL = 1, 101, 113


class PcapWriter:
    """Write captured packets as a classic pcap file (raw-IP link type)."""

    def __init__(self, path):
        self._file = open(path, "wb")
        self._file.write(struct.pack("<IHHiIII", _PCAP_MAGIC, 2, 4, 0, 0, 65535, _LINKTYPE_RAW))

    def write(self, packet):
        if not packet.raw:
            return
        seconds = int(packet.timestamp)
        micros = int((packet.timestamp - seconds) * 1_000_000)
        size = len(packet.raw)
        self._file.write(struct.pack("<IIII", seconds, micros, size, size))
        self._file.write(packet.raw)

    def close(self):
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


_LINKTYPE_NULL, _LINKTYPE_IPV4, _LINKTYPE_IPV6, _LINKTYPE_LINUX_SLL2 = 0, 228, 229, 276
_LINKTYPE_IEEE802_11 = 105
SUPPORTED_LINKTYPES = {_LINKTYPE_NULL, _LINKTYPE_ETHERNET, _LINKTYPE_RAW, _LINKTYPE_LINUX_SLL,
                       _LINKTYPE_IPV4, _LINKTYPE_IPV6, _LINKTYPE_LINUX_SLL2, _LINKTYPE_IEEE802_11}
_LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00"


def wifi_payload(frame):
    """IP packet inside an unencrypted 802.11 data frame (LLC/SNAP encapsulated), else None.

    Windows pktmon writes Wi-Fi adapters' frames like this while labelling the
    file as Ethernet, so Ethernet frames that don't parse are tried here too.
    """
    if len(frame) < 24 or (frame[0] >> 2) & 0x3 != 2:       # frame type 2 = data
        return None
    header = 24
    if frame[1] & 0x03 == 0x03:                             # ToDS + FromDS: fourth address
        header += 6
    if frame[0] & 0x80:                                     # QoS data subtype
        header += 2
        if frame[1] & 0x80:                                 # +HT control field
            header += 4
    snap = frame[header:header + 8]
    if len(snap) < 8 or snap[:6] != _LLC_SNAP or snap[6:8] not in _ETHERTYPES_IP:
        return None                                         # encrypted or not IP
    return frame[header + 8:]
_NULL_FAMILIES = {2, 24, 28, 30}         # AF_INET, and AF_INET6 on the BSDs / macOS
_MAX_RECORD = 262144
_MAX_BLOCK = 16 * 1024 * 1024


def frame_to_ip(linktype, frame):
    """Strip the link-layer header. Returns the IP packet bytes, or None to skip."""
    if linktype in (_LINKTYPE_RAW, _LINKTYPE_IPV4, _LINKTYPE_IPV6):
        return frame
    if linktype == _LINKTYPE_ETHERNET:
        if len(frame) >= 18 and frame[12:14] == b"\x81\x00":      # 802.1Q VLAN tag
            return frame[18:] if frame[16:18] in _ETHERTYPES_IP else None
        if len(frame) >= 14 and frame[12:14] in _ETHERTYPES_IP:
            return frame[14:]
        return wifi_payload(frame)                                 # mislabelled Wi-Fi (pktmon)
    if linktype == _LINKTYPE_IEEE802_11:
        return wifi_payload(frame)
    if linktype == _LINKTYPE_LINUX_SLL:
        return frame[16:] if len(frame) >= 16 and frame[14:16] in _ETHERTYPES_IP else None
    if linktype == _LINKTYPE_LINUX_SLL2:
        return frame[20:] if len(frame) >= 20 and frame[0:2] in _ETHERTYPES_IP else None
    if linktype == _LINKTYPE_NULL and len(frame) >= 4:
        # 4-byte address family in the *capturing* machine's byte order
        family = int.from_bytes(frame[:4], "little")
        if family not in _NULL_FAMILIES:
            family = int.from_bytes(frame[:4], "big")
        return frame[4:] if family in _NULL_FAMILIES else None
    return None


def _decode(linktype, frame, timestamp):
    data = frame_to_ip(linktype, frame)
    if data is None:
        return None
    try:
        return parse_packet(data, timestamp=timestamp)
    except ValueError:
        return None


def read_pcap(path):
    """Yield decoded Packets from a .pcap or .pcapng file (format is detected).

    Frames that are not IPv4/IPv6 are skipped.
    Raises ValueError for unsupported or corrupt files.
    """
    with open(path, "rb") as file:
        magic = file.read(4)
        if len(magic) < 4:
            raise ValueError("file is too short to be a pcap capture")
        file.seek(0)
        reader = _read_pcapng if magic == b"\x0a\x0d\x0d\x0a" else _read_classic
        for packet in reader(file):
            if packet is not None:
                yield packet


read_capture = read_pcap


def _read_classic(file):
    header = file.read(24)
    if len(header) < 24:
        raise ValueError("file is too short to be a pcap capture")
    magic = header[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("not a pcap file")
    divisor = 1_000_000_000 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1_000_000
    linktype = struct.unpack(endian + "I", header[20:24])[0]
    if linktype not in SUPPORTED_LINKTYPES:
        raise ValueError(f"unsupported link type {linktype}")
    while True:
        record = file.read(16)
        if len(record) < 16:
            return
        seconds, fraction, included, _original = struct.unpack(endian + "IIII", record)
        if included > _MAX_RECORD:
            raise ValueError("corrupt record length")
        data = file.read(included)
        if len(data) < included:
            return  # truncated final record
        yield _decode(linktype, data, seconds + fraction / divisor)


def _interface_resolution(options, endian):
    """Seconds per timestamp unit from IDB options (if_tsresol, code 9); default 1 µs."""
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[offset:offset + 4])
        if code == 0:
            break
        value = options[offset + 4:offset + 4 + length]
        if code == 9 and value:
            exponent = value[0] & 0x7F
            return 2.0 ** -exponent if value[0] & 0x80 else 10.0 ** -exponent
        offset += 4 + length + (-length % 4)
    return 1e-6


def _read_pcapng(file):
    """pcapng (Wireshark's default format): sections, interfaces, packet blocks."""
    endian, interfaces = "<", []
    while True:
        head = file.read(8)
        if len(head) < 8:
            return
        if head[:4] == b"\x0a\x0d\x0d\x0a":              # Section Header Block
            byte_order = file.read(4)
            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("pcapng: bad byte-order magic (corrupt file?)")
            total = struct.unpack(endian + "I", head[4:8])[0]
            if total < 28 or total % 4 or total > _MAX_BLOCK:
                raise ValueError("pcapng: bad section header length")
            file.read(total - 12)
            interfaces = []                              # interface ids restart per section
            continue

        block_type, total = struct.unpack(endian + "II", head)
        if total < 12 or total % 4 or total > _MAX_BLOCK:
            raise ValueError("pcapng: corrupt block length")
        body = file.read(total - 8)
        if len(body) < total - 8:
            return                                       # truncated final block
        body = body[:-4]                                 # drop the trailing length copy

        if block_type == 1 and len(body) >= 8:           # Interface Description Block
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _interface_resolution(body[8:], endian)))
        elif block_type == 6 and len(body) >= 20:        # Enhanced Packet Block
            iface, high, low, captured, _original = struct.unpack(endian + "IIIII", body[:20])
            if iface < len(interfaces):
                linktype, unit = interfaces[iface]
                yield _decode(linktype, body[20:20 + captured], ((high << 32) | low) * unit)
        elif block_type == 3 and len(body) >= 4 and interfaces:   # Simple Packet Block
            original = struct.unpack(endian + "I", body[:4])[0]
            yield _decode(interfaces[0][0], body[4:4 + original], 0.0)
        elif block_type == 2 and len(body) >= 20:        # obsolete Packet Block
            iface, _drops, high, low, captured, _original = struct.unpack(endian + "HHIIII", body[:20])
            if iface < len(interfaces):
                linktype, unit = interfaces[iface]
                yield _decode(linktype, body[20:20 + captured], ((high << 32) | low) * unit)
        # other blocks (name resolution, statistics, custom) carry no packets


# --- live capture ----------------------------------------------------------
def local_ip():
    """IP of the interface used for outbound traffic. Sends nothing."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))  # RFC 5737 address; UDP connect sends no packet
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


class PacketSniffer:
    def __init__(self, interface_ip=None, dedupe=True):
        self.interface_ip = interface_ip or local_ip()
        self._sock = None
        self._dedupe = Deduplicator() if dedupe else None

    def open(self):
        try:
            if sys.platform == "win32":
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((self.interface_ip, 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            raise SniffError("permission denied: run the terminal as Administrator/root") from None
        except (OSError, AttributeError) as error:
            raise SniffError(f"cannot open raw socket: {error}") from None
        sock.settimeout(1.0)
        self._sock = sock

    def close(self):
        if self._sock is None:
            return
        try:
            if sys.platform == "win32":
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except OSError:
            pass
        self._sock.close()
        self._sock = None

    def packets(self):
        """Yield decoded packets (None on idle ticks) until the caller stops."""
        if self._sock is None:
            self.open()
        while True:
            try:
                data = self._sock.recv(65535)
            except socket.timeout:
                yield None  # lets the caller check for Ctrl+C / limits
                continue
            if sys.platform != "win32":
                if len(data) < 14 or data[12:14] not in _ETHERTYPES_IP:
                    continue  # not IP over Ethernet
                data = data[14:]
            try:
                packet = parse_packet(data, timestamp=time.time())
            except ValueError:
                continue
            if self._dedupe and self._dedupe.is_duplicate(packet):
                continue
            yield packet
