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

Limits: IPv4 only; classic pcap only (no pcapng); on Windows a raw socket sees
IP-level traffic of a single interface (no Ethernet headers).
"""

import socket
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass, field

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
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
    ttl: int = 0
    ident: int = 0
    src_port: int = 0
    dst_port: int = 0
    flags: str = ""
    seq: int = 0
    info: str = ""
    timestamp: float = 0.0
    payload: bytes = field(default=b"", repr=False)
    raw: bytes = field(default=b"", repr=False)

    def summary(self):
        if self.src_port or self.dst_port:
            left, right = f"{self.src}:{self.src_port}", f"{self.dst}:{self.dst_port}"
        else:
            left, right = self.src, self.dst
        flags = f" [{self.flags}]" if self.flags else ""
        info = f" {self.info}" if self.info else ""
        return f"{self.protocol:<5} {left:>21} -> {right:<21} len={self.length}{flags}{info}"


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
    """Decode a raw IPv4 packet into a Packet. Raises ValueError if malformed."""
    ip, rest = parse_ipv4(data)
    name = PROTOCOLS.get(ip["protocol"], f"IP/{ip['protocol']}")
    packet = Packet(src=ip["src"], dst=ip["dst"], protocol=name,
                    length=ip["total_length"], ttl=ip["ttl"], ident=ip["ident"],
                    timestamp=timestamp, raw=data)
    if name == "TCP":
        tcp, payload = parse_tcp(rest)
        packet.src_port, packet.dst_port = tcp["src_port"], tcp["dst_port"]
        packet.flags, packet.seq, packet.payload = tcp["flags"], tcp["seq"], payload
        packet.info = printable_preview(payload)
    elif name == "UDP":
        udp, payload = parse_udp(rest)
        packet.src_port, packet.dst_port = udp["src_port"], udp["dst_port"]
        packet.payload = payload
        if 53 in (udp["src_port"], udp["dst_port"]):
            packet.info = dns_summary(payload)
    elif name == "ICMP":
        icmp, payload = parse_icmp(rest)
        packet.info = ICMP_TYPES.get(icmp["type"], f"type={icmp['type']}")
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
        if token == "dns":
            return lambda p: p.protocol == "UDP" and 53 in (p.src_port, p.dst_port)
        direction = None
        if token in ("src", "dst"):
            direction, token = token, self._take("'host' or 'port'")
        if token == "host":
            ip = self._take("an IP address")
            try:
                socket.inet_aton(ip)
            except OSError:
                raise FilterError(f"'{ip}' is not an IPv4 address") from None
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
        key = (packet.src, packet.dst, packet.protocol, packet.ident, packet.seq,
               packet.src_port, packet.dst_port, packet.length, packet.flags)
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


def read_pcap(path):
    """Yield decoded Packets from a classic pcap file.

    Non-IPv4 frames are skipped. Raises ValueError for unsupported/corrupt files.
    """
    with open(path, "rb") as file:
        header = file.read(24)
        if len(header) < 24:
            raise ValueError("file is too short to be a pcap capture")
        magic = header[:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("pcapng is not supported; save as classic pcap in Wireshark")
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError("not a pcap file")
        nanosecond = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype not in (_LINKTYPE_ETHERNET, _LINKTYPE_RAW, _LINKTYPE_LINUX_SLL):
            raise ValueError(f"unsupported link type {linktype}")

        while True:
            record = file.read(16)
            if len(record) < 16:
                return
            seconds, fraction, included, _original = struct.unpack(endian + "IIII", record)
            if included > 262144:
                raise ValueError("corrupt record length")
            data = file.read(included)
            if len(data) < included:
                return  # truncated final record
            if linktype == _LINKTYPE_ETHERNET:
                if len(data) < 14 or data[12:14] != b"\x08\x00":
                    continue
                data = data[14:]
            elif linktype == _LINKTYPE_LINUX_SLL:
                if len(data) < 16 or data[14:16] != b"\x08\x00":
                    continue
                data = data[16:]
            divisor = 1_000_000_000 if nanosecond else 1_000_000
            try:
                yield parse_packet(data, timestamp=seconds + fraction / divisor)
            except ValueError:
                continue


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
                if len(data) < 14 or data[12:14] != b"\x08\x00":
                    continue  # not IPv4 over Ethernet
                data = data[14:]
            try:
                packet = parse_packet(data, timestamp=time.time())
            except ValueError:
                continue
            if self._dedupe and self._dedupe.is_duplicate(packet):
                continue
            yield packet
