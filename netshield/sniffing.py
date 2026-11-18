"""Wireshark-style packet capture and decoding using only the standard library.

Two layers, kept apart on purpose:

* Parsers (`parse_ipv4`, `parse_tcp`, ...) are pure functions over bytes. They
  never touch the network, so they can be tested with hand-built packets.
* `PacketSniffer` opens a raw socket. This needs Administrator (Windows) or
  root (Linux) and only works on networks you own or may monitor.

Limits: IPv4 only; on Windows a raw socket sees IP-level traffic of a single
interface (no Ethernet headers) and may miss traffic the OS sends itself.
"""

import socket
import struct
import sys
from dataclasses import dataclass, field

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
TCP_FLAGS = (("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08),
             ("ACK", 0x10), ("URG", 0x20))
ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request",
              11: "time-exceeded"}


class SniffError(Exception):
    """Capture could not start (usually missing privileges)."""


@dataclass
class Packet:
    src: str
    dst: str
    protocol: str
    length: int
    ttl: int = 0
    src_port: int = 0
    dst_port: int = 0
    flags: str = ""
    info: str = ""
    payload: bytes = field(default=b"", repr=False)

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
    version_ihl, _tos, total_length, _ident, _frag, ttl, proto, _csum, src, dst = \
        struct.unpack("!BBHHHBBH4s4s", data[:20])
    if version_ihl >> 4 != 4:
        raise ValueError("not an IPv4 packet")
    header_len = (version_ihl & 0x0F) * 4
    if header_len < 20 or len(data) < header_len:
        raise ValueError("bad IPv4 header length")
    header = {
        "ttl": ttl,
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


def printable_preview(payload, limit=60):
    """First line of the payload if it looks like text, else ''."""
    chunk = payload[:limit]
    if not chunk:
        return ""
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in chunk)
    if printable / len(chunk) < 0.9:
        return ""
    return chunk.decode("ascii", errors="replace").splitlines()[0] if chunk.strip() else ""


def parse_packet(data):
    """Decode a raw IPv4 packet into a Packet. Raises ValueError if malformed."""
    ip, rest = parse_ipv4(data)
    name = PROTOCOLS.get(ip["protocol"], f"IP/{ip['protocol']}")
    packet = Packet(src=ip["src"], dst=ip["dst"], protocol=name,
                    length=ip["total_length"], ttl=ip["ttl"])
    if name == "TCP":
        tcp, payload = parse_tcp(rest)
        packet.src_port, packet.dst_port = tcp["src_port"], tcp["dst_port"]
        packet.flags, packet.payload = tcp["flags"], payload
        packet.info = printable_preview(payload)
    elif name == "UDP":
        udp, payload = parse_udp(rest)
        packet.src_port, packet.dst_port = udp["src_port"], udp["dst_port"]
        packet.payload = payload
        packet.info = "DNS?" if 53 in (udp["src_port"], udp["dst_port"]) else ""
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


# --- capture ---------------------------------------------------------------
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
    def __init__(self, interface_ip=None):
        self.interface_ip = interface_ip or local_ip()
        self._sock = None

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
        """Yield decoded packets until the caller stops iterating."""
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
                yield parse_packet(data)
            except ValueError:
                continue
