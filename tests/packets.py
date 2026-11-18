"""Hand-built packet bytes for tests (no network needed)."""
import socket
import struct


def ipv4(proto, payload, src="10.0.0.5", dst="93.184.216.34", ttl=64, ident=1):
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0, ttl, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def tcp(src_port, dst_port, flags, data=b"", seq=100):
    return struct.pack("!HHLLBBHHH", src_port, dst_port, seq, 0, 5 << 4, flags, 8192, 0, 0) + data


def udp(src_port, dst_port, data=b""):
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(data), 0) + data


def icmp_echo():
    return struct.pack("!BBH", 8, 0, 0) + b"abcd"


def dns_name(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(name, qtype=1, ident=0x1234):
    return (struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
            + dns_name(name) + struct.pack("!HH", qtype, 1))


def dns_response(name, address, ident=0x1234):
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + question + answer
