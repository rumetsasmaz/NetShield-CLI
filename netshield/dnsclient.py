"""Minimal DNS client: UDP with TCP fallback, standard library only.

`build_query` / `parse_response` are pure functions (testable with bytes);
`query` talks to a resolver. By default the system's own resolver is used,
so lookups go where every other program on this machine sends them.
"""

import secrets
import socket
import struct
import sys
from dataclasses import dataclass

from netshield.sniffing import _read_name

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
TYPE_NAMES = {number: name for name, number in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
FALLBACK_SERVER = "1.1.1.1"


class DnsError(ValueError):
    """Lookup failed (bad name, no resolver answered, malformed reply)."""


@dataclass
class Record:
    name: str
    type: str
    ttl: int
    value: str


@dataclass
class Answer:
    rcode: str
    records: list
    server: str = ""

    def values(self, record_type):
        return [r.value for r in self.records if r.type == record_type]


# --- encoding / decoding -----------------------------------------------------
def encode_name(name):
    name = name.strip().rstrip(".")
    if not name:
        return b"\x00"
    try:
        ascii_name = name.encode("idna")        # handles non-ASCII (e.g. Turkish) domains
    except UnicodeError:
        raise DnsError(f"'{name}' is not a valid domain name") from None
    if len(ascii_name) > 253:
        raise DnsError("domain name is longer than 253 characters")
    out = b""
    for label in ascii_name.split(b"."):
        if not 0 < len(label) <= 63:
            raise DnsError(f"'{name}' has an empty or over-long label")
        out += bytes([len(label)]) + label
    return out + b"\x00"


def build_query(name, record_type, ident):
    if record_type not in TYPES:
        raise DnsError(f"unsupported record type '{record_type}'")
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)   # recursion desired
    return header + encode_name(name) + struct.pack("!HH", TYPES[record_type], 1)


def _character_strings(rdata):
    parts, offset = [], 0
    while offset < len(rdata):
        length = rdata[offset]
        parts.append(rdata[offset + 1:offset + 1 + length].decode("utf-8", errors="replace"))
        offset += 1 + length
    return parts


def _decode_rdata(message, offset, rtype, rdata):
    if rtype == 1 and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if rtype == 28 and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5):
        return _read_name(message, offset)[0]
    if rtype == 15 and len(rdata) >= 3:
        return f"{struct.unpack('!H', rdata[:2])[0]} {_read_name(message, offset + 2)[0]}"
    if rtype == 16:
        return "".join(_character_strings(rdata))   # SPF/DMARC: strings are concatenated
    if rtype == 6:
        mname, after = _read_name(message, offset)
        rname, after = _read_name(message, after)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", message[after:after + 20])
        return f"{mname} {rname} serial={serial} refresh={refresh} retry={retry} expire={expire} min={minimum}"
    if rtype == 257 and len(rdata) >= 2:
        flags, tag_length = rdata[0], rdata[1]
        tag = rdata[2:2 + tag_length].decode("ascii", errors="replace")
        value = rdata[2 + tag_length:].decode("utf-8", errors="replace")
        return f'{flags} {tag} "{value}"'
    return rdata.hex()


def parse_response(message, ident):
    """Decode a DNS reply. Returns (Answer, truncated). Raises DnsError."""
    if len(message) < 12:
        raise DnsError("reply too short")
    reply_id, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", message[:12])
    if reply_id != ident or not flags & 0x8000:
        raise DnsError("reply does not match the query")
    truncated = bool(flags & 0x0200)
    rcode = RCODES.get(flags & 0x000F, str(flags & 0x000F))
    try:
        offset = 12
        for _ in range(qdcount):
            _name, offset = _read_name(message, offset)
            offset += 4
        records = []
        for _ in range(min(ancount, 100)):
            name, offset = _read_name(message, offset)
            if offset + 10 > len(message):
                raise ValueError("truncated record")
            rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", message[offset:offset + 10])
            offset += 10
            rdata = message[offset:offset + rdlength]
            if len(rdata) < rdlength:
                raise ValueError("truncated record data")
            value = _decode_rdata(message, offset, rtype, rdata)
            records.append(Record(name, TYPE_NAMES.get(rtype, str(rtype)), ttl, value))
            offset += rdlength
    except (ValueError, struct.error) as error:
        if truncated:
            return Answer(rcode, []), True
        raise DnsError(f"malformed reply: {error}") from None
    return Answer(rcode, records), truncated


# --- resolver discovery ------------------------------------------------------
def _split_servers(text):
    return [part for part in text.replace(",", " ").split() if part]


def system_dns_servers():
    """IPv4 resolvers configured on this machine (current settings first)."""
    servers = []
    if sys.platform == "win32":
        try:
            import winreg
            base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
                for value in ("NameServer", "DhcpNameServer"):
                    try:
                        servers += _split_servers(winreg.QueryValueEx(key, value)[0])
                    except OSError:
                        pass
                with winreg.OpenKey(key, "Interfaces") as interfaces:
                    index = 0
                    while True:
                        try:
                            name = winreg.EnumKey(interfaces, index)
                        except OSError:
                            break
                        index += 1
                        with winreg.OpenKey(interfaces, name) as interface:
                            for value in ("NameServer", "DhcpNameServer"):
                                try:
                                    servers += _split_servers(winreg.QueryValueEx(interface, value)[0])
                                except OSError:
                                    pass
        except OSError:
            pass
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as file:
                for line in file:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        servers.append(parts[1])
        except OSError:
            pass
    unique = []
    for server in servers:
        try:
            socket.inet_aton(server)
        except OSError:
            continue                    # skip IPv6 / garbage
        if server not in unique:
            unique.append(server)
    return unique


# --- querying ----------------------------------------------------------------
def _ask_udp(server, payload, timeout, port=53):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, (server, port))
        while True:
            data, address = sock.recvfrom(4096)
            if address[0] == server:
                return data


def _ask_tcp(server, payload, timeout, port=53):
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(payload)) + payload)
        header = _recv_exact(sock, 2)
        return _recv_exact(sock, struct.unpack("!H", header)[0])


def _recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("connection closed early")
        data += chunk
    return data


def query(name, record_type="A", server=None, timeout=3.0, port=53, servers=None):
    """Look up one record type. Tries each resolver in turn.

    Returns an Answer (rcode may be NXDOMAIN with no records).
    Raises DnsError if no resolver gives a usable reply.
    """
    if servers is None:
        servers = [server] if server else (system_dns_servers() or [FALLBACK_SERVER])
    last_error = "no DNS server configured"
    for candidate in servers[:4]:
        ident = secrets.randbelow(65536)
        payload = build_query(name, record_type, ident)
        try:
            answer, truncated = parse_response(_ask_udp(candidate, payload, timeout, port), ident)
            if truncated:                       # large TXT sets etc. need TCP
                answer, _ = parse_response(_ask_tcp(candidate, payload, timeout, port), ident)
        except (OSError, DnsError) as error:
            last_error = f"{candidate}: {error}"
            continue
        if answer.rcode in ("SERVFAIL", "REFUSED"):
            last_error = f"{candidate}: {answer.rcode}"
            continue
        answer.server = candidate
        return answer
    raise DnsError(f"no DNS server answered ({last_error})")


def txt_records(name, server=None, timeout=3.0):
    return query(name, "TXT", server, timeout).values("TXT")
