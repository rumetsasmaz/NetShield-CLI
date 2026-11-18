"""Helpers to build DNS replies and run a fake DNS server (UDP + TCP) locally."""
import socket
import struct
import threading

from netshield import dnsclient

POINTER_TO_QNAME = b"\xc0\x0c"


def rr(rtype, rdata, name=POINTER_TO_QNAME, ttl=60):
    return name + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def txt_rdata(*strings):
    return b"".join(bytes([len(s)]) + s for s in strings)


def reply(query, answers=(), rcode=0, truncated=False):
    flags = 0x8180 | rcode | (0x0200 if truncated else 0)
    question = query[12:]
    return query[:2] + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0) + question + b"".join(answers)


class FakeDnsServer:
    """handler(query_bytes, protocol) -> reply bytes or None (stay silent)."""

    def __init__(self, handler, host="127.0.0.1"):
        self.handler = handler
        self.queries = []
        for _ in range(20):                      # find a port free for both UDP and TCP
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp.bind((host, 0))
            self.port = self.udp.getsockname()[1]
            self.tcp = socket.socket()
            try:
                self.tcp.bind((host, self.port))
                break
            except OSError:
                self.udp.close()
                self.tcp.close()
        self.tcp.listen(5)
        threading.Thread(target=self._serve_udp, daemon=True).start()
        threading.Thread(target=self._serve_tcp, daemon=True).start()

    def _serve_udp(self):
        while True:
            try:
                data, address = self.udp.recvfrom(4096)
            except OSError:
                return
            self.queries.append(("udp", data))
            answer = self.handler(data, "udp")
            if answer:
                self.udp.sendto(answer, address)

    def _serve_tcp(self):
        while True:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            with conn:
                try:
                    length = struct.unpack("!H", dnsclient._recv_exact(conn, 2))[0]
                    data = dnsclient._recv_exact(conn, length)
                except OSError:
                    continue
                self.queries.append(("tcp", data))
                answer = self.handler(data, "tcp")
                if answer:
                    conn.sendall(struct.pack("!H", len(answer)) + answer)

    def close(self):
        self.udp.close()
        self.tcp.close()


def fake_resolver(records, nxdomain=()):
    """A stand-in for dnsclient.query backed by {(name, type): [values]}."""

    def query(name, record_type="A", server=None, timeout=3.0, **_kwargs):
        name = name.lower().rstrip(".")
        if name in nxdomain or name.endswith(".invalid"):
            return dnsclient.Answer("NXDOMAIN", [], "fake")
        values = records.get((name, record_type), [])
        return dnsclient.Answer("NOERROR", [dnsclient.Record(name, record_type, 60, v) for v in values], "fake")

    return query
