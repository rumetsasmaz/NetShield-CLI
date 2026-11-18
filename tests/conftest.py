"""Shared fixtures: local TLS and UDP servers (nothing leaves this machine)."""
import socket
import ssl
import threading
from pathlib import Path

import pytest

DATA = Path(__file__).parent / "data"


@pytest.fixture
def tls_server():
    """Factory: tls_server("localhost") serves tests/data/localhost.pem on a free port."""
    servers = []

    def start(name):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(DATA / f"{name}.pem", DATA / f"{name}.key")
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        servers.append(server)

        def serve():
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                try:
                    with context.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(100)
                except (ssl.SSLError, OSError):
                    pass

        threading.Thread(target=serve, daemon=True).start()
        return server.getsockname()[1]

    yield start
    for server in servers:
        server.close()


@pytest.fixture
def udp_server():
    """Factory: udp_server(handler) where handler(datagram) -> reply bytes or None."""
    servers = []

    def start(handler):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        servers.append(server)

        def serve():
            while True:
                try:
                    data, address = server.recvfrom(2048)
                except OSError:
                    return
                reply = handler(data)
                if reply:
                    server.sendto(reply, address)

        threading.Thread(target=serve, daemon=True).start()
        return server.getsockname()[1]

    yield start
    for server in servers:
        server.close()


@pytest.fixture
def closed_udp_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port
