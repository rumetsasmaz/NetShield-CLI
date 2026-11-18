import socket
import threading

import pytest

from netshield import scanning as sc


def _listener(on_connect):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    held = []

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            on_connect(conn, held)

    threading.Thread(target=serve, daemon=True).start()
    return server, held


@pytest.fixture
def ssh_listener():
    def greet(conn, held):
        conn.sendall(b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n")
        conn.close()

    server, _ = _listener(greet)
    yield server.getsockname()[1]
    server.close()


@pytest.fixture
def silent_listener():
    """Accepts and stays quiet, like a service that waits for the client."""
    server, held = _listener(lambda conn, held: held.append(conn))
    yield server.getsockname()[1]
    server.close()
    for conn in held:
        conn.close()


@pytest.fixture
def closed_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# --- parsing ------------------------------------------------------------
def test_parse_ports():
    assert sc.parse_ports("22,80,1-3") == [1, 2, 3, 22, 80]
    assert sc.parse_ports(" 80 , 80 ") == [80]
    assert sc.parse_ports("top")
    assert len(sc.parse_ports("all")) == 65535


@pytest.mark.parametrize("bad", ["", "0", "70000", "5-2", "abc", "1-", "-5"])
def test_parse_ports_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        sc.parse_ports(bad)


def test_expand_network():
    assert sc.expand_network("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]
    assert sc.expand_network("10.0.0.7/32") == ["10.0.0.7"]
    assert len(sc.expand_network("10.0.0.0/24")) == 254


@pytest.mark.parametrize("bad", ["10.0.0.0/8", "abc", "10.0.0.0/23", "::1/128"])
def test_expand_network_rejects(bad):
    with pytest.raises(ValueError):
        sc.expand_network(bad)


def test_resolve_target(monkeypatch):
    assert sc.resolve_target("127.0.0.1") == "127.0.0.1"

    def fail(name):
        raise socket.gaierror("no such host")

    # simulate a failed lookup: some networks hijack DNS and resolve anything
    monkeypatch.setattr(socket, "gethostbyname", fail)
    with pytest.raises(ValueError, match="could not resolve"):
        sc.resolve_target("example.invalid")


# --- identification -----------------------------------------------------
@pytest.mark.parametrize("port, banner, expected", [
    (22, "SSH-2.0-OpenSSH_9.2p1 Debian-2", ("ssh", "OpenSSH 9.2p1 (protocol 2.0)")),
    (2222, "SSH-2.0-dropbear_2022.83", ("ssh", "dropbear_2022.83 (protocol 2.0)")),
    (80, "HTTP/1.1 200 OK\r\nServer: nginx/1.25", ("http", "nginx/1.25")),
    (21, "220 ProFTPD Server (FTP) ready", ("ftp", "")),
    (6000, "", ("unknown", "")),
    (443, "", ("https", "")),
])
def test_identify_service(port, banner, expected):
    assert sc.identify_service(port, banner) == expected


# --- live probing against local listeners ----------------------------------
def test_open_port_with_banner(ssh_listener):
    result = sc.probe_port("127.0.0.1", ssh_listener)
    assert result.state == sc.OPEN
    assert result.service == "ssh" and "OpenSSH" in result.version


def test_silent_open_port_is_still_open(silent_listener):
    result = sc.probe_port("127.0.0.1", silent_listener, timeout=1.0)
    assert result.state == sc.OPEN and result.banner == ""


def test_closed_port(closed_port):
    # Windows reports a refusal only after ~2 s, so give it room.
    assert sc.probe_port("127.0.0.1", closed_port, timeout=4.0).state == sc.CLOSED


def test_scan_ports_sorted_and_progress(ssh_listener, closed_port):
    ports = [ssh_listener, closed_port]
    ticks = []
    results = sc.scan_ports("127.0.0.1", ports, timeout=4.0,
                            progress=lambda done, total: ticks.append((done, total)))
    assert [r.port for r in results] == sorted(ports)
    assert ticks[-1] == (2, 2)
    assert {r.state for r in results} == {sc.OPEN, sc.CLOSED}


def test_host_discovery_finds_localhost():
    assert sc.discover_hosts("127.0.0.1/32") == ["127.0.0.1"]


def test_unreachable_documentation_address_is_filtered():
    # 192.0.2.1 is reserved (RFC 5737): nothing answers, so the probe times out.
    assert sc.probe_port("192.0.2.1", 80, timeout=0.5).state == sc.FILTERED
