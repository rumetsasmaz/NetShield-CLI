import pytest

from netshield import scanning as sc


# --- TLS ----------------------------------------------------------------
def test_tls_info_self_signed_certificate(tls_server):
    port = tls_server("localhost")
    info = sc.tls_info("127.0.0.1", port, timeout=3, server_name="localhost")
    assert info["version"] in ("TLSv1.2", "TLSv1.3")
    assert info["subject"] == "localhost" and info["issuer"] == "localhost"
    assert info["self_signed"] is True and info["trusted"] is False
    assert {"localhost", "test.local", "127.0.0.1"} <= set(info["san"])
    assert info["days_left"] > 36000
    assert "self-signed certificate" in info["findings"]
    assert len(info["fingerprint_sha256"]) == 64


def test_tls_info_flags_expired_certificate(tls_server):
    port = tls_server("expired")
    info = sc.tls_info("127.0.0.1", port, timeout=3, server_name="expired.test")
    assert info["days_left"] < 0
    assert any("expired" in finding for finding in info["findings"])
    assert "EXPIRED" in sc.tls_summary(info)


def test_tls_info_connection_refused(closed_udp_port):
    with pytest.raises(OSError):
        sc.tls_info("127.0.0.1", closed_udp_port, timeout=3)


def test_tls_summary_empty():
    assert sc.tls_summary(None) == ""


def test_scan_attaches_tls_info_on_tls_ports(tls_server, monkeypatch):
    port = tls_server("localhost")
    monkeypatch.setattr(sc, "_TLS_PORTS", sc._TLS_PORTS | {port})
    result = sc.probe_port("127.0.0.1", port, timeout=3)
    assert result.state == sc.OPEN
    assert result.tls and result.tls["subject"] == "localhost"
    assert result.to_dict()["tls"]["self_signed"] is True


def test_scan_passes_hostname_to_tls_inspection(tls_server, monkeypatch):
    """SNI / trust checks must use the name the user typed, not the resolved IP."""
    port = tls_server("localhost")
    monkeypatch.setattr(sc, "_TLS_PORTS", sc._TLS_PORTS | {port})
    seen = []
    real = sc.tls_info
    monkeypatch.setattr(sc, "tls_info", lambda *a, **k: seen.append(k.get("server_name")) or real(*a, **k))
    sc.scan_ports("127.0.0.1", [port], timeout=3, server_name="myhost.test")
    sc.scan_ports("127.0.0.1", [port], timeout=3)                   # target was an IP
    assert seen == ["myhost.test", None]


def test_hostname_is_used_for_host_header():
    import socket
    import threading
    received = []
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        received.append(conn.recv(1024))
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    sc.probe_port("127.0.0.1", server.getsockname()[1], timeout=2, server_name="virtual.test")
    server.close()
    assert b"Host: virtual.test" in received[0]


def test_hostname_or_none():
    assert sc.hostname_or_none("example.com") == "example.com"
    assert sc.hostname_or_none("127.0.0.1") is None
    assert sc.hostname_or_none("::1") is None


# --- UDP ----------------------------------------------------------------
def test_udp_top_ports():
    assert sc.parse_ports("top", "udp") == sorted(sc.UDP_TOP_PORTS)
    assert sc.parse_ports("top", "tcp") != sc.parse_ports("top", "udp")


def test_udp_probes_are_well_formed():
    assert len(sc._UDP_PROBES[123]) == 48
    assert sc._UDP_PROBES[161][0] == 0x30 and b"public" in sc._UDP_PROBES[161]
    assert sc._UDP_PROBES[161][1] == len(sc._UDP_PROBES[161]) - 2     # BER length is correct
    from netshield import sniffing
    assert sniffing.decode_dns(sc._UDP_PROBES[53])["questions"] == [("", "NS")]


def test_identify_udp_replies():
    dns_reply = sc._UDP_PROBES[53][:2] + b"\x81\x80" + sc._UDP_PROBES[53][4:]
    assert sc.identify_udp(53, dns_reply) == ("dns", "")
    assert sc.identify_udp(123, b"\x24\x02" + b"\x00" * 46) == ("ntp", "NTPv4 stratum 2")
    descr = b"Linux testbox 6.1"
    snmp = sc._tlv(0x30, sc._tlv(2, b"\x00") + sc._tlv(4, b"public") + sc._tlv(0xA2, sc._tlv(0x30, sc._tlv(
        0x30, sc._tlv(6, sc._SNMP_SYSDESCR_OID) + sc._tlv(4, descr)))))
    assert sc.identify_udp(161, snmp) == ("snmp", "Linux testbox 6.1")
    assert sc.identify_udp(9999, b"x") == ("unknown", "")


def test_udp_open_when_server_replies(udp_server):
    port = udp_server(lambda data: b"pong")
    result = sc.probe_udp_port("127.0.0.1", port, timeout=1.0)
    assert (result.state, result.protocol, result.banner) == (sc.OPEN, "udp", "pong")


def test_udp_open_filtered_when_silent(udp_server):
    port = udp_server(lambda data: None)
    assert sc.probe_udp_port("127.0.0.1", port, timeout=0.5).state == sc.OPEN_FILTERED


def test_udp_closed_when_icmp_unreachable(closed_udp_port):
    # The OS reports the ICMP "port unreachable" as ECONNREFUSED / WSAECONNRESET.
    assert sc.probe_udp_port("127.0.0.1", closed_udp_port, timeout=1.0).state == sc.CLOSED


def test_udp_scan_ports_mixed(udp_server, closed_udp_port):
    echo = udp_server(lambda data: data)
    silent = udp_server(lambda data: None)
    results = sc.scan_ports("127.0.0.1", [echo, silent, closed_udp_port], timeout=0.5, protocol="udp")
    states = {r.port: r.state for r in results}
    assert states[echo] == sc.OPEN
    assert states[silent] == sc.OPEN_FILTERED
    assert states[closed_udp_port] == sc.CLOSED
    assert all(r.protocol == "udp" for r in results)
    assert [r.port for r in results] == sorted(states)
