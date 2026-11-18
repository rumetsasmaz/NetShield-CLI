import struct

import pytest

from netshield import sniffing as sn
from tests.packets import dns_query, dns_response, icmp_echo, ipv4, ipv6, tcp, udp


def http_get():
    return ipv4(6, tcp(51000, 80, 0x18, b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"))


# --- decoding -----------------------------------------------------------
def test_tcp_packet_decoded():
    p = sn.parse_packet(http_get())
    assert (p.protocol, p.src_port, p.dst_port, p.flags) == ("TCP", 51000, 80, "PSH|ACK")
    assert p.info.startswith("GET /index.html")
    assert p.seq == 100 and p.ident == 1


def test_syn_flag():
    assert sn.parse_packet(ipv4(6, tcp(1, 443, 0x02))).flags == "SYN"


def test_udp_icmp_and_unknown_protocol():
    assert sn.parse_packet(ipv4(17, udp(5000, 6000, b"x"))).protocol == "UDP"
    assert sn.parse_packet(ipv4(1, icmp_echo())).info == "echo-request"
    assert sn.parse_packet(ipv4(47, b"xx")).protocol == "IP/47"


@pytest.mark.parametrize("data", [b"", b"\x45" * 10, b"\x60" + b"\x00" * 30,
                                  ipv4(6, b"\x00" * 5)])
def test_malformed_packets_raise_value_error(data):
    with pytest.raises(ValueError):
        sn.parse_packet(data)


# --- DNS ----------------------------------------------------------------
def test_dns_query_summary():
    p = sn.parse_packet(ipv4(17, udp(50000, 53, dns_query("example.com"))))
    assert p.info == "DNS query A example.com"


def test_dns_response_with_compression_pointer():
    message = sn.decode_dns(dns_response("example.com", "93.184.216.34"))
    assert message["response"] is True
    assert message["answers"] == [("example.com", "A", "93.184.216.34")]
    p = sn.parse_packet(ipv4(17, udp(53, 50000, dns_response("example.com", "1.2.3.4"))))
    assert p.info == "DNS response example.com -> 1.2.3.4"


def test_dns_compression_loop_is_rejected():
    # header + a name whose pointer points at itself
    evil = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    with pytest.raises(ValueError):
        sn.decode_dns(evil)


def test_garbage_dns_does_not_crash_packet_parser():
    p = sn.parse_packet(ipv4(17, udp(50000, 53, b"\x00\x01")))
    assert p.info == "DNS?"


# --- filters ------------------------------------------------------------
@pytest.mark.parametrize("expression, expected", [
    ("", True),
    ("tcp", True),
    ("udp", False),
    ("port 80", True),
    ("dst port 80", True),
    ("src port 80", False),
    ("host 10.0.0.5", True),
    ("src host 93.184.216.34", False),
    ("tcp and port 80", True),
    ("tcp and not port 80", False),
    ("udp or port 443 or port 80", True),
    ("not (udp or icmp)", True),
    ("(tcp and port 22) or (tcp and port 80)", True),
])
def test_filter_expressions(expression, expected):
    assert sn.compile_filter(expression)(sn.parse_packet(http_get())) is expected


def test_dns_filter_keyword():
    dns = sn.parse_packet(ipv4(17, udp(50000, 53, dns_query("a.b"))))
    assert sn.compile_filter("dns")(dns)
    assert not sn.compile_filter("dns")(sn.parse_packet(http_get()))


@pytest.mark.parametrize("expression", ["tcp and", "port", "port 99999", "host banana",
                                        "(tcp", "tcp udp", "frobnicate", "src"])
def test_bad_filters_raise_filter_error(expression):
    with pytest.raises(sn.FilterError):
        sn.compile_filter(expression)


# --- stats --------------------------------------------------------------
def test_stats_report():
    stats = sn.CaptureStats()
    stats.add(sn.parse_packet(http_get(), timestamp=10.0))
    stats.add(sn.parse_packet(ipv4(17, udp(5, 6, b"x")), timestamp=12.0))
    stats.add(sn.parse_packet(http_get(), timestamp=11.0))
    assert stats.packets == 3
    assert stats.protocols["TCP"] == 2
    report = stats.report()
    assert "Packets: 3" in report and "Duration: 2.00s" in report and "TCP" in report


# --- dedupe -------------------------------------------------------------
def test_deduplicator():
    dedupe = sn.Deduplicator(window=0.05)
    assert not dedupe.is_duplicate(sn.parse_packet(http_get(), timestamp=1.000))
    assert dedupe.is_duplicate(sn.parse_packet(http_get(), timestamp=1.010))   # same packet again
    retransmit = sn.parse_packet(
        ipv4(6, tcp(51000, 80, 0x18, b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"), ident=2),
        timestamp=1.020)
    assert not dedupe.is_duplicate(retransmit)                                  # new IP id
    assert not dedupe.is_duplicate(sn.parse_packet(http_get(), timestamp=2.0))  # outside window


def test_deduplicator_keeps_distinct_packets_that_share_ident_zero():
    dedupe = sn.Deduplicator()
    ack_1 = sn.parse_packet(ipv4(6, tcp(1, 2, 0x10, seq=500, ack=1000), ident=0), timestamp=1.0000)
    ack_2 = sn.parse_packet(ipv4(6, tcp(1, 2, 0x10, seq=500, ack=2460), ident=0), timestamp=1.0001)
    assert not dedupe.is_duplicate(ack_1)
    assert not dedupe.is_duplicate(ack_2)                       # differs only in the ack number
    assert dedupe.is_duplicate(sn.parse_packet(ipv4(6, tcp(1, 2, 0x10, seq=500, ack=2460), ident=0),
                                               timestamp=1.0002))   # a true duplicate is still dropped
    # same-sized datagrams (QUIC-like), and every IPv6 packet has id 0
    d1 = sn.parse_packet(ipv6(17, udp(5000, 443, b"A" * 40)), timestamp=2.0000)
    d2 = sn.parse_packet(ipv6(17, udp(5000, 443, b"B" * 40)), timestamp=2.0001)
    assert not dedupe.is_duplicate(d1) and not dedupe.is_duplicate(d2)


def test_deduplicator_uses_tight_window_for_ident_zero():
    dedupe = sn.Deduplicator(window=0.05, zero_id_window=0.005)
    syn = ipv4(6, tcp(1, 2, 0x02), ident=0)
    assert not dedupe.is_duplicate(sn.parse_packet(syn, timestamp=1.0000))
    assert dedupe.is_duplicate(sn.parse_packet(syn, timestamp=1.0002))     # same SYN, microseconds apart
    assert not dedupe.is_duplicate(sn.parse_packet(syn, timestamp=2.0))    # SYN retransmit ~1 s later is kept
    assert not dedupe.is_duplicate(sn.parse_packet(syn, timestamp=2.020))  # beyond the tight window


# --- pcap ---------------------------------------------------------------
def test_pcap_round_trip(tmp_path):
    path = tmp_path / "out.pcap"
    originals = [sn.parse_packet(http_get(), timestamp=1700000000.25),
                 sn.parse_packet(ipv4(17, udp(1, 53, dns_query("x.org"))), timestamp=1700000001.5)]
    with sn.PcapWriter(path) as writer:
        for packet in originals:
            writer.write(packet)
    loaded = list(sn.read_pcap(path))
    assert [p.summary() for p in loaded] == [p.summary() for p in originals]
    assert loaded[0].timestamp == pytest.approx(1700000000.25, abs=1e-5)


def test_reads_ethernet_pcap_and_skips_non_ipv4(tmp_path):
    eth_ipv4 = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + http_get()
    eth_arp = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x06" + b"\x00" * 28
    path = tmp_path / "eth.pcap"
    with open(path, "wb") as file:
        file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for frame in (eth_ipv4, eth_arp):
            file.write(struct.pack("<IIII", 5, 0, len(frame), len(frame)) + frame)
    packets = list(sn.read_pcap(path))
    assert len(packets) == 1 and packets[0].dst_port == 80


@pytest.mark.parametrize("name, content, fragment", [
    ("short.pcap", b"abc", "too short"),
    ("junk.pcap", b"\x00" * 40, "not a pcap"),
    ("ng.pcap", b"\x0a\x0d\x0d\x0a" + b"\x00" * 40, "pcapng"),
])
def test_read_pcap_rejects_bad_files(tmp_path, name, content, fragment):
    path = tmp_path / name
    path.write_bytes(content)
    with pytest.raises(ValueError, match=fragment):
        list(sn.read_pcap(path))


def test_truncated_final_record_is_ignored(tmp_path):
    path = tmp_path / "cut.pcap"
    packet = sn.parse_packet(http_get(), timestamp=1.0)
    with sn.PcapWriter(path) as writer:
        writer.write(packet)
        writer.write(packet)
    path.write_bytes(path.read_bytes()[:-10])
    assert len(list(sn.read_pcap(path))) == 1
