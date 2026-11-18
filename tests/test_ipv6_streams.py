import struct

import pytest

from netshield import sniffing as sn
from tests.packets import dns_query, icmpv6, ipv4, ipv6, tcp, udp


# --- IPv6 ---------------------------------------------------------------
def test_ipv6_tcp_decoded_and_summary_brackets_addresses():
    p = sn.parse_packet(ipv6(6, tcp(51000, 443, 0x02)))
    assert (p.version, p.protocol, p.dst_port, p.flags) == (6, "TCP", 443, "SYN")
    assert p.src == "2001:db8::1" and p.length == 40 + 20
    assert "[2001:db8::1]:51000 -> [2001:db8::2]:443" in p.summary()


def test_ipv6_udp_dns_and_icmpv6():
    dns = sn.parse_packet(ipv6(17, udp(5000, 53, dns_query("example.org"))))
    assert dns.info == "DNS query A example.org"
    assert sn.parse_packet(ipv6(58, icmpv6(128))).info == "echo-request"
    ns = sn.parse_packet(ipv6(58, icmpv6(135), src="fe80::1", dst="ff02::1:ff00:2"))
    assert (ns.protocol, ns.info) == ("ICMPv6", "neighbor-solicit")


def test_ipv6_extension_headers_are_skipped():
    hop_by_hop = bytes([6, 0]) + b"\x00" * 6                 # next=TCP, length 8 bytes
    p = sn.parse_packet(ipv6(0, hop_by_hop + tcp(1, 80, 0x10)))
    assert p.protocol == "TCP" and p.dst_port == 80
    fragment_first = bytes([6, 0, 0, 1]) + b"\x00" * 4         # offset 0, more-fragments
    assert sn.parse_packet(ipv6(44, fragment_first + tcp(1, 80, 0x10))).protocol == "TCP"


def test_ipv6_non_first_fragment_is_not_decoded_further():
    fragment_later = bytes([6, 0]) + struct.pack("!H", 8 << 3) + b"\x00" * 4   # offset 8
    p = sn.parse_packet(ipv6(44, fragment_later + b"data"))
    assert p.protocol == "IP/44" and p.payload == b""


@pytest.mark.parametrize("data", [b"\x60" + b"\x00" * 10, b"",
                                  ipv6(0, b"\x06")])        # truncated extension header
def test_malformed_ipv6_raises_value_error(data):
    with pytest.raises(ValueError):
        sn.parse_packet(data)


@pytest.mark.parametrize("expression, expected", [
    ("ip6", True), ("ip", False), ("ipv6 and tcp", True), ("icmp6", False),
    ("host 2001:db8::1", True), ("host 2001:0db8:0:0:0:0:0:1", True),   # normalised
    ("src host 2001:db8::2", False), ("tcp and port 443", True),
])
def test_filters_on_ipv6(expression, expected):
    packet = sn.parse_packet(ipv6(6, tcp(51000, 443, 0x02)))
    assert sn.compile_filter(expression)(packet) is expected


def test_ip_keyword_and_icmp6_filter():
    assert sn.compile_filter("ip")(sn.parse_packet(ipv4(6, tcp(1, 2, 0x10))))
    assert sn.compile_filter("icmp6")(sn.parse_packet(ipv6(58, icmpv6(128))))


def test_bad_ip_in_filter():
    with pytest.raises(sn.FilterError):
        sn.compile_filter("host 2001:::1")


def test_ipv6_pcap_round_trip_and_ethernet(tmp_path):
    packet = sn.parse_packet(ipv6(6, tcp(1, 80, 0x02)), timestamp=5.0)
    path = tmp_path / "v6.pcap"
    with sn.PcapWriter(path) as writer:
        writer.write(packet)
    assert [p.summary() for p in sn.read_pcap(path)] == [packet.summary()]

    frame = b"\xaa" * 6 + b"\xbb" * 6 + b"\x86\xdd" + ipv6(6, tcp(1, 80, 0x02))
    eth = tmp_path / "eth6.pcap"
    with open(eth, "wb") as file:
        file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        file.write(struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)
    assert next(sn.read_pcap(eth)).version == 6


# --- TCP streams ----------------------------------------------------------
CLIENT, SERVER = ("10.0.0.5", 51000), ("93.184.216.34", 80)


def seg(src, dst, flags, data=b"", seq=0, ts=0.0, ident=1):
    return sn.parse_packet(ipv4(6, tcp(src[1], dst[1], flags, data, seq), src=src[0], dst=dst[0],
                                ident=ident), timestamp=ts)


def http_conversation():
    request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    return [
        seg(CLIENT, SERVER, 0x02, seq=1000, ts=1.0),
        seg(SERVER, CLIENT, 0x12, seq=5000, ts=1.1),
        seg(CLIENT, SERVER, 0x10, seq=1001, ts=1.2),
        seg(CLIENT, SERVER, 0x18, request, seq=1001, ts=1.3),
        seg(SERVER, CLIENT, 0x18, b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n", seq=5001, ts=1.4),
        seg(SERVER, CLIENT, 0x18, b"hello world", seq=5001 + 39, ts=1.5),
        seg(CLIENT, SERVER, 0x11, seq=1001 + len(request), ts=1.6),
    ]


def test_streams_group_and_identify_endpoints():
    streams = sn.tcp_streams(http_conversation())
    assert len(streams) == 1
    stream = streams[0]
    assert stream.client == CLIENT and stream.server == SERVER
    assert stream.guess_protocol() == "http"
    assert "10.0.0.5:51000 <-> 93.184.216.34:80" == stream.label()
    counts = stream.byte_counts()
    assert counts["client"] == len(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert counts["server"] == 39 + 11


def test_follow_stream_renders_both_directions():
    text = sn.tcp_streams(http_conversation())[0].render()
    assert "--- client -> server" in text and "--- server -> client" in text
    assert "GET /index.html HTTP/1.1" in text
    assert "HTTP/1.1 200 OK" in text and "hello world" in text
    assert text.index("GET /index") < text.index("HTTP/1.1 200")


def test_retransmissions_are_dropped():
    packets = http_conversation()
    packets.append(seg(SERVER, CLIENT, 0x18, b"hello world", seq=5001 + 39, ts=2.0, ident=9))  # retransmit
    text = sn.tcp_streams(packets)[0].render()
    assert text.count("hello world") == 1


def test_out_of_order_segments_are_reordered():
    # The *later* bytes ("hello world", seq 5040) ARRIVE FIRST (ts 1.4); the earlier
    # bytes (headers, seq 5001) arrive second (ts 1.5). Output must follow seq, not arrival.
    request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    packets = [
        seg(CLIENT, SERVER, 0x02, seq=1000, ts=1.0),
        seg(SERVER, CLIENT, 0x12, seq=5000, ts=1.1),
        seg(CLIENT, SERVER, 0x18, request, seq=1001, ts=1.3),
        seg(SERVER, CLIENT, 0x18, b"hello world", seq=5001 + 39, ts=1.4),
        seg(SERVER, CLIENT, 0x18, b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n", seq=5001, ts=1.5),
    ]
    stream = sn.tcp_streams(packets)[0]
    server_data = b"".join(c.data for c in stream.chunks() if c.direction == "server")
    assert server_data == b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world"
    text = stream.render()
    assert text.index("HTTP/1.1 200 OK") < text.index("hello world")


def test_capture_gap_is_reported():
    packets = http_conversation()
    del packets[4]                                              # lose the first 39 server bytes
    chunks = sn.tcp_streams(packets)[0].chunks()
    gaps = [c for c in chunks if c.missing]
    assert gaps and gaps[0].missing == 39
    assert "39 byte(s) missing" in sn.tcp_streams(packets)[0].render()


def test_overlapping_retransmission_keeps_only_new_bytes():
    packets = [
        seg(CLIENT, SERVER, 0x02, seq=1000, ts=1.0),
        seg(CLIENT, SERVER, 0x18, b"abcdef", seq=1001, ts=1.1),
        seg(CLIENT, SERVER, 0x18, b"defghi", seq=1004, ts=1.2),    # overlaps "def"
    ]
    chunks = sn.tcp_streams(packets)[0].chunks()
    assert b"".join(c.data for c in chunks) == b"abcdefghi"


def test_sequence_numbers_wrapping_around_32_bits():
    top = 0xFFFFFFFE
    packets = [
        seg(CLIENT, SERVER, 0x02, seq=top - 1, ts=1.0),
        seg(CLIENT, SERVER, 0x18, b"abcd", seq=top, ts=1.1),       # covers top..top+3, wraps
        seg(CLIENT, SERVER, 0x18, b"efgh", seq=(top + 4) & 0xFFFFFFFF, ts=1.2),
    ]
    assert b"".join(c.data for c in sn.tcp_streams(packets)[0].chunks()) == b"abcdefgh"


def test_separate_streams_and_non_tcp_ignored():
    other = ("10.0.0.5", 52000)
    packets = http_conversation() + [
        seg(other, SERVER, 0x02, seq=1, ts=3.0),
        sn.parse_packet(ipv4(17, udp(1, 2, b"x")), timestamp=3.1),
    ]
    streams = sn.tcp_streams(packets)
    assert len(streams) == 2 and streams[1].client == other


def test_non_printable_bytes_rendered_as_dots_and_empty_stream():
    packets = [seg(CLIENT, SERVER, 0x02, seq=1, ts=1.0),
               seg(CLIENT, SERVER, 0x18, b"hi\x00\x01\xffthere\r\n", seq=2, ts=1.1)]
    assert "hi...there" in sn.tcp_streams(packets)[0].render()
    handshake_only = sn.tcp_streams([seg(CLIENT, SERVER, 0x02, seq=1, ts=1.0)])[0]
    assert "no payload" in handshake_only.render()


def test_render_truncates_huge_streams():
    packets = [seg(CLIENT, SERVER, 0x02, seq=1, ts=1.0),
               seg(CLIENT, SERVER, 0x18, b"A" * 5000, seq=2, ts=1.1)]
    assert "truncated" in sn.tcp_streams(packets)[0].render(limit=1000)
