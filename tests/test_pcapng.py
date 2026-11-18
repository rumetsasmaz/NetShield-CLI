"""pcapng files are built here byte by byte following the pcapng specification."""
import struct

import pytest

from netshield import cli, sniffing as sn
from tests.packets import ipv4, ipv6, tcp, udp
from tests.test_ipv6_streams import http_conversation


def block(block_type, body, endian="<"):
    body += b"\x00" * (-len(body) % 4)
    total = 12 + len(body)
    return struct.pack(endian + "II", block_type, total) + body + struct.pack(endian + "I", total)


def shb(endian="<"):
    body = struct.pack(endian + "I", 0x1A2B3C4D) + struct.pack(endian + "HHq", 1, 0, -1)
    return block(0x0A0D0D0A, body, endian)


def idb(linktype, tsresol=None, endian="<"):
    body = struct.pack(endian + "HHI", linktype, 0, 65535)
    if tsresol is not None:
        body += struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) + b"\x00\x00\x00"
        body += struct.pack(endian + "HH", 0, 0)
    return block(1, body, endian)


def epb(interface, units, data, endian="<"):
    body = struct.pack(endian + "IIIII", interface, units >> 32, units & 0xFFFFFFFF, len(data), len(data))
    return block(6, body + data, endian)


def spb(data, endian="<"):
    return block(3, struct.pack(endian + "I", len(data)) + data, endian)


def ethernet(payload, ethertype=b"\x08\x00", vlan=False):
    header = b"\xaa" * 6 + b"\xbb" * 6
    if vlan:
        header += b"\x81\x00\x00\x07"
    return header + ethertype + payload


def write(tmp_path, *parts):
    path = tmp_path / "cap.pcapng"
    path.write_bytes(b"".join(parts))
    return path


GET = ipv4(6, tcp(51000, 80, 0x18, b"GET / HTTP/1.1\r\n\r\n"))


def test_little_endian_ethernet_microseconds(tmp_path):
    path = write(tmp_path, shb(), idb(1), epb(0, 1_700_000_000_250_000, ethernet(GET)))
    [packet] = list(sn.read_pcap(path))
    assert packet.dst_port == 80 and packet.info.startswith("GET /")
    assert packet.timestamp == pytest.approx(1_700_000_000.25)


def test_big_endian_raw_ip_nanoseconds(tmp_path):
    path = write(tmp_path, shb(">"), idb(101, tsresol=9, endian=">"),
                 epb(0, 1_700_000_000_123_456_789, GET, ">"))
    [packet] = list(sn.read_pcap(path))
    assert packet.timestamp == pytest.approx(1_700_000_000.123456789)


def test_power_of_two_resolution(tmp_path):
    path = write(tmp_path, shb(), idb(101, tsresol=0x80 | 10), epb(0, 1024 * 5, GET))   # units of 2^-10 s
    assert next(sn.read_pcap(path)).timestamp == pytest.approx(5.0)


def test_several_interfaces_and_sections(tmp_path):
    path = write(tmp_path,
                 shb(), idb(1), idb(101), epb(0, 1, ethernet(GET)), epb(1, 2, GET),
                 shb(">"), idb(101, endian=">"), epb(0, 3, ipv6(6, tcp(1, 443, 0x02)), ">"))
    packets = list(sn.read_pcap(path))
    assert [p.version for p in packets] == [4, 4, 6]


def test_simple_packet_block_and_ignored_blocks(tmp_path):
    name_resolution = block(4, b"\x00\x00\x00\x00")
    stats = block(5, b"\x00" * 12)
    path = write(tmp_path, shb(), idb(101), name_resolution, spb(GET), stats)
    [packet] = list(sn.read_pcap(path))
    assert packet.dst_port == 80 and packet.timestamp == 0.0


def test_vlan_ipv6_ethernet_and_non_ip_frames(tmp_path):
    arp = ethernet(b"\x00" * 28, ethertype=b"\x08\x06")
    path = write(tmp_path, shb(), idb(1),
                 epb(0, 1, ethernet(GET, vlan=True)),
                 epb(0, 2, ethernet(ipv6(17, udp(5, 53, b"x")), ethertype=b"\x86\xdd")),
                 epb(0, 3, arp))
    packets = list(sn.read_pcap(path))
    assert [p.protocol for p in packets] == ["TCP", "UDP"]


@pytest.mark.parametrize("family", [struct.pack("<I", 2), struct.pack(">I", 2),
                                    struct.pack("<I", 24), struct.pack(">I", 30)])
def test_null_loopback_link_type(tmp_path, family):
    payload = GET if family in (struct.pack("<I", 2), struct.pack(">I", 2)) else ipv6(6, tcp(1, 80, 0x02))
    path = write(tmp_path, shb(), idb(0), epb(0, 1, family + payload))
    assert len(list(sn.read_pcap(path))) == 1


def test_linux_sll2(tmp_path):
    frame = b"\x08\x00" + b"\x00" * 18 + GET
    assert next(sn.read_pcap(write(tmp_path, shb(), idb(276), epb(0, 1, frame)))).dst_port == 80


def test_unsupported_link_type_packets_are_skipped(tmp_path):
    path = write(tmp_path, shb(), idb(105), epb(0, 1, b"\x00" * 40), idb(101), epb(1, 2, GET))
    assert len(list(sn.read_pcap(path))) == 1


def test_truncated_last_block_is_ignored(tmp_path):
    data = shb() + idb(101) + epb(0, 1, GET) + epb(0, 2, GET)
    path = write(tmp_path, data[:-10])
    assert len(list(sn.read_pcap(path))) == 1


@pytest.mark.parametrize("content, message", [
    (b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + b"\x00" * 20, "byte-order"),
    (shb() + struct.pack("<II", 6, 7), "corrupt block length"),
])
def test_corrupt_files(tmp_path, content, message):
    with pytest.raises(ValueError, match=message):
        list(sn.read_pcap(write(tmp_path, content)))


def test_analyze_follow_works_on_pcapng(tmp_path, capsys):
    blocks = [shb(), idb(101)] + [epb(0, int(p.timestamp * 1_000_000), p.raw) for p in http_conversation()]
    path = write(tmp_path, *blocks)
    assert cli.run(["analyze", str(path), "--follow", "0"]) == 0
    out = capsys.readouterr().out
    assert "GET /index.html HTTP/1.1" in out and "hello world" in out


def test_drop_exact_copies():
    first = sn.parse_packet(GET, timestamp=1.000)
    copies = [sn.parse_packet(GET, timestamp=1.000 + i * 0.001) for i in range(1, 8)]   # pktmon-style
    later = sn.parse_packet(GET, timestamp=5.0)                                         # same bytes, later
    other = sn.parse_packet(ipv4(6, tcp(51000, 80, 0x10)), timestamp=1.002)
    kept, dropped = sn.drop_exact_copies([first, *copies, other, later])
    assert dropped == 7 and kept == [first, other, later]


def test_analyze_warns_about_and_removes_pktmon_copies(tmp_path, capsys):
    packets = http_conversation()
    blocks = [shb(), idb(101)]
    for packet in packets:                                   # every packet logged 8 times
        blocks += [epb(0, int(packet.timestamp * 1_000_000) + i, packet.raw) for i in range(8)]
    path = write(tmp_path, *blocks)

    assert cli.run(["analyze", str(path), "--stats"]) == 0
    out = capsys.readouterr().out
    assert "87% of the packets are exact copies" in out and f"Packets: {8 * len(packets)}" in out

    assert cli.run(["analyze", str(path), "--stats", "--dedupe"]) == 0
    out = capsys.readouterr().out
    assert f"Dropped {7 * len(packets)}" in out and f"Packets: {len(packets)}" in out and "exact copies" not in out


MAC_A, MAC_B = b"\xba\x20\xd6\xea\xcd\x33", b"\xcc\x5e\xf8\x83\x4f\x8f"
SNAP_IPV4 = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"


def wifi_frame(payload, fc0=0x08, fc1=0x01, snap=SNAP_IPV4):
    header = bytes([fc0, fc1]) + b"\x00\x80" + MAC_A + MAC_B + MAC_A + b"\x00\x00"   # 24 bytes
    if fc1 & 0x03 == 0x03:
        header += MAC_B                                       # fourth address
    if fc0 & 0x80:
        header += b"\x00\x00"                                 # QoS control
        if fc1 & 0x80:
            header += b"\x00\x00\x00\x00"                     # HT control
    return header + snap + payload


def test_wifi_payload_variants():
    assert sn.wifi_payload(wifi_frame(GET)) == GET                                  # plain data, ToDS
    assert sn.wifi_payload(wifi_frame(GET, fc0=0x88, fc1=0x02)) == GET              # QoS data, FromDS
    assert sn.wifi_payload(wifi_frame(GET, fc0=0x88, fc1=0x83)) == GET              # QoS + 4 addr + HT
    assert sn.wifi_payload(wifi_frame(GET, fc1=0x42)) == GET                        # decrypted (pktmon)
    assert sn.wifi_payload(wifi_frame(GET, snap=b"\x12" * 8)) is None               # encrypted payload
    assert sn.wifi_payload(wifi_frame(GET, fc0=0x80)) is None                       # beacon (management)
    assert sn.wifi_payload(b"\x08\x01") is None


def test_pktmon_wifi_frames_labelled_as_ethernet(tmp_path):
    """pktmon --comp nics on a Wi-Fi adapter: 802.11 frames inside an 'Ethernet' file."""
    path = write(tmp_path, shb(), idb(1), epb(0, 1, wifi_frame(GET)), epb(0, 2, ethernet(GET)))
    packets = list(sn.read_pcap(path))
    assert len(packets) == 2 and all(p.dst_port == 80 for p in packets)


def test_native_80211_link_type(tmp_path):
    path = write(tmp_path, shb(), idb(105), epb(0, 1, wifi_frame(GET)), epb(0, 2, wifi_frame(GET, fc0=0x80)))
    assert [p.dst_port for p in sn.read_pcap(path)] == [80]


def test_frame_to_ip_unknown_link_type():
    assert sn.frame_to_ip(999, b"anything") is None
