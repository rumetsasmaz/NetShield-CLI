import json
import socket
import threading

import pytest

from netshield import cli, sniffing as sn
from tests.packets import dns_query, ipv4, tcp, udp


@pytest.fixture
def banner_server():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.sendall(b"SSH-2.0-OpenSSH_9.2p1\r\n")
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield server.getsockname()[1]
    server.close()


def test_no_command_is_a_usage_error():
    with pytest.raises(SystemExit) as exit_info:
        cli.run([])
    assert exit_info.value.code == 2


def test_scan_json_to_file(banner_server, tmp_path):
    out = tmp_path / "report.json"
    code = cli.run(["scan", "127.0.0.1", "-p", str(banner_server), "--format", "json", "-o", str(out)])
    assert code == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["results"][0]["service"] == "ssh"


def test_scan_table_and_csv(banner_server, capsys):
    assert cli.run(["scan", "127.0.0.1", "-p", str(banner_server)]) == 0
    assert "open" in capsys.readouterr().out
    assert cli.run(["scan", "127.0.0.1", "-p", str(banner_server), "--format", "csv"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == "port,state,service,version,banner,risk"


def test_scan_bad_ports_returns_1():
    assert cli.run(["scan", "127.0.0.1", "-p", "abc"]) == 1


def test_remote_scan_refused_without_authorization(monkeypatch):
    def no_input(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", no_input)
    assert cli.run(["scan", "192.0.2.1", "-p", "80"]) == 1


def test_analyze_pcap_with_filter_and_stats(tmp_path, capsys):
    path = tmp_path / "c.pcap"
    with sn.PcapWriter(path) as writer:
        writer.write(sn.parse_packet(ipv4(6, tcp(5000, 80, 0x02)), timestamp=1.0))
        writer.write(sn.parse_packet(ipv4(17, udp(5000, 53, dns_query("example.com"))), timestamp=2.0))
    assert cli.run(["analyze", str(path), "-f", "dns"]) == 0
    out = capsys.readouterr().out
    assert "DNS query A example.com" in out and "1 packet(s) matched" in out
    assert cli.run(["analyze", str(path), "--stats"]) == 0
    assert "Packets: 2" in capsys.readouterr().out


def test_analyze_errors(tmp_path):
    assert cli.run(["analyze", str(tmp_path / "missing.pcap")]) == 1
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\x00" * 40)
    assert cli.run(["analyze", str(bad)]) == 1
    assert cli.run(["analyze", str(bad), "-f", "tcp and"]) == 1


def test_small_commands(capsys):
    assert cli.run(["ports", "rdp"]) == 0 and "3389" in capsys.readouterr().out
    assert cli.run(["ports", "zzz"]) == 1
    assert cli.run(["hash", "hello"]) == 0
    assert "5d41402abc4b2a76b9719d911017c592" in capsys.readouterr().out
    assert cli.run(["passwd", "--check", "Abcdefg1!"]) == 0
    assert "5/5" in capsys.readouterr().out
    assert cli.run(["passwd", "--generate", "24"]) == 0
    assert len(capsys.readouterr().out.strip()) == 24
