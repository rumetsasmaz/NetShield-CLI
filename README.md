# 🛡️ NetShield-CLI

A modular, Python-based cybersecurity command-line toolkit for learning, experimentation and basic security analysis. Standard library plus `colorama` only.

> ⚠️ **Educational project.** Use it only on systems, networks, accounts and data you own or have explicit written permission to test.
>
> 🤖 **Development note:** this repository is developed with AI assistance (Claude Code).

## ✨ Tools

| Tool | What it does |
|---|---|
| **Port & Service Scanner** | Threaded **TCP and UDP** scan. TCP: `open` / `closed` / `filtered`, banners (passive first, then an HTTP probe), service/version detection, automatic TLS inspection on TLS ports. UDP: real DNS, NTP and SNMP probes; `open` / `closed` (ICMP unreachable) / `open\|filtered`. Port specs: `22,80`, `1-1000`, `top`, `all`. JSON/CSV reports. |
| **TLS Certificate Check** | Protocol, cipher, subject/issuer, validity, SANs, trust verdict, SHA-256 fingerprint, and findings (expired, expiring < 30 days, self-signed, untrusted, outdated protocol). |
| **Host Discovery** | TCP ping of a network (CIDR, max `/24`). |
| **Packet Sniffer** | Wireshark-style live capture and decoding of IPv4 TCP/UDP/ICMP (DNS queries/answers included). tcpdump-like filters (`tcp and (port 80 or port 443) and not host 10.0.0.1`), duplicate-packet removal, `.pcap` export. Needs Administrator/root. |
| **Capture Analyzer** | Reads classic `.pcap` files (including Wireshark captures) with no special privileges: filter, statistics, **IPv4 and IPv6**, TCP stream list and **Follow TCP Stream** (reordering, retransmission removal, gap detection). |
| **Port Database** | Look up a port number or service name, with risk notes. |
| **Password Checker / Generator** | Strength scoring with hints; `secrets`-based generator. |
| **Hash Text / Hash Cracker** | MD5, SHA-1, SHA-256, SHA-512; dictionary attack with automatic algorithm detection. |
| **Themes** | `default`, `matrix`, `hacker`, `ocean`, `mono` (saved in `~/.netshield/config.json`). |

## 📦 Install & run

```bash
git clone https://github.com/rumetsasmaz/NetShield-CLI.git
cd NetShield-CLI
pip install -r requirements.txt
python main.py
```

## 💻 Command line

`python main.py` opens the interactive menu; with arguments it behaves like a normal CLI:

```bash
python main.py scan 127.0.0.1 -p 1-1000 --format json -o report.json
python main.py scan scanme.example -p top --yes        # --yes = I am authorised to scan this target
python main.py scan 127.0.0.1 --udp                   # DNS/NTP/SNMP probes, UDP top ports
python main.py tls example.com                          # or host:port
python main.py discover 192.168.1.0/24
python main.py sniff -f "tcp and port 80" -c 50 -w capture.pcap   # needs Administrator/root
python main.py analyze capture.pcap -f dns                         # no privileges needed
python main.py analyze capture.pcap --stats
python main.py analyze capture.pcap --streams           # list TCP streams
python main.py analyze capture.pcap --follow 0          # reassembled data of stream 0
python main.py analyze capture.pcap -f "ip6 and icmp6"
python main.py ports ssh | hash "text" | passwd --generate 20
```

Exit codes: `0` success, `1` error or refused, `2` bad usage.

## 🧪 Tests

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Tests use hand-built packets and local listeners only; nothing touches the internet.

## 🧱 Architecture

```
main.py                  no args -> menu, args -> CLI
netshield/
  cli.py / menu.py       argparse commands / interactive menu
  base.py                BaseModule (name, description, run)
  theme.py / config.py   colours, safe output, settings
  scanning.py            scan core (returns data, never prints)
  sniffing.py            parsers, DNS, filters, stats, pcap I/O, raw-socket capture
  modules/               one BaseModule subclass per tool
tests/                   pytest suite
```

Adding a tool = write a `BaseModule` subclass in `netshield/modules/` and list it in `netshield/modules/__init__.py`.

## 📝 Notes & limits

* On Windows a refused connection is reported after ~2 s, so the default timeout is 2.5 s there. Below ~2 s, `closed` and `filtered` cannot be told apart.
* The scanner uses plain TCP connects and ordinary UDP datagrams (no raw SYN scan, no OS fingerprinting).
* UDP: silence is reported as `open|filtered`, never as open. Unknown UDP ports get a single zero byte as probe, so only services that answer it are detected.
* TLS certificate details come from Python's private `ssl._ssl._test_decode_cert`; if a future Python removes it, protocol/cipher/fingerprint/trust are still reported.
* IPv6 is decoded from pcap files and on Linux live capture. **Live IPv6 capture on Windows is not supported.** On Windows the sniffer sees IPv4 only, on one interface, and needs an elevated terminal.
* Follow Stream shows captured data only (no TLS decryption); loss at the end of a stream cannot be detected.
* Linux live capture (`AF_PACKET`) is implemented but **untested**: the project has only been run on Windows.
* `tests/data/*.key` are throwaway private keys for local TLS test servers; they protect nothing.
* Service detection concepts (port states, passive banner wait before probing) follow nmap's public documentation; the code and signatures are original.

## 🗺️ Roadmap

- [x] Modular architecture, themes, threaded scanner, packet sniffer
- [x] `argparse` commands, pcap export/import, DNS decoding, capture filters, statistics, tests
- [x] UDP scan (DNS, NTP, SNMP), TLS certificate inspection, IPv6 decoding, Follow TCP Stream
- [ ] More service probes and signatures (UDP: SSDP, mDNS, NetBIOS)
- [ ] Live IPv6 capture on Windows (needs Npcap), `.pcapng`, HTTP request/response view
- [ ] Logging, more security utilities (HTTP header audit, DNS and WHOIS tools)

## 🔒 Ethical use

For personal labs, CTFs, local testing and systems you are authorised to assess. Never use it for unauthorised access. The author is not responsible for misuse.

## 👨‍💻 Author

**Rumet Şaşmaz**: https://github.com/rumetsasmaz
