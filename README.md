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
| **HTTP Security Headers** | Grades a site A+ to F (securityheaders.com style): HTTPS redirect, HSTS, CSP (unsafe-inline/eval, wildcards, nonces), clickjacking, nosniff, Referrer-Policy, Permissions-Policy, cookie flags, version leaks. Every finding comes with a fix hint. One normal GET request, follows up to 5 redirects. |
| **Host Discovery** | TCP ping of a network (CIDR, max `/24`). |
| **Packet Sniffer** | Wireshark-style live capture and decoding of IPv4 TCP/UDP/ICMP (DNS queries/answers included). tcpdump-like filters (`tcp and (port 80 or port 443) and not host 10.0.0.1`), duplicate-packet removal, `.pcap` export. Needs Administrator/root. |
| **DNS Lookup** | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA via the system resolver (or `--server`), UDP with TCP fallback; warns if your resolver invents answers for non-existent names (NXDOMAIN hijacking). |
| **Email Security** | Spoofing protection grade: SPF (qualifier, 10-lookup limit, duplicates), DMARC (policy, pct, sp), DKIM at common selectors (incl. revoked keys), null MX, CAA. |
| **WHOIS / RDAP** | Registrar, creation/expiry dates, name servers, transfer lock, DNSSEC and registrar abuse contact. RDAP (JSON, via IANA bootstrap) first; classic WHOIS on port 43 for TLDs without RDAP (e.g. `.tr` via TRABIS). Subdomains are walked up to the registered name. |
| **Disclosure Contact** | Finds and validates `security.txt` (RFC 9116): where and how an organisation wants vulnerabilities reported. Without one, explains the responsible-disclosure route. |
| **Capture Analyzer** | Reads `.pcap` and **`.pcapng`** files (Wireshark's default; Ethernet/VLAN, raw IP, Linux SLL/SLL2, loopback) with no special privileges: filter, statistics, **IPv4 and IPv6**, TCP stream list and **Follow TCP Stream** (reordering, retransmission removal, gap detection). |
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
python main.py headers example.com                      # security header grade + fixes
python main.py dns example.com -t mx,txt
python main.py mail example.com                         # SPF / DMARC / DKIM grade
python main.py whois metu.edu.tr                        # RDAP, or WHOIS where there is no RDAP
python main.py disclosure github.com                    # where to report vulnerabilities
python main.py --color never scan 127.0.0.1             # colour: auto (default) | always | never
python main.py headers https://my.site --fail-under 70  # exit 1 below 70 (for CI)
python main.py discover 192.168.1.0/24
python main.py sniff -f "tcp and port 80" -c 50 -w capture.pcap   # needs Administrator/root
python main.py analyze capture.pcap -f dns                         # no privileges needed
python main.py analyze capture.pcap --stats
python main.py analyze capture.pcap --streams           # list TCP streams
python main.py analyze capture.pcap --follow 0          # reassembled data of stream 0
python main.py analyze capture.pcap -f "ip6 and icmp6"
python main.py analyze cap.pcapng --streams --dedupe    # pktmon / pcapng, duplicate copies removed
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
* DMARC is inherited from parent domains (walking up to two labels, without a public-suffix list). WHOIS text formats differ per registry, so the WHOIS fallback is best-effort; RDAP results are structured.
* The tools give leads, not report-ready findings: some resolvers (including the one this was developed on) tamper with answers. Re-check with `--server 1.1.1.1` and by hand before contacting anyone.
* SPF lookup counting is top-level only (nested `include:` records are not followed). DKIM can only be found at well-known selector names, so "not found" never proves it is missing.
* pcapng support was tested with files built from the specification and with a real Windows `pktmon` capture (`pktmon etl2pcap`), not yet with a file written by Wireshark itself. pktmon logs every packet at several components (14 copies in our test): use `analyze --dedupe`, or capture with `pktmon start --capture --comp nics`. On Wi-Fi, pktmon stores raw 802.11 frames while labelling the file as Ethernet; NetShield detects and decodes these (Wireshark would show them as malformed Ethernet).
* The header audit checks one page's response headers. It cannot know intent: a cookie that is deliberately readable by JavaScript (e.g. analytics) is still flagged for missing `HttpOnly`.
* Follow Stream shows captured data only (no TLS decryption); loss at the end of a stream cannot be detected.
* Linux live capture (`AF_PACKET`) is implemented but **untested**: the project has only been run on Windows.
* `tests/data/*.key` are throwaway private keys for local TLS test servers; they protect nothing.
* Service detection concepts (port states, passive banner wait before probing) follow nmap's public documentation; the code and signatures are original.

## 🗺️ Roadmap

- [x] Modular architecture, themes, threaded scanner, packet sniffer
- [x] `argparse` commands, pcap export/import, DNS decoding, capture filters, statistics, tests
- [x] UDP scan (DNS, NTP, SNMP), TLS certificate inspection, IPv6 decoding, Follow TCP Stream
- [ ] More service probes and signatures (UDP: SSDP, mDNS, NetBIOS)
- [x] HTTP security header audit
- [x] DNS lookup, email security (SPF/DMARC/DKIM), WHOIS/RDAP, security.txt finder, `.pcapng` reading, coloured CLI output
- [ ] Live IPv6 capture on Windows (needs Npcap), HTTP request/response view
- [ ] Logging, recursive SPF lookup counting, public-suffix list for DMARC organisational domains

## 🐞 Reporting vulnerabilities to organisations

1. Run `python main.py disclosure <domain>` to find the official channel (security.txt), or look for the company's bug bounty / disclosure programme (HackerOne, Bugcrowd, Intigriti, YesWeHack).
2. Test **only** what the programme lists as in scope. Unauthorised testing can be a crime (in Turkey: TCK 243-244), even with good intentions.
3. Passive findings (headers, TLS, SPF/DMARC) are a start, but many programmes classify them as informational. Describe impact, steps to reproduce and a fix, and never access, change or keep data that is not yours.

## 🔒 Ethical use

For personal labs, CTFs, local testing and systems you are authorised to assess. Never use it for unauthorised access. The author is not responsible for misuse.

## 👨‍💻 Author

**Rumet Şaşmaz**: https://github.com/rumetsasmaz
