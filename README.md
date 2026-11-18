# 🛡️ NetShield-CLI

A modular, Python-based cybersecurity command-line toolkit for learning, experimentation and basic security analysis. Standard library plus `colorama` only.

> ⚠️ **Educational project.** Use it only on systems, networks, accounts and data you own or have explicit written permission to test.
>
> 🤖 **Development note:** this repository is developed with AI assistance (Claude Code).

## ✨ Tools

| Tool | What it does |
|---|---|
| **Port & Service Scanner** | Threaded TCP scan. Reports `open` / `closed` / `filtered`, grabs banners (passive first, then an HTTP probe) and identifies services and versions. Port specs: `22,80`, `1-1000`, `top`, `all`. Optional JSON report. |
| **Host Discovery** | TCP ping of a network (CIDR, max `/24`). |
| **Packet Sniffer** | Wireshark-style capture and decoding of IPv4 TCP/UDP/ICMP with protocol/port/host filters. Needs Administrator/root. |
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

## 🧱 Architecture

```
main.py                  menu built automatically from the module registry
netshield/
  base.py                BaseModule (name, description, run)
  theme.py / config.py   colours, safe output, settings
  scanning.py            scan core (returns data, never prints)
  sniffing.py            packet parsers (pure) + raw-socket capture
  modules/               one BaseModule subclass per tool
```

Adding a tool = write a `BaseModule` subclass in `netshield/modules/` and list it in `netshield/modules/__init__.py`.

## 📝 Notes & limits

* On Windows a refused connection is reported after ~2 s, so the default timeout is 2.5 s there. Below ~2 s, `closed` and `filtered` cannot be told apart.
* The scanner uses plain TCP connects (no raw SYN scan, no OS fingerprinting).
* The sniffer is IPv4 only. On Windows it sees IP-level traffic of one interface and needs an elevated terminal.
* Service detection concepts (port states, passive banner wait before probing) follow nmap's public documentation; the code and signatures are original.

## 🗺️ Roadmap

- [x] Modular architecture, themes, threaded scanner, packet sniffer
- [ ] `argparse` commands (`netshield scan 10.0.0.5 -p 1-1000`)
- [ ] More service probes and signatures, UDP scan
- [ ] Export sniffer captures (pcap)
- [ ] Automated tests (`pytest`), logging

## 🔒 Ethical use

For personal labs, CTFs, local testing and systems you are authorised to assess. Never use it for unauthorised access. The author is not responsible for misuse.

## 👨‍💻 Author

**Rumet Şaşmaz**: https://github.com/rumetsasmaz
