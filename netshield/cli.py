"""Command-line interface: `python main.py scan 127.0.0.1 -p 1-1000`.

Run `python main.py` with no arguments for the interactive menu.
Exit codes: 0 success, 1 runtime error / refused, 2 bad usage (argparse).
"""

import argparse
import csv
import io
import json
import sys
import time
from datetime import datetime

from netshield import scanning, sniffing, theme
from netshield.modules.hashing import ALGORITHMS, hash_text
from netshield.modules.password import generate_password, score_password
from netshield.modules.portdb import lookup
from netshield.modules.scanner import format_table
from netshield.theme import say


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netshield",
        description="NetShield-CLI: scanner, packet capture/analysis and security utilities. "
                    "Use only on systems and networks you own or are authorised to test. "
                    "Run without arguments for the interactive menu.")
    parser.add_argument("--theme", choices=theme.available_themes(), help="colour theme")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="TCP port & service scan")
    scan.add_argument("target", help="IP address or hostname")
    scan.add_argument("-p", "--ports", default="top",
                      help="22,80 | 1-1000 | top | all (default: top)")
    scan.add_argument("-t", "--timeout", type=float, default=scanning.DEFAULT_TIMEOUT,
                      help=f"seconds per port (default {scanning.DEFAULT_TIMEOUT})")
    scan.add_argument("-w", "--workers", type=int, default=100, help="threads (max 300)")
    scan.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    scan.add_argument("--all", action="store_true", help="also list closed/filtered ports")
    scan.add_argument("--format", choices=("table", "json", "csv"), default="table")
    scan.add_argument("-o", "--output", help="write the report to this file")
    scan.add_argument("--yes", action="store_true",
                      help="confirm you are authorised to scan a non-local target")

    disc = sub.add_parser("discover", help="find live hosts in a network (max /24)")
    disc.add_argument("network", help="CIDR, e.g. 192.168.1.0/24")
    disc.add_argument("-t", "--timeout", type=float, default=scanning.DEFAULT_TIMEOUT)
    disc.add_argument("--yes", action="store_true", help="confirm you are authorised")

    sniff = sub.add_parser("sniff", help="capture live traffic (Administrator/root)")
    sniff.add_argument("-i", "--interface-ip", help="local IP of the interface to listen on")
    sniff.add_argument("-c", "--count", type=int, default=20, help="stop after N packets")
    sniff.add_argument("-f", "--filter", default="", help="e.g. 'tcp and port 80'")
    sniff.add_argument("-w", "--write", help="save the capture as a pcap file")
    sniff.add_argument("--no-dedupe", action="store_true", help="keep duplicate packets")

    analyze = sub.add_parser("analyze", help="read a pcap file (also works on Wireshark captures)")
    analyze.add_argument("file", help="classic .pcap file")
    analyze.add_argument("-f", "--filter", default="", help="e.g. 'dns' or 'host 10.0.0.5'")
    analyze.add_argument("-n", "--limit", type=int, default=50, help="max packets to print")
    analyze.add_argument("--stats", action="store_true", help="show statistics instead of packets")

    ports = sub.add_parser("ports", help="look up a port number or service name")
    ports.add_argument("query")

    hashing = sub.add_parser("hash", help="hash text with md5/sha1/sha256/sha512")
    hashing.add_argument("text")

    passwd = sub.add_parser("passwd", help="check a password or generate one")
    group = passwd.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", metavar="PASSWORD")
    group.add_argument("--generate", nargs="?", const=16, type=int, metavar="LENGTH")
    return parser


def _authorised(ip, assume_yes):
    if scanning.is_loopback(ip) or assume_yes:
        return True
    say("warn", f"[!] {ip} is not this machine. Only scan systems you own or may test.")
    try:
        answer = input("Do you have authorization? [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def _write_or_print(text, path):
    if not path:
        print(text)
        return 0
    try:
        with open(path, "w", encoding="utf-8", newline="") as file:
            file.write(text + "\n")
    except OSError as error:
        say("error", f"[-] Could not write {path}: {error}")
        return 1
    say("ok", f"[+] Report written to {path}")
    return 0


def cmd_scan(args):
    ip = scanning.resolve_target(args.target)
    ports = scanning.parse_ports(args.ports)
    if not _authorised(ip, args.yes):
        say("error", "[-] Cancelled.")
        return 1
    started = datetime.now()
    results = scanning.scan_ports(ip, ports, timeout=args.timeout, workers=args.workers,
                                  grab_banner=not args.no_banner)
    shown = results if args.all else [r for r in results if r.state == scanning.OPEN]

    if args.format == "json":
        text = json.dumps({"target": args.target, "ip": ip, "scanned_at": started.isoformat(),
                           "results": [r.to_dict() for r in shown]}, indent=2)
    elif args.format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["port", "state", "service", "version", "banner", "risk"])
        for r in shown:
            writer.writerow([r.port, r.state, r.service, r.version, r.banner, r.risk])
        text = buffer.getvalue().rstrip("\n")
    else:
        counts = {s: sum(r.state == s for r in results)
                  for s in (scanning.OPEN, scanning.CLOSED, scanning.FILTERED)}
        text = (f"NetShield scan of {args.target} ({ip}) at {started:%Y-%m-%d %H:%M:%S}\n"
                + (format_table(shown) if shown else "No open ports found.")
                + f"\n\n{counts['open']} open, {counts['closed']} closed, "
                  f"{counts['filtered']} filtered ({len(ports)} ports)")
    return _write_or_print(text, args.output)


def cmd_discover(args):
    hosts = scanning.expand_network(args.network)
    if not (args.yes or input(
            f"Probe {len(hosts)} addresses? Only on networks you own/administer [y/N]: "
    ).strip().lower() in ("y", "yes")):
        say("error", "[-] Cancelled.")
        return 1
    alive = scanning.discover_hosts(args.network, timeout=args.timeout)
    print("\n".join(alive) if alive else "No live hosts responded.")
    return 0


def cmd_sniff(args):
    packet_filter = sniffing.compile_filter(args.filter)
    sniffer = sniffing.PacketSniffer(args.interface_ip, dedupe=not args.no_dedupe)
    sniffer.open()
    writer = sniffing.PcapWriter(args.write) if args.write else None
    say("info", f"[+] Listening on {sniffer.interface_ip}. Ctrl+C to stop.")
    captured = 0
    try:
        for packet in sniffer.packets():
            if packet is None or not packet_filter(packet):
                continue
            print(packet.summary())
            if writer:
                writer.write(packet)
            captured += 1
            if captured >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.close()
        if writer:
            writer.close()
    say("info", f"[+] Captured {captured} packet(s)" + (f", saved to {args.write}" if writer else ""))
    return 0


def cmd_analyze(args):
    packet_filter = sniffing.compile_filter(args.filter)
    stats = sniffing.CaptureStats()
    printed = matched = 0
    for packet in sniffing.read_pcap(args.file):
        if not packet_filter(packet):
            continue
        matched += 1
        stats.add(packet)
        if not args.stats and printed < args.limit:
            print(packet.summary())
            printed += 1
    if args.stats:
        print(stats.report() if matched else "No packets matched.")
    else:
        print(f"\n{matched} packet(s) matched" + (f", showing first {printed}" if matched > printed else ""))
    return 0


def cmd_ports(args):
    rows = lookup(args.query)
    for port, name, risk in rows:
        print(f"{port:>5}/tcp  {name:<14} {risk}")
    return 0 if rows else 1


def cmd_hash(args):
    for algorithm in ALGORITHMS:
        print(f"{algorithm.upper():<7} {hash_text(args.text, algorithm)}")
    return 0


def cmd_passwd(args):
    if args.check is not None:
        score, hints = score_password(args.check)
        print(f"Score: {score}/5")
        for hint in hints:
            print(f"  - {hint}")
        return 0
    print(generate_password(args.generate))
    return 0


COMMANDS = {"scan": cmd_scan, "discover": cmd_discover, "sniff": cmd_sniff,
            "analyze": cmd_analyze, "ports": cmd_ports, "hash": cmd_hash,
            "passwd": cmd_passwd}


def run(argv=None):
    args = build_parser().parse_args(argv)
    if args.theme:
        theme.set_theme(args.theme)
    try:
        return COMMANDS[args.command](args)
    except (ValueError, FileNotFoundError, sniffing.SniffError) as error:
        say("error", f"[-] {error}")
        return 1
    except KeyboardInterrupt:
        say("warn", "\n[!] Interrupted.")
        return 1
