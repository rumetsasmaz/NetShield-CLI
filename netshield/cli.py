"""Command-line interface: `python main.py scan 127.0.0.1 -p 1-1000`.

Run `python main.py` with no arguments for the interactive menu.
Exit codes: 0 success, 1 runtime error / refused / below --fail-under, 2 bad usage.
Colour: on for terminals, off for files and pipes (or force with --color).
"""

import argparse
import csv
import io
import json
import socket
from datetime import datetime

from netshield import disclosure, mailsec, report, scanning, sniffing, theme, webaudit, whois
from netshield.modules.analyzer import format_stream_list
from netshield.modules.dnstools import DEFAULT_TYPES, lookup_lines
from netshield.modules.hashing import ALGORITHMS, hash_text
from netshield.modules.password import generate_password, score_password
from netshield.modules.portdb import lookup
from netshield.modules.scanner import format_table, format_tls_report, summarize_counts
from netshield.theme import STATUS_ROLES, paint, say


def build_parser():
    parser = argparse.ArgumentParser(
        prog="netshield",
        description="NetShield-CLI: scanner, packet capture/analysis and security utilities. "
                    "Use only on systems and networks you own or are authorised to test. "
                    "Run without arguments for the interactive menu.")
    parser.add_argument("--theme", choices=theme.available_themes(), help="colour theme")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="coloured output (auto: only on a terminal and if NO_COLOR is unset)")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="TCP (default) or UDP port & service scan")
    scan.add_argument("target", help="IP address or hostname")
    scan.add_argument("-p", "--ports", default="top",
                      help="22,80 | 1-1000 | top | all (default: top)")
    scan.add_argument("--udp", action="store_true",
                      help="scan UDP instead of TCP (DNS/NTP/SNMP get real probes)")
    scan.add_argument("-t", "--timeout", type=float, default=None,
                      help=f"seconds per port (default {scanning.DEFAULT_TIMEOUT} TCP, "
                           f"{scanning.UDP_TIMEOUT} per attempt UDP)")
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

    analyze = sub.add_parser("analyze", help="read a .pcap/.pcapng file (e.g. a Wireshark capture)")
    analyze.add_argument("file", help=".pcap or .pcapng file")
    analyze.add_argument("-f", "--filter", default="", help="e.g. 'dns' or 'host 10.0.0.5'")
    analyze.add_argument("-n", "--limit", type=int, default=50, help="max packets to print")
    analyze.add_argument("--stats", action="store_true", help="show statistics instead of packets")
    analyze.add_argument("--streams", action="store_true", help="list TCP streams")
    analyze.add_argument("--follow", type=int, metavar="N",
                         help="print the reassembled data of TCP stream number N (see --streams)")
    analyze.add_argument("--dedupe", action="store_true",
                         help="drop byte-identical copies (e.g. pktmon logs each packet several times)")

    tls = sub.add_parser("tls", help="inspect a TLS service: protocol, certificate, weaknesses")
    tls.add_argument("target", help="host or host:port (default port 443)")
    tls.add_argument("-t", "--timeout", type=float, default=scanning.DEFAULT_TIMEOUT)

    headers = sub.add_parser("headers", help="grade a website's HTTP security headers")
    headers.add_argument("url", help="e.g. example.com or https://example.com/login")
    headers.add_argument("-t", "--timeout", type=float, default=10.0)
    headers.add_argument("--insecure", action="store_true",
                         help="skip certificate verification (self-signed hosts you trust)")
    headers.add_argument("--show-headers", action="store_true", help="also print all response headers")
    _add_report_options(headers)

    dns = sub.add_parser("dns", help="look up DNS records of a domain")
    dns.add_argument("domain")
    dns.add_argument("-t", "--types", default=",".join(DEFAULT_TYPES),
                     help=f"comma-separated, default {','.join(DEFAULT_TYPES)} (also SOA)")
    _add_server_option(dns)

    mail = sub.add_parser("mail", help="grade a domain's email spoofing protection (SPF/DMARC/DKIM)")
    mail.add_argument("domain")
    mail.add_argument("--no-dkim", action="store_true", help="skip probing common DKIM selectors")
    _add_server_option(mail)
    _add_report_options(mail)

    who = sub.add_parser("whois", help="domain registration data (RDAP, WHOIS fallback)")
    who.add_argument("domain")
    who.add_argument("-t", "--timeout", type=float, default=10.0)
    who.add_argument("--format", choices=("table", "json"), default="table")

    disclose = sub.add_parser("disclosure", help="find where to report a vulnerability (security.txt)")
    disclose.add_argument("domain")
    disclose.add_argument("-t", "--timeout", type=float, default=10.0)
    disclose.add_argument("--format", choices=("table", "json"), default="table")

    rep = sub.add_parser("report", help="passive assessment of a domain as a Markdown/JSON report")
    rep.add_argument("domain")
    rep.add_argument("--checks", default=",".join(report.CHECKS),
                     help=f"comma-separated subset of {','.join(report.CHECKS)}")
    rep.add_argument("--format", choices=("md", "json"), default="md")
    rep.add_argument("-o", "--output", help="write the report to this file")
    rep.add_argument("-t", "--timeout", type=float, default=10.0)
    _add_server_option(rep)

    ports = sub.add_parser("ports", help="look up a port number or service name")
    ports.add_argument("query")

    hashing = sub.add_parser("hash", help="hash text with md5/sha1/sha256/sha512")
    hashing.add_argument("text")

    passwd = sub.add_parser("passwd", help="check a password or generate one")
    group = passwd.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", metavar="PASSWORD")
    group.add_argument("--generate", nargs="?", const=16, type=int, metavar="LENGTH")
    return parser


def _add_report_options(parser):
    parser.add_argument("--format", choices=("table", "json"), default="table")
    parser.add_argument("-o", "--output", help="write the report to this file")
    parser.add_argument("--fail-under", type=int, metavar="SCORE",
                        help="exit with code 1 if the score is below SCORE (useful in CI)")


def _add_server_option(parser):
    parser.add_argument("--server", help="DNS server IP to ask (default: this machine's resolver)")


def _check_server(server):
    if server is None:
        return None
    try:
        socket.inet_aton(server)
    except OSError:
        raise ValueError(f"--server must be an IPv4 address, got '{server}'") from None
    return server


# --- output ------------------------------------------------------------------
def _output(lines, path=None):
    """Print [(role, text)] in colour, or write plain text to `path`."""
    if not path:
        for role, text in lines:
            print(paint(role, text))
        return 0
    try:
        with open(path, "w", encoding="utf-8", newline="") as file:
            file.write("\n".join(text for _role, text in lines) + "\n")
    except OSError as error:
        say("error", f"[-] Could not write {path}: {error}")
        return 1
    say("ok", f"[+] Report written to {path}")
    return 0


def _plain(text):
    return [("plain", text)]


def _status_lines(pairs):
    return [(STATUS_ROLES[status], text) for status, text in pairs]


def _table_lines(table):
    lines = []
    for line in table.splitlines():
        if line.startswith("PORT"):
            lines.append(("title", line))
        elif line.lstrip().startswith("!"):
            lines.append(("warn", line))
        else:
            lines.append(("warn" if scanning.OPEN_FILTERED in line else "ok", line))
    return lines


def _check_fail_under(args, score, code):
    if code == 0 and args.fail_under is not None and score < args.fail_under:
        say("error", f"[-] Score {score} is below the required {args.fail_under}.")
        return 1
    return code


def _authorised(ip, assume_yes):
    if scanning.is_loopback(ip) or assume_yes:
        return True
    say("warn", f"[!] {ip} is not this machine. Only scan systems you own or may test.")
    try:
        answer = input("Do you have authorization? [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


# --- commands ----------------------------------------------------------------
def cmd_scan(args):
    protocol = "udp" if args.udp else "tcp"
    ip = scanning.resolve_target(args.target)
    ports = scanning.parse_ports(args.ports, protocol)
    if not _authorised(ip, args.yes):
        say("error", "[-] Cancelled.")
        return 1
    started = datetime.now()
    results = scanning.scan_ports(ip, ports, timeout=args.timeout, workers=args.workers,
                                  grab_banner=not args.no_banner, protocol=protocol,
                                  server_name=scanning.hostname_or_none(args.target))
    if args.all:
        shown = results
    else:
        shown = [r for r in results if r.state == scanning.OPEN]
        if protocol == "udp" and not shown:  # UDP silence is the common case; show it
            shown = [r for r in results if r.state == scanning.OPEN_FILTERED]

    if args.format == "json":
        return _output(_plain(json.dumps({"target": args.target, "ip": ip, "protocol": protocol,
                                          "scanned_at": started.isoformat(),
                                          "results": [r.to_dict() for r in shown]}, indent=2)),
                       args.output)
    if args.format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["port", "state", "service", "version", "banner", "risk"])
        for r in shown:
            writer.writerow([r.port, r.state, r.service, r.version, r.banner, r.risk])
        return _output(_plain(buffer.getvalue().rstrip("\n")), args.output)

    lines = [("title", f"NetShield {protocol.upper()} scan of {args.target} ({ip}) "
                       f"at {started:%Y-%m-%d %H:%M:%S}")]
    lines += _table_lines(format_table(shown)) if shown else [("warn", "No open ports found.")]
    lines += [("plain", ""), ("info", f"{summarize_counts(results)} ({len(ports)} ports)")]
    return _output(lines, args.output)


def cmd_discover(args):
    hosts = scanning.expand_network(args.network)
    if not (args.yes or input(
            f"Probe {len(hosts)} addresses? Only on networks you own/administer [y/N]: "
    ).strip().lower() in ("y", "yes")):
        say("error", "[-] Cancelled.")
        return 1
    alive = scanning.discover_hosts(args.network, timeout=args.timeout)
    return _output([("ok", ip) for ip in alive] or [("warn", "No live hosts responded.")])


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


def cmd_tls(args):
    host, _, port_text = args.target.partition(":") if args.target.count(":") == 1 else (args.target, "", "")
    port = int(port_text) if port_text else 443
    ip = scanning.resolve_target(host)
    try:
        info = scanning.tls_info(ip, port, timeout=args.timeout, server_name=host)
    except OSError as error:  # includes ssl.SSLError and timeouts
        say("error", f"[-] TLS handshake with {host}:{port} failed: {error}")
        return 1
    lines = []
    for line in format_tls_report(host, port, info).splitlines():
        if line.strip().startswith("!") or "NO -" in line or "EXPIRED" in line:
            lines.append(("warn" if line.strip().startswith("!") else "error", line))
        else:
            lines.append(("title" if line.startswith("TLS report") else "plain", line))
    return _output(lines)


def cmd_headers(args):
    report = webaudit.audit_url(args.url, timeout=args.timeout, insecure=args.insecure)
    if args.format == "json":
        code = _output(_plain(json.dumps(report.to_dict(), indent=2)), args.output)
    else:
        code = _output(_status_lines(webaudit.report_lines(report, args.show_headers)), args.output)
    return _check_fail_under(args, report.score, code)


def cmd_dns(args):
    types = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    return _output(lookup_lines(args.domain, types, _check_server(args.server)))


def cmd_mail(args):
    report = mailsec.audit_domain(args.domain, server=_check_server(args.server),
                                  check_dkim=not args.no_dkim)
    if args.format == "json":
        code = _output(_plain(json.dumps(report.to_dict(), indent=2)), args.output)
    else:
        code = _output(_status_lines(mailsec.report_lines(report)), args.output)
    return _check_fail_under(args, report.score, code)


def cmd_whois(args):
    info = whois.lookup(args.domain, timeout=args.timeout)
    if args.format == "json":
        return _output(_plain(json.dumps(info.to_dict(), indent=2)))
    return _output(_status_lines(whois.report_lines(info)))


def cmd_report(args):
    checks = [c.strip().lower() for c in args.checks.split(",") if c.strip()]
    unknown = [c for c in checks if c not in report.CHECKS]
    if unknown or not checks:
        raise ValueError(f"unknown check(s) {', '.join(unknown) or '(none given)'}; "
                         f"choose from {', '.join(report.CHECKS)}")
    result = report.assess(args.domain, checks=checks, timeout=args.timeout,
                           dns_server=_check_server(args.server))
    text = report.to_json(result) if args.format == "json" else report.to_markdown(result)
    code = _output(_plain(text), args.output)
    if args.output:
        counts = result.counts()
        say("info", "    " + ", ".join(f"{counts[s]} {s}" for s in report.SEVERITIES))
    return code


def cmd_disclosure(args):
    result = disclosure.find_security_txt(args.domain, timeout=args.timeout)
    if args.format == "json":
        return _output(_plain(json.dumps(result.to_dict() if result else None, indent=2)))
    return _output(_status_lines(disclosure.report_lines(args.domain, result)))


def _load_packets(args):
    """Read, filter and (optionally) de-duplicate a capture; warn about heavy duplication."""
    packet_filter = sniffing.compile_filter(args.filter)
    packets = [p for p in sniffing.read_pcap(args.file) if packet_filter(p)]
    unique, copies = sniffing.drop_exact_copies(packets)
    if args.dedupe:
        if copies:
            say("info", f"[+] Dropped {copies} byte-identical copies ({len(unique)} packets left).")
        return unique
    if packets and copies / len(packets) > 0.3:
        say("warn", f"[!] {100 * copies // len(packets)}% of the packets are exact copies (pktmon logs each "
                    "packet at several components). Add --dedupe, or capture with "
                    "'pktmon start --capture --comp nics'.")
    return packets


def cmd_analyze(args):
    packets = _load_packets(args)
    if args.streams or args.follow is not None:
        streams = sniffing.tcp_streams(packets)
        if args.follow is None:
            return _output(_plain(format_stream_list(streams)) if streams
                           else [("warn", "No TCP streams found.")])
        if not 0 <= args.follow < len(streams):
            say("error", f"[-] Stream {args.follow} does not exist ({len(streams)} found; see --streams).")
            return 1
        lines = [("title", f"Stream {args.follow}: {streams[args.follow].label()}"), ("plain", "")]
        for line in streams[args.follow].render().splitlines():
            role = "title" if line.startswith("--- client") else "info" if line.startswith("--- server") \
                else "warn" if line.startswith("[...") else "plain"
            lines.append((role, line))
        return _output(lines)

    stats = sniffing.CaptureStats()
    printed = matched = 0
    for packet in packets:
        matched += 1
        stats.add(packet)
        if not args.stats and printed < args.limit:
            print(packet.summary())
            printed += 1
    if args.stats:
        return _output(_plain(stats.report()) if matched else [("warn", "No packets matched.")])
    return _output([("info", f"\n{matched} packet(s) matched"
                             + (f", showing first {printed}" if matched > printed else ""))])


def cmd_ports(args):
    rows = lookup(args.query)
    _output([("warn" if risk else "ok", f"{port:>5}/tcp  {name:<14} {risk}") for port, name, risk in rows])
    return 0 if rows else 1


def cmd_hash(args):
    return _output([("ok", f"{algorithm.upper():<7} {hash_text(args.text, algorithm)}")
                    for algorithm in ALGORITHMS])


def cmd_passwd(args):
    if args.check is not None:
        score, hints = score_password(args.check)
        role = "ok" if score == 5 else "warn" if score >= 3 else "error"
        return _output([(role, f"Score: {score}/5")] + [("warn", f"  - {hint}") for hint in hints])
    return _output(_plain(generate_password(args.generate)))


COMMANDS = {"scan": cmd_scan, "discover": cmd_discover, "sniff": cmd_sniff,
            "analyze": cmd_analyze, "tls": cmd_tls, "headers": cmd_headers,
            "dns": cmd_dns, "mail": cmd_mail, "whois": cmd_whois, "disclosure": cmd_disclosure,
            "report": cmd_report,
            "ports": cmd_ports, "hash": cmd_hash, "passwd": cmd_passwd}


def run(argv=None):
    args = build_parser().parse_args(argv)
    if args.theme:
        theme.set_theme(args.theme)
    theme.set_colour(args.color)
    try:
        return COMMANDS[args.command](args)
    except (ValueError, FileNotFoundError, sniffing.SniffError) as error:
        say("error", f"[-] {error}")
        return 1
    except KeyboardInterrupt:
        say("warn", "\n[!] Interrupted.")
        return 1
