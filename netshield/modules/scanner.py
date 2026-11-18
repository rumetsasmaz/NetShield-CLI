import json
import sys
from datetime import datetime

from netshield import scanning
from netshield.base import BaseModule
from netshield.theme import ask, say

_STATES = (scanning.OPEN, scanning.OPEN_FILTERED, scanning.CLOSED, scanning.FILTERED)


def _confirm_authorization(ip):
    """Scanning other people's machines can be illegal; ask before doing it."""
    if scanning.is_loopback(ip):
        return True
    say("warn", f"[!] {ip} is not this machine. Only scan systems you own or have written permission to test.")
    return ask("Do you have authorization to scan this target? [y/N]:").lower() in ("y", "yes")


def _progress(done, total):
    if total >= 100 and (done % 25 == 0 or done == total):
        sys.stdout.write(f"\r  progress: {done}/{total}")
        sys.stdout.flush()
        if done == total:
            sys.stdout.write("\r" + " " * 30 + "\r")


def _save_report(payload):
    path = ask("Save JSON report to (Enter to skip):")
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2)
        say("ok", f"[+] Report saved to {path}")
    except OSError as error:
        say("error", f"[-] Could not save report: {error}")


def format_table(results):
    """Scan results as an nmap-style table; TLS findings are listed under their port."""
    lines = [f"{'PORT':<10}{'STATE':<15}{'SERVICE':<14}VERSION / BANNER"]
    for r in results:
        if r.version:
            detail = r.version
        else:
            detail = r.banner.splitlines()[0][:50] if r.banner else ""
        if r.tls:
            detail = (detail + "  " if detail else "") + f"[{scanning.tls_summary(r.tls)}]"
        lines.append(f"{f'{r.port}/{r.protocol}':<10}{r.state:<15}{r.service:<14}{detail}")
        if r.tls:
            for finding in r.tls.get("findings", []):
                lines.append(f"{'':<10}  ! {finding}")
    return "\n".join(lines)


def format_tls_report(host, port, info):
    lines = [f"TLS report for {host}:{port}",
             f"  Protocol : {info['version']}   Cipher: {info['cipher']} ({info['bits']}-bit)",
             f"  Subject  : {info['subject'] or '(unknown)'}",
             f"  Issuer   : {info['issuer'] or '(unknown)'}",
             f"  Valid    : {info['not_before'] or '?'}  ->  {info['not_after'] or '?'}"]
    if info["days_left"] is not None:
        lines.append(f"  Expires  : in {info['days_left']} day(s)" if info["days_left"] >= 0
                     else f"  Expires  : EXPIRED {-info['days_left']} day(s) ago")
    if info["san"]:
        lines.append(f"  Names    : {', '.join(info['san'][:8])}")
    lines.append(f"  Trusted  : {'yes' if info['trusted'] else 'NO - ' + info['verify_error']}")
    lines.append(f"  SHA-256  : {info['fingerprint_sha256']}")
    if info["findings"]:
        lines.append("  Findings :")
        lines += [f"    ! {finding}" for finding in info["findings"]]
    else:
        lines.append("  Findings : none")
    return "\n".join(lines)


def summarize_counts(results):
    counts = {state: sum(r.state == state for r in results) for state in _STATES}
    return ", ".join(f"{counts[s]} {s}" for s in _STATES if counts[s])


class PortScannerModule(BaseModule):
    name = "Port & Service Scanner"
    description = "Threaded TCP/UDP scan with port states, banners, service and TLS detection"

    def run(self):
        target = ask("Target IP or domain (e.g. 127.0.0.1):")
        if not target:
            say("error", "[-] Target cannot be empty.")
            return
        protocol = "udp" if ask("Protocol tcp/udp [tcp]:").lower() == "udp" else "tcp"
        try:
            ip = scanning.resolve_target(target)
            ports = scanning.parse_ports(
                ask("Ports (e.g. 22,80,443 | 1-1000 | top | all) [top]:") or "top", protocol)
        except ValueError as error:
            say("error", f"[-] {error}")
            return
        if not _confirm_authorization(ip):
            say("error", "[-] Scan cancelled.")
            return

        say("title", f"\n[+] {protocol.upper()} scan of {target} ({ip}), {len(ports)} ports")
        started = datetime.now()
        try:
            results = scanning.scan_ports(ip, ports, progress=_progress, protocol=protocol,
                                          server_name=scanning.hostname_or_none(target))
        except KeyboardInterrupt:
            say("warn", "\n[!] Scan interrupted.")
            return
        seconds = (datetime.now() - started).total_seconds()

        found = [r for r in results if r.state in (scanning.OPEN, scanning.OPEN_FILTERED)]
        say("dim", "=" * 60)
        shown = [r for r in found if r.state == scanning.OPEN] or found
        if shown:
            say("ok", format_table(shown))
            for r in shown:
                if r.risk:
                    say("warn", f"  ! {r.port}/{r.service}: {r.risk}")
        else:
            say("warn", "No open ports found.")
        say("dim", "=" * 60)
        say("info", f"{summarize_counts(results)} in {seconds:.1f}s")
        if protocol == "udp":
            say("dim", "(open|filtered: no reply; the port may be open or a firewall dropped the probe)")

        _save_report({"target": target, "ip": ip, "protocol": protocol,
                      "scanned_at": started.isoformat(),
                      "results": [r.to_dict() for r in results if r.state != scanning.CLOSED]})


class TlsCheckModule(BaseModule):
    name = "TLS Certificate Check"
    description = "Protocol, cipher, certificate validity, trust and weaknesses of a TLS service"

    def run(self):
        text = ask("Host or host:port (default port 443):")
        host, _, port_text = text.partition(":") if text.count(":") == 1 else (text, "", "")
        if not host:
            say("error", "[-] No host given.")
            return
        try:
            port = int(port_text) if port_text else 443
            ip = scanning.resolve_target(host)
            info = scanning.tls_info(ip, port, server_name=host)
        except ValueError as error:
            say("error", f"[-] {error}")
            return
        except OSError as error:  # includes ssl.SSLError and timeouts
            say("error", f"[-] TLS handshake failed: {error}")
            return
        say("ok", format_tls_report(host, port, info))


class HostDiscoveryModule(BaseModule):
    name = "Host Discovery"
    description = "Find live hosts in a network (TCP ping, max /24)"

    def run(self):
        cidr = ask("Network in CIDR form (e.g. 192.168.1.0/24):")
        try:
            hosts = scanning.expand_network(cidr)
        except ValueError as error:
            say("error", f"[-] {error}")
            return
        say("warn", f"[!] This probes {len(hosts)} addresses. Only use it on networks you own or administer.")
        if ask("Continue? [y/N]:").lower() not in ("y", "yes"):
            say("error", "[-] Cancelled.")
            return
        try:
            alive = scanning.discover_hosts(cidr, progress=_progress)
        except KeyboardInterrupt:
            say("warn", "\n[!] Interrupted.")
            return
        if not alive:
            say("warn", "No live hosts responded.")
            return
        say("ok", f"[+] {len(alive)} host(s) up:")
        for ip in alive:
            say("ok", f"    {ip}")
