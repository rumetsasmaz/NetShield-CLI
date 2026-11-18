import json
import sys
from datetime import datetime

from netshield import scanning
from netshield.base import BaseModule
from netshield.theme import ask, say


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
    lines = [f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}VERSION / BANNER"]
    for r in results:
        detail = r.version or (r.banner.splitlines()[0][:50] if r.banner else "")
        lines.append(f"{str(r.port) + '/tcp':<10}{r.state:<10}{r.service:<15}{detail}")
    return "\n".join(lines)


class PortScannerModule(BaseModule):
    name = "Port & Service Scanner"
    description = "Threaded TCP scan with port states, banner grabbing and service detection"

    def run(self):
        target = ask("Target IP or domain (e.g. 127.0.0.1):")
        if not target:
            say("error", "[-] Target cannot be empty.")
            return
        try:
            ip = scanning.resolve_target(target)
            ports = scanning.parse_ports(
                ask("Ports (e.g. 22,80,443 | 1-1000 | top | all) [top]:") or "top")
        except ValueError as error:
            say("error", f"[-] {error}")
            return
        if not _confirm_authorization(ip):
            say("error", "[-] Scan cancelled.")
            return

        say("title", f"\n[+] Scanning {target} ({ip}), {len(ports)} ports")
        started = datetime.now()
        try:
            results = scanning.scan_ports(ip, ports, progress=_progress)
        except KeyboardInterrupt:
            say("warn", "\n[!] Scan interrupted.")
            return
        seconds = (datetime.now() - started).total_seconds()

        open_ports = [r for r in results if r.state == scanning.OPEN]
        closed = sum(r.state == scanning.CLOSED for r in results)
        filtered = sum(r.state == scanning.FILTERED for r in results)
        say("dim", "=" * 60)
        if open_ports:
            say("ok", format_table(open_ports))
            for r in open_ports:
                if r.risk:
                    say("warn", f"  ! {r.port}/{r.service}: {r.risk}")
        else:
            say("warn", "No open ports found.")
        say("dim", "=" * 60)
        say("info", f"{len(open_ports)} open, {closed} closed, {filtered} filtered "
                    f"in {seconds:.1f}s")
        if filtered and seconds and scanning.DEFAULT_TIMEOUT < 2.1 and sys.platform == "win32":
            say("dim", "(on Windows, timeouts under ~2s cannot separate closed from filtered)")

        _save_report({"target": target, "ip": ip, "scanned_at": started.isoformat(),
                      "results": [r.to_dict() for r in results if r.state == scanning.OPEN]})


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
