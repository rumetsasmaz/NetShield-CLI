"""Scanning core: port states, banner grabbing, service detection, host discovery.

Concepts are inspired by nmap's documented behaviour (port states, passive
"null probe" banner wait first, protocol probes only afterwards). The code,
service list and signatures here are original to NetShield.

Nothing in this module prints. Functions return data so the UI (or tests,
or a JSON exporter) can decide how to show it.
"""

import errno
import ipaddress
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass

# --- port states -----------------------------------------------------------
OPEN, CLOSED, FILTERED = "open", "closed", "filtered"

# On Windows a refused connection is only reported after ~2 s (SYN retries),
# so anything below that cannot tell "closed" from "filtered".
DEFAULT_TIMEOUT = 2.5 if sys.platform == "win32" else 1.0

_REFUSED = {errno.ECONNREFUSED, 10061}
_MAX_HOSTS = 256  # discovery is capped at a /24

# --- own service table: port -> (name, risk note or "") --------------------
SERVICES = {
    20: ("ftp-data", ""),
    21: ("ftp", "Plain-text credentials and data (risky)"),
    22: ("ssh", ""),
    23: ("telnet", "Plain-text remote shell (very risky)"),
    25: ("smtp", ""),
    53: ("dns", ""),
    67: ("dhcp", ""),
    80: ("http", "Unencrypted web traffic"),
    110: ("pop3", "Plain-text mail login"),
    111: ("rpcbind", "Exposes RPC services"),
    123: ("ntp", ""),
    135: ("msrpc", "Windows RPC, common attack surface"),
    139: ("netbios-ssn", "Legacy Windows file sharing"),
    143: ("imap", "Plain-text mail login"),
    161: ("snmp", "Weak community strings are common"),
    389: ("ldap", ""),
    443: ("https", ""),
    445: ("smb", "File sharing, frequent exploit target"),
    465: ("smtps", ""),
    514: ("syslog", ""),
    587: ("submission", ""),
    631: ("ipp", ""),
    636: ("ldaps", ""),
    873: ("rsync", ""),
    993: ("imaps", ""),
    995: ("pop3s", ""),
    1080: ("socks", ""),
    1433: ("mssql", "Database should not be internet-facing"),
    1521: ("oracle", "Database should not be internet-facing"),
    2049: ("nfs", "Network file system"),
    2375: ("docker", "Unauthenticated Docker API is critical"),
    3000: ("dev-http", ""),
    3306: ("mysql", "Database should not be internet-facing"),
    3389: ("rdp", "Remote desktop, common brute-force target"),
    5000: ("dev-http", ""),
    5432: ("postgresql", "Database should not be internet-facing"),
    5900: ("vnc", "Often weakly protected remote desktop"),
    5985: ("winrm", ""),
    6379: ("redis", "Often exposed without authentication"),
    8000: ("http-alt", ""),
    8080: ("http-proxy", ""),
    8443: ("https-alt", ""),
    8888: ("http-alt", ""),
    9200: ("elasticsearch", "Often exposed without authentication"),
    27017: ("mongodb", "Often exposed without authentication"),
}

# Ports ordered roughly by how often they are open on real hosts.
TOP_PORTS = [
    80, 443, 22, 21, 25, 3389, 445, 139, 135, 53, 8080, 23, 110, 143, 3306,
    5900, 993, 995, 111, 1723, 587, 8443, 8000, 5432, 1433, 6379, 27017,
    8888, 3000, 5000, 389, 636, 161, 123, 631, 2049, 873, 1521, 5985, 9200,
    2375, 465, 514, 1080, 20, 67, 5060, 8081, 8888, 9090, 10000, 49152,
]

_TLS_PORTS = {443, 465, 636, 993, 995, 8443}


def service_name(port):
    return SERVICES.get(port, ("unknown", ""))[0]


def risk_note(port):
    return SERVICES.get(port, ("", ""))[1]


@dataclass
class PortResult:
    port: int
    state: str
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    risk: str = ""

    def to_dict(self):
        return asdict(self)


# --- input parsing ---------------------------------------------------------
def parse_ports(spec):
    """'22,80,1000-1010' -> sorted unique list. 'top' -> TOP_PORTS.

    Raises ValueError with a readable message on bad input.
    """
    spec = spec.strip().lower()
    if not spec:
        raise ValueError("port list is empty")
    if spec in ("top", "top50"):
        return sorted(set(TOP_PORTS))
    if spec == "all":
        return list(range(1, 65536))

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low_text, _, high_text = part.partition("-")
            low, high = _to_port(low_text), _to_port(high_text)
            if low > high:
                raise ValueError(f"range '{part}' starts after it ends")
            ports.update(range(low, high + 1))
        else:
            ports.add(_to_port(part))
    return sorted(ports)


def _to_port(text):
    try:
        value = int(text)
    except ValueError:
        raise ValueError(f"'{text}' is not a number") from None
    if not 1 <= value <= 65535:
        raise ValueError(f"port {value} is outside 1-65535")
    return value


def resolve_target(target):
    """Hostname or IP -> IPv4 string. Raises ValueError if it cannot resolve."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"could not resolve '{target}'") from None


def is_loopback(ip):
    return ipaddress.ip_address(ip).is_loopback


# --- service identification (own signatures) -------------------------------
_SIGNATURES = [
    (re.compile(r"^SSH-(\d\.\d)-OpenSSH[_-]([\w.]+)"), "ssh", "OpenSSH {2} (protocol {1})"),
    (re.compile(r"^SSH-(\d\.\d)-([\w.\-]+)"), "ssh", "{2} (protocol {1})"),
    (re.compile(r"^220[ -].*\bFTP\b", re.I), "ftp", ""),
    (re.compile(r"^220[ -].*\bSMTP\b|^220[ -].*ESMTP", re.I), "smtp", ""),
    (re.compile(r"^\+OK.*\bPOP3\b", re.I), "pop3", ""),
    (re.compile(r"^\* OK.*IMAP", re.I), "imap", ""),
    (re.compile(r"^RFB (\d{3}\.\d{3})"), "vnc", "RFB {1}"),
    (re.compile(r"^-ERR|^\+PONG|^-NOAUTH|^-DENIED", re.I), "redis", ""),
    (re.compile(r"^HTTP/(\d\.\d|\d) \d{3}"), "http", ""),
]
_SERVER_HEADER = re.compile(r"^server:\s*(.+)$", re.I | re.M)


def identify_service(port, banner):
    """Return (service, version) from a banner, falling back to the port table."""
    for pattern, service, template in _SIGNATURES:
        match = pattern.search(banner)
        if match:
            version = template.format(*([None] + list(match.groups()))) if template else ""
            if service == "http":
                header = _SERVER_HEADER.search(banner)
                if header:
                    version = header.group(1).strip()
            return service, version
    return service_name(port), ""


# --- single port -----------------------------------------------------------
def _classify(code):
    if code == 0:
        return OPEN
    if code in _REFUSED:
        return CLOSED
    return FILTERED  # timeout, unreachable, blocked...


def _clean(raw):
    text = raw.decode("utf-8", errors="replace").replace("\x00", "").strip()
    return text[:300]


def _grab_banner(sock, ip, port, timeout):
    """Passive first (many services speak first), then a protocol probe."""
    sock.settimeout(min(timeout, 1.5))
    try:
        data = sock.recv(1024)
        if data:
            return _clean(data)
    except (socket.timeout, OSError):
        pass

    try:
        if port in _TLS_PORTS:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=ip)
        # The service stayed silent, so ask it something. Silent services that
        # are not HTTP simply do not answer; the timeout bounds the cost.
        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        return _clean(sock.recv(2048))
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    return ""


def probe_port(ip, port, timeout=DEFAULT_TIMEOUT, grab_banner=True):
    """Probe one TCP port and return a PortResult."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        state = _classify(sock.connect_ex((ip, port)))
        result = PortResult(port=port, state=state, service=service_name(port))
        if state == OPEN:
            result.risk = risk_note(port)
            if grab_banner:
                result.banner = _grab_banner(sock, ip, port, timeout)
                result.service, result.version = identify_service(port, result.banner)
        return result
    except OSError:
        return PortResult(port=port, state=FILTERED, service=service_name(port))
    finally:
        sock.close()


# --- many ports ------------------------------------------------------------
def scan_ports(ip, ports, timeout=DEFAULT_TIMEOUT, workers=100,
               grab_banner=True, progress=None):
    """Scan ports concurrently. Returns results sorted by port number.

    progress, if given, is called as progress(done, total) from the calling
    thread only, so it is safe to print from it.
    """
    workers = max(1, min(workers, 300))
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe_port, ip, p, timeout, grab_banner) for p in ports]
        for done, future in enumerate(as_completed(futures), start=1):
            results.append(future.result())
            if progress:
                progress(done, len(futures))
    return sorted(results, key=lambda r: r.port)


# --- host discovery --------------------------------------------------------
DISCOVERY_PORTS = (80, 443, 22, 445, 3389, 135)


def expand_network(cidr):
    """'192.168.1.0/24' -> list of host IPs. Refuses anything bigger than a /24."""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        raise ValueError(f"'{cidr}' is not a valid network (example: 192.168.1.0/24)") from None
    if network.version != 4:
        raise ValueError("only IPv4 networks are supported")
    if network.num_addresses > _MAX_HOSTS:
        raise ValueError("network too large, the limit is a /24 (256 addresses)")
    hosts = list(network.hosts())
    return [str(h) for h in hosts] or [str(network.network_address)]


def host_is_up(ip, timeout=DEFAULT_TIMEOUT, ports=DISCOVERY_PORTS):
    """TCP ping: a host is up if any port accepts OR actively refuses.

    A refusal proves something answered, so it counts as alive too.
    """
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((ip, port))
            if code == 0 or code in _REFUSED:
                return True
        except OSError:
            pass
        finally:
            sock.close()
    return False


def discover_hosts(cidr, timeout=DEFAULT_TIMEOUT, workers=64, progress=None):
    hosts = expand_network(cidr)
    alive = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 128))) as pool:
        futures = {pool.submit(host_is_up, h, timeout): h for h in hosts}
        for done, future in enumerate(as_completed(futures), start=1):
            if future.result():
                alive.append(futures[future])
            if progress:
                progress(done, len(futures))
    return sorted(alive, key=lambda ip: tuple(int(p) for p in ip.split(".")))
