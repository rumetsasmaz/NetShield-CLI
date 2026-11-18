"""Scanning core: port states, banner grabbing, service detection, host discovery.

Concepts are inspired by nmap's documented behaviour (port states, passive
"null probe" banner wait first, protocol probes only afterwards). The code,
service list and signatures here are original to NetShield.

Nothing in this module prints. Functions return data so the UI (or tests,
or a JSON exporter) can decide how to show it.
"""

import errno
import hashlib
import ipaddress
import os
import re
import socket
import ssl
import struct
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

# --- port states -----------------------------------------------------------
OPEN, CLOSED, FILTERED = "open", "closed", "filtered"
OPEN_FILTERED = "open|filtered"  # UDP: silence can mean open or dropped

# On Windows a refused connection is only reported after ~2 s (SYN retries),
# so anything below that cannot tell "closed" from "filtered".
DEFAULT_TIMEOUT = 2.5 if sys.platform == "win32" else 1.0
UDP_TIMEOUT = 1.5  # per attempt; each UDP port gets two attempts

_REFUSED = {errno.ECONNREFUSED, 10061}
# A UDP "port closed" arrives as an ICMP unreachable, which the OS reports as
# ECONNREFUSED (Linux) or WSAECONNRESET (Windows) on the next socket call.
_UDP_CLOSED = {errno.ECONNREFUSED, errno.ECONNRESET, 10061, 10054}
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

# UDP services (names differ from the TCP table for the same port number).
UDP_SERVICES = {
    53: ("dns", ""), 67: ("dhcp", ""), 69: ("tftp", "Unauthenticated file transfer"),
    123: ("ntp", ""), 137: ("netbios-ns", ""), 161: ("snmp", "Weak community strings are common"),
    500: ("isakmp", ""), 514: ("syslog", ""), 1900: ("ssdp", "UPnP discovery, often exposed by accident"),
    5353: ("mdns", ""),
}
UDP_TOP_PORTS = [53, 123, 161, 137, 67, 69, 500, 514, 1900, 5353]


def service_name(port, protocol="tcp"):
    table = UDP_SERVICES if protocol == "udp" else SERVICES
    return table.get(port, ("unknown", ""))[0]


def risk_note(port, protocol="tcp"):
    table = UDP_SERVICES if protocol == "udp" else SERVICES
    return table.get(port, ("", ""))[1]


@dataclass
class PortResult:
    port: int
    state: str
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    risk: str = ""
    protocol: str = "tcp"
    tls: dict = None

    def to_dict(self):
        return asdict(self)


# --- input parsing ---------------------------------------------------------
def parse_ports(spec, protocol="tcp"):
    """'22,80,1000-1010' -> sorted unique list. 'top' -> the common ports.

    Raises ValueError with a readable message on bad input.
    """
    spec = spec.strip().lower()
    if not spec:
        raise ValueError("port list is empty")
    if spec in ("top", "top50"):
        return sorted(set(UDP_TOP_PORTS if protocol == "udp" else TOP_PORTS))
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


def hostname_or_none(target):
    """The name to use for SNI/Host: the target if it is a hostname, None if it is an IP."""
    try:
        ipaddress.ip_address(target)
        return None
    except ValueError:
        return target


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


def _grab_banner(sock, ip, port, timeout, server_name=None):
    """Passive first (many services speak first), then a protocol probe.

    server_name is the hostname the user asked for; it is used for TLS SNI and
    the HTTP Host header (virtual hosts and CDNs answer differently per name).
    """
    name = server_name or ip
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
            sock = context.wrap_socket(sock, server_hostname=name)
        # The service stayed silent, so ask it something. Silent services that
        # are not HTTP simply do not answer; the timeout bounds the cost.
        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {name}\r\n\r\n".encode())
        return _clean(sock.recv(2048))
    except (socket.timeout, ssl.SSLError, OSError):
        pass
    return ""


def probe_port(ip, port, timeout=DEFAULT_TIMEOUT, grab_banner=True, server_name=None):
    """Probe one TCP port and return a PortResult.

    server_name: the hostname the user typed (None when they gave an IP), so TLS
    SNI, the Host header and certificate hostname checks use the right name.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        state = _classify(sock.connect_ex((ip, port)))
        result = PortResult(port=port, state=state, service=service_name(port))
        if state == OPEN:
            result.risk = risk_note(port)
            if grab_banner:
                result.banner = _grab_banner(sock, ip, port, timeout, server_name)
                result.service, result.version = identify_service(port, result.banner)
                if port in _TLS_PORTS:
                    try:
                        result.tls = tls_info(ip, port, timeout, server_name=server_name)
                    except (OSError, ssl.SSLError, ValueError):
                        result.tls = None
        return result
    except OSError:
        return PortResult(port=port, state=FILTERED, service=service_name(port))
    finally:
        sock.close()


# --- TLS certificate inspection ---------------------------------------------
def _flatten_name(rdns):
    flat = {}
    for rdn in rdns or ():
        for key, value in rdn:
            flat.setdefault(key, value)
    return flat


def _name_text(flat):
    if flat.get("commonName"):
        return flat["commonName"]
    return flat.get("organizationName") or ", ".join(f"{k}={v}" for k, v in flat.items())


def _decode_certificate(der):
    """Decode a DER certificate into getpeercert()-style data.

    The standard library only parses certificates it has verified, so this uses
    its test decoder (a private API). If that is unavailable we return {} and
    the caller reports what it can without certificate details.
    """
    handle, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(handle, "w") as file:
            file.write(ssl.DER_cert_to_PEM_cert(der))
        return ssl._ssl._test_decode_cert(path)
    except (AttributeError, ValueError, OSError, ssl.SSLError):
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _verify_chain(host, port, timeout, server_name):
    """Second handshake with full verification. Returns (trusted, reason)."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_name):
                return True, ""
    except ssl.SSLCertVerificationError as error:
        return False, error.verify_message
    except (ssl.SSLError, OSError) as error:
        return False, str(error)


def tls_info(host, port=443, timeout=DEFAULT_TIMEOUT, server_name=None):
    """Inspect a TLS service: protocol, cipher, certificate and weaknesses.

    Raises OSError / ssl.SSLError if the connection or handshake fails.
    """
    server_name = server_name or host
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # we want to inspect bad certificates too
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            version = tls.version()
            cipher, _protocol, bits = tls.cipher()
            der = tls.getpeercert(binary_form=True)

    cert = _decode_certificate(der) if der else {}
    subject = _flatten_name(cert.get("subject"))
    issuer = _flatten_name(cert.get("issuer"))
    days_left = None
    if cert.get("notAfter"):
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
    trusted, reason = _verify_chain(host, port, timeout, server_name)
    self_signed = bool(subject) and subject == issuer

    findings = []
    if days_left is not None:
        if days_left < 0:
            findings.append(f"certificate expired {-days_left} day(s) ago")
        elif days_left < 30:
            findings.append(f"certificate expires in {days_left} day(s)")
    if self_signed:
        findings.append("self-signed certificate")
    elif not trusted and not (days_left is not None and days_left < 0):
        findings.append(f"not trusted: {reason}")
    if version in ("SSLv3", "TLSv1", "TLSv1.1"):
        findings.append(f"outdated protocol {version}")
    if bits and bits < 128:
        findings.append(f"weak cipher ({bits}-bit)")

    return {
        "version": version,
        "cipher": cipher,
        "bits": bits,
        "subject": _name_text(subject),
        "issuer": _name_text(issuer),
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
        "days_left": days_left,
        "san": [value for _kind, value in cert.get("subjectAltName", ())],
        "self_signed": self_signed,
        "trusted": trusted,
        "verify_error": reason,
        "fingerprint_sha256": hashlib.sha256(der).hexdigest() if der else "",
        "findings": findings,
    }


def tls_summary(info):
    """One-line summary of tls_info() output for tables."""
    if not info:
        return ""
    text = f"{info['version']} {info['subject']}".strip()
    days = info.get("days_left")
    if days is not None:
        text += f", EXPIRED {-days}d ago" if days < 0 else f", expires in {days}d"
    return text


# --- UDP ---------------------------------------------------------------------
def _tlv(tag, content):
    return bytes([tag, len(content)]) + content


_SNMP_SYSDESCR_OID = bytes.fromhex("2b06010201010100")  # 1.3.6.1.2.1.1.1.0
_DNS_PROBE_ID = b"\x4e\x53"
_UDP_PROBES = {
    # DNS: standard query for the root NS records
    53: _DNS_PROBE_ID + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + b"\x00" + struct.pack("!HH", 2, 1),
    # NTP: plain client-mode request
    123: b"\x1b" + b"\x00" * 47,
    # SNMPv1 GetRequest for sysDescr.0 with the well-known community "public"
    161: _tlv(0x30, _tlv(2, b"\x00") + _tlv(4, b"public") + _tlv(0xA0, (
        _tlv(2, b"\x00\x00\x00\x01") + _tlv(2, b"\x00") + _tlv(2, b"\x00")
        + _tlv(0x30, _tlv(0x30, _tlv(6, _SNMP_SYSDESCR_OID) + _tlv(5, b"")))))),
}


def identify_udp(port, reply):
    """Return (service, version) for a UDP reply."""
    if port == 53 and len(reply) >= 12 and reply[:2] == _DNS_PROBE_ID and reply[2] & 0x80:
        return "dns", ""
    if port == 123 and len(reply) >= 48:
        return "ntp", f"NTPv{(reply[0] >> 3) & 7} stratum {reply[1]}"
    if port == 161 and reply[:1] == b"\x30":
        index = reply.find(_SNMP_SYSDESCR_OID)
        if index >= 0:
            start = index + len(_SNMP_SYSDESCR_OID)
            if start + 1 < len(reply) and reply[start] == 0x04 and reply[start + 1] < 128:
                text = reply[start + 2:start + 2 + reply[start + 1]]
                return "snmp", text.decode("utf-8", errors="replace")[:60]
        return "snmp", ""
    return service_name(port, "udp"), ""


def probe_udp_port(ip, port, timeout=UDP_TIMEOUT):
    """Probe one UDP port. States: open (got a reply), closed (ICMP unreachable),
    open|filtered (silence after two attempts)."""
    probe = _UDP_PROBES.get(port, b"\x00")
    result = PortResult(port=port, state=OPEN_FILTERED, service=service_name(port, "udp"),
                        protocol="udp")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))  # sends nothing, but lets the OS report ICMP errors
        for _attempt in range(2):
            try:
                sock.send(probe)
                reply = sock.recv(2048)
            except socket.timeout:
                continue
            except OSError as error:
                code = getattr(error, "winerror", None) or error.errno
                result.state = CLOSED if code in _UDP_CLOSED else FILTERED
                return result
            result.state = OPEN
            result.risk = risk_note(port, "udp")
            result.service, result.version = identify_udp(port, reply)
            result.banner = _clean(reply)
            return result
        return result
    except OSError:
        result.state = FILTERED
        return result
    finally:
        sock.close()


# --- many ports ------------------------------------------------------------
def scan_ports(ip, ports, timeout=None, workers=100, grab_banner=True,
               progress=None, protocol="tcp", server_name=None):
    """Scan ports concurrently. Returns results sorted by port number.

    protocol is "tcp" or "udp". server_name is the hostname the target was
    given as (see probe_port). progress, if given, is called as
    progress(done, total) from the calling thread only, so it is safe to print.
    """
    if protocol == "udp":
        def job(port):
            return probe_udp_port(ip, port, timeout or UDP_TIMEOUT)
    else:
        def job(port):
            return probe_port(ip, port, timeout or DEFAULT_TIMEOUT, grab_banner, server_name)

    workers = max(1, min(workers, 300))
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(job, p) for p in ports]
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
