"""Domain registration lookup: RDAP (modern, JSON) with classic WHOIS fallback.

RDAP servers are found through IANA's bootstrap file. TLDs without RDAP
(for example .tr) fall back to WHOIS on port 43, following IANA's referral.
`parse_rdap` and `parse_whois_text` are pure functions over the replies.
"""

import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from netshield.webaudit import INFO, PASS, WARN, Finding

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
IANA_WHOIS = "whois.iana.org"
_HEADERS = {"User-Agent": "NetShield-CLI RDAP lookup", "Accept": "application/rdap+json, application/json"}
_bootstrap_cache = {}


class WhoisError(ValueError):
    pass


@dataclass
class DomainInfo:
    domain: str
    source: str                       # "rdap" or "whois"
    server: str = ""
    registrar: str = ""
    created: str = ""
    expires: str = ""
    updated: str = ""
    status: list = field(default_factory=list)
    nameservers: list = field(default_factory=list)
    abuse_email: str = ""
    dnssec: str = ""                  # "signed", "unsigned" or ""
    raw: list = field(default_factory=list)      # interesting WHOIS lines (fallback only)
    findings: list = field(default_factory=list)

    def to_dict(self):
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


# --- RDAP --------------------------------------------------------------------------
def rdap_base_for(domain, bootstrap):
    """Pick the RDAP base URL for a domain from IANA's bootstrap data (longest TLD match)."""
    labels = domain.lower().split(".")
    best, best_length = None, 0
    for tlds, urls in bootstrap.get("services", []):
        for tld in tlds:
            tld_labels = tld.lower().split(".")
            if labels[-len(tld_labels):] == tld_labels and len(tld_labels) > best_length:
                https = [u for u in urls if u.startswith("https://")]
                best, best_length = (https or urls)[0], len(tld_labels)
    if best and not best.endswith("/"):
        best += "/"
    return best


def _vcard_value(entity, key):
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2:
        return ""
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == key:
            value = item[3]
            return value if isinstance(value, str) else ""
    return ""


def _walk_entities(entities):
    for entity in entities or []:
        yield entity
        yield from _walk_entities(entity.get("entities"))


def parse_rdap(data, domain):
    info = DomainInfo(domain=data.get("ldhName", domain).lower(), source="rdap")
    for event in data.get("events", []):
        action, date = event.get("eventAction", ""), event.get("eventDate", "")
        if action == "registration":
            info.created = date
        elif action == "expiration":
            info.expires = date
        elif action == "last changed":
            info.updated = date
    info.status = list(data.get("status", []))
    info.nameservers = sorted({ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])
                               if ns.get("ldhName")})
    for entity in _walk_entities(data.get("entities")):
        roles = entity.get("roles", [])
        if "registrar" in roles and not info.registrar:
            info.registrar = _vcard_value(entity, "fn")
        if "abuse" in roles and not info.abuse_email:
            info.abuse_email = _vcard_value(entity, "email")
    secure = data.get("secureDNS")
    if isinstance(secure, dict) and "delegationSigned" in secure:
        info.dnssec = "signed" if secure["delegationSigned"] else "unsigned"
    return info


def _get_json(url, timeout):
    request = urllib.request.Request(url, headers=_HEADERS)
    with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
        return json.loads(response.read(2_000_000).decode("utf-8", errors="replace"))


def load_bootstrap(timeout=10.0):
    if "dns" not in _bootstrap_cache:
        _bootstrap_cache["dns"] = _get_json(BOOTSTRAP_URL, timeout)
    return _bootstrap_cache["dns"]


# --- classic WHOIS -------------------------------------------------------------------
_INTERESTING = ("registrar", "creation", "created", "registered", "expir", "updated", "changed",
                "name server", "nameserver", "nserver", "status", "abuse", "dnssec")


def whois_query(server, query, timeout=10.0, port=43):
    with socket.create_connection((server, port), timeout=timeout) as sock:
        sock.sendall(query.encode("idna") + b"\r\n")
        chunks = []
        while sum(map(len, chunks)) < 500_000:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def whois_referral(iana_text):
    for line in iana_text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() in ("refer", "whois") and value.strip():
            return value.strip()
    return None


def parse_whois_text(text, domain, server=""):
    """Best-effort parser for the many WHOIS formats: "Key: value" lines (gTLD
    style) and sectioned layouts such as TRABIS (.tr) with "** Section:" headers,
    dot-padded keys and indented lists."""
    info = DomainInfo(domain=domain, source="whois", server=server)
    section = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            if section == "domain servers":
                section = ""
            continue
        if line.startswith(("%", "#", ">>>")):
            continue
        if line.startswith("**"):
            header, _, rest = line.lstrip("* ").partition(":")
            section = header.strip().lower()
            if rest.strip():
                info.raw.append(f"{header.strip()}: {rest.strip()}")
            continue
        key, sep, value = line.partition(":")
        name = key.strip().rstrip(". \t").lower()
        value = value.strip().rstrip(".").strip()
        if section == "domain servers" and (not sep or " " in key.strip()):
            info.nameservers.append(line.split()[0].lower().rstrip("."))
            continue
        if not sep or not value:
            continue
        if any(word in name for word in _INTERESTING) or section == "registrar" and name == "organization name":
            info.raw.append(f"{key.strip().rstrip('. ')}: {value}")
        if name in ("registrar", "registrar name", "sponsoring registrar") or \
                (section == "registrar" and name == "organization name"):
            info.registrar = info.registrar or value
        elif ("creation" in name or name in ("created", "created on", "registered on", "registered")) \
                and not info.created:
            info.created = value
        elif "expir" in name and not info.expires:
            info.expires = value
        elif name in ("updated date", "last updated", "changed", "last update time") and not info.updated:
            info.updated = value
        elif name in ("name server", "nameserver", "nserver"):
            info.nameservers.append(value.split()[0].lower().rstrip("."))
        elif "abuse" in name and "@" in value and not info.abuse_email:
            info.abuse_email = value
        elif name in ("domain status", "status"):
            info.status.append(value.split()[0])
        elif "transfer" in name and "lock" in value.lower():
            info.status.append("transfer locked")
    info.nameservers = sorted(set(info.nameservers))
    info.raw = info.raw[:25]
    return info


# --- analysis ----------------------------------------------------------------------
_DATE_FORMATS = ("%Y-%b-%d", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d", "%d/%m/%Y", "%Y%m%d")


def _parse_date(text):
    text = text.strip().rstrip(".")
    for candidate in (text, text.replace("Z", "+00:00").replace("z", "+00:00"), text[:10]):
        try:
            moment = datetime.fromisoformat(candidate)
            return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    for pattern in _DATE_FORMATS:                      # e.g. TRABIS: 2027-Mar-10
        try:
            return datetime.strptime(text.split()[0], pattern).replace(tzinfo=timezone.utc)
        except (ValueError, IndexError):
            continue
    return None


def analyze(info, now=None):
    now = now or datetime.now(timezone.utc)
    findings = []
    expires = _parse_date(info.expires) if info.expires else None
    if expires:
        days = (expires - now).days
        if days < 0:
            findings.append(Finding("Expiry", WARN, f"registration expired {-days} day(s) ago"))
        elif days < 30:
            findings.append(Finding("Expiry", WARN, f"expires in {days} day(s); an expired domain can be "
                                                    "re-registered by anyone"))
        else:
            findings.append(Finding("Expiry", PASS, f"expires in {days} day(s)"))
    else:
        findings.append(Finding("Expiry", INFO, info.expires or "not published"))
    locks = [s for s in info.status if "transfer" in s.lower()
             and ("prohibited" in s.lower() or "lock" in s.lower())]
    findings.append(Finding("Transfer lock", PASS if locks else INFO,
                            "transfer lock is set" if locks else "no transfer lock listed"))
    if info.dnssec:
        findings.append(Finding("DNSSEC", PASS if info.dnssec == "signed" else INFO, info.dnssec))
    return findings


# --- lookup -------------------------------------------------------------------------
def _candidates(domain):
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]   # www.a.com -> a.com (stop at 2)


def lookup(domain, timeout=10.0):
    """RDAP first, classic WHOIS second. Subdomains are walked up to the registered name."""
    domain = domain.strip().lower().split("://")[-1].split("/")[0].rstrip(".")
    if "." not in domain:
        raise WhoisError("give a full domain name such as example.com")
    try:
        bootstrap = load_bootstrap(timeout)
    except (urllib.error.URLError, OSError, ValueError):
        bootstrap = {}
    base = rdap_base_for(domain, bootstrap)
    if base:
        for name in _candidates(domain):
            try:
                info = parse_rdap(_get_json(f"{base}domain/{name}", timeout), name)
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    continue
                raise WhoisError(f"RDAP server {base} answered {error.code}") from None
            except (urllib.error.URLError, OSError, ValueError) as error:
                raise WhoisError(f"RDAP lookup failed: {error}") from None
            info.server = base
            info.findings = analyze(info)
            return info
        raise WhoisError(f"{domain} is not registered (RDAP {base})")

    tld = domain.rsplit(".", 1)[-1]
    try:
        server = whois_referral(whois_query(IANA_WHOIS, tld, timeout))
        if not server:
            raise WhoisError(f"no RDAP or WHOIS server is known for .{tld}")
        for name in _candidates(domain)[::-1][:1] + _candidates(domain)[:-1]:
            text = whois_query(server, name, timeout)
            info = parse_whois_text(text, name, server)
            if info.raw:
                info.findings = analyze(info)
                return info
    except OSError as error:
        raise WhoisError(f"WHOIS lookup failed: {error}") from None
    raise WhoisError(f"{domain}: the WHOIS server {server} returned nothing useful")


_MARK = {PASS: "[PASS]", WARN: "[WARN]", INFO: "[INFO]"}


def report_lines(info):
    lines = [(INFO, f"Registration data for {info.domain}   ({info.source.upper()} via {info.server})"),
             (INFO, "")]
    for label, value in (("Registrar", info.registrar), ("Created", info.created),
                         ("Expires", info.expires), ("Updated", info.updated),
                         ("Name servers", ", ".join(info.nameservers)), ("Status", ", ".join(info.status)),
                         ("Abuse contact", info.abuse_email)):
        if value:
            lines.append((INFO, f"  {label:<14}: {value}"))
    lines.append((INFO, ""))
    for finding in info.findings:
        lines.append((finding.status, f"{_MARK.get(finding.status, '[INFO]')} {finding.name}: {finding.detail}"))
    if info.source == "whois" and info.raw:
        lines.append((INFO, "\nWHOIS lines:"))
        lines += [(INFO, f"  {line}") for line in info.raw]
    if info.abuse_email:
        lines.append((INFO, "\nNote: the abuse contact is the registrar's, for phishing/spam/malware on the "
                            "domain - not for vulnerabilities in the company's systems."))
    return lines
