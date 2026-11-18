"""Find where to report a vulnerability: security.txt (RFC 9116).

A security.txt file is how an organisation says "send security reports here,
under these rules". Reading it is the first step of responsible disclosure.
"""

import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from netshield.webaudit import FAIL, INFO, PASS, WARN, Finding

LOCATIONS = ("/.well-known/security.txt", "/security.txt")   # second one is the legacy location
_MAX_BYTES = 64 * 1024
_MULTI = ("contact", "encryption", "acknowledgments", "policy", "hiring", "canonical")


class DisclosureError(ValueError):
    pass


@dataclass
class SecurityTxt:
    url: str = ""
    fields: dict = field(default_factory=dict)     # name -> list of values
    signed: bool = False
    findings: list = field(default_factory=list)

    def get(self, name):
        return self.fields.get(name.lower(), [])

    def to_dict(self):
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


def parse_security_txt(text):
    """Return (fields dict of lists, signed). Ignores comments and PGP armour lines."""
    fields, signed = {}, "-----BEGIN PGP SIGNED MESSAGE-----" in text
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-----") or line.lower().startswith("hash:"):
            continue
        name, sep, value = line.partition(":")
        if not sep or " " in name.strip():
            continue
        fields.setdefault(name.strip().lower(), []).append(value.strip())
    return fields, signed


def _parse_expires(value):
    text = value.strip()
    if text[-1:] in ("Z", "z"):          # RFC 3339 allows lower-case 'z' (Google and GitHub use it)
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def analyze_security_txt(fields, signed, now=None):
    now = now or datetime.now(timezone.utc)
    findings = []
    contacts = fields.get("contact", [])
    if contacts:
        findings.append(Finding("Contact", PASS, ", ".join(contacts)))
    else:
        findings.append(Finding("Contact", FAIL, "no Contact field (required by RFC 9116)"))
    expires = fields.get("expires", [])
    if not expires:
        findings.append(Finding("Expires", WARN, "no Expires field (required by RFC 9116)"))
    else:
        moment = _parse_expires(expires[0])
        if moment is None:
            findings.append(Finding("Expires", WARN, f"cannot parse '{expires[0]}'"))
        elif moment < now:
            findings.append(Finding("Expires", WARN, f"expired on {expires[0]}; the contact may be outdated"))
        else:
            findings.append(Finding("Expires", PASS, expires[0]))
    for name in ("policy", "encryption", "acknowledgments", "preferred-languages", "hiring"):
        values = fields.get(name, [])
        if values:
            findings.append(Finding(name.title(), INFO, ", ".join(values)))
    findings.append(Finding("Signature", INFO, "PGP-signed" if signed else "not signed"))
    return findings


def find_security_txt(domain, timeout=10.0, insecure=False):
    """Try the standard locations over HTTPS. Returns SecurityTxt or None if absent.

    insecure=True skips certificate checks (only for local test servers).
    Raises DisclosureError only when the host cannot be reached at all.
    """
    domain = domain.strip().split("://")[-1].split("/")[0]
    if not domain:
        raise DisclosureError("no domain given")
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    reached = False
    for path in LOCATIONS:
        url = f"https://{domain}{path}"
        request = urllib.request.Request(url, headers={"User-Agent": "NetShield-CLI security.txt check"})
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                reached = True
                content_type = response.headers.get("Content-Type", "")
                body = response.read(_MAX_BYTES).decode("utf-8", errors="replace")
        except urllib.error.HTTPError:
            reached = True
            continue
        except (urllib.error.URLError, OSError, ValueError):
            continue
        if "text/plain" not in content_type.lower():
            continue          # many sites answer every path with an HTML page
        fields, signed = parse_security_txt(body)
        if not fields:
            continue
        result = SecurityTxt(url=url, fields=fields, signed=signed)
        result.findings = analyze_security_txt(fields, signed)
        return result
    if not reached:
        raise DisclosureError(f"could not reach https://{domain}")
    return None


_MARK = {PASS: "[PASS]", WARN: "[WARN]", FAIL: "[FAIL]", INFO: "[INFO]"}


def report_lines(domain, result):
    """[(status, text)] for a find_security_txt() result (None = not found)."""
    if result is None:
        return [(WARN, line) if i == 0 else (INFO, line) for i, line in enumerate(NO_FILE_ADVICE)]
    lines = [(INFO, f"security.txt for {domain}: {result.url}"), (INFO, "")]
    for finding in result.findings:
        lines.append((finding.status, f"{_MARK[finding.status]} {finding.name}: {finding.detail}"))
    lines += [(INFO, ""), (INFO, "Report through the Contact above and follow the Policy, if one is given.")]
    return lines


NO_FILE_ADVICE = [
    "No security.txt found. Before reporting anything:",
    "  1. Search for an official bug bounty or disclosure program (HackerOne, Bugcrowd, Intigriti,",
    "     YesWeHack, or the company's own 'security' / 'responsible disclosure' page).",
    "  2. Only test what that program lists as in scope. Testing without permission can be a crime",
    "     (in Turkey: TCK 243-244), even with good intentions.",
    "  3. If there is no program, report only what you saw passively, through an official channel,",
    "     and never access, change or keep data that is not yours.",
]
