"""Passive security assessment of a domain, written up as a disclosure-ready report.

Only passive checks run here: one HTTP GET (headers), one TLS handshake,
public DNS records (SPF/DMARC/DKIM), RDAP/WHOIS and security.txt. No port
scanning and nothing that a normal visitor would not also do, so the report
can be produced for any public website. Severities are rough guidance for a
report, not CVSS scores; every finding should be verified by hand.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from netshield import disclosure, dnsclient, mailsec, scanning, webaudit, whois
from netshield.webaudit import FAIL, INFO, PASS, WARN

CHECKS = ("disclosure", "headers", "tls", "mail", "whois")
SEVERITIES = ("High", "Medium", "Low", "Informational")

# (finding name, status) -> severity. Anything not listed: FAIL -> Low, WARN -> Informational.
_SEVERITY = {
    ("HTTPS", FAIL): "High",
    ("Cookies", FAIL): "Medium",
    ("SPF", FAIL): "Medium",
    ("DMARC", FAIL): "Medium",
    ("Content-Security-Policy", FAIL): "Low",
    ("Strict-Transport-Security", FAIL): "Low",
    ("Clickjacking protection", FAIL): "Low",
    ("SPF", WARN): "Low",
    ("DMARC", WARN): "Low",
    ("Expiry", WARN): "Medium",
}

_IMPACT = {
    "HTTPS": "Traffic can be read or changed by anyone on the network path (public Wi-Fi, ISP).",
    "Strict-Transport-Security": "A user's first visit or any http:// link can be downgraded to plain HTTP "
                                 "(SSL stripping), exposing session cookies and credentials.",
    "Content-Security-Policy": "There is no second line of defence if an XSS bug exists: injected scripts "
                               "run with full access to the page.",
    "Clickjacking protection": "Another site can load the page in an invisible frame and trick users into "
                               "clicking buttons (e.g. confirming actions).",
    "X-Content-Type-Options": "Browsers may guess content types and run uploaded files as scripts.",
    "Referrer-Policy": "Full URLs, including tokens in query strings, can leak to third-party sites.",
    "Permissions-Policy": "Embedded content is not restricted from requesting camera, microphone or location.",
    "Cookies": "Cookies without Secure can travel over plain HTTP; without HttpOnly they can be read by "
               "injected scripts; without SameSite they are sent with cross-site requests (CSRF).",
    "Information disclosure": "Exact software versions let attackers look up known vulnerabilities (CVEs).",
    "SPF": "Mail servers cannot tell real mail from forged mail, so attackers can send phishing that appears "
           "to come from this domain.",
    "DMARC": "Receivers are not told to reject forged mail from this domain, which makes phishing in the "
             "company's name easier.",
    "Expiry": "If the registration lapses, anyone can register the domain and take over its email and website.",
    "TLS": "Users see certificate warnings or connections can be intercepted, depending on the issue.",
    "security.txt": "Security researchers have no clear, official way to report problems.",
    "Expires": "An expired security.txt suggests the listed contacts may no longer be monitored.",
}

# Fixes for findings whose check does not provide one itself.
_FIX = {
    "Expiry": "Renew the domain registration and enable auto-renew with the registrar.",
    "Expires": "Update the Expires field of security.txt (at most one year ahead) and check the contacts.",
    "Contact": "Add at least one Contact field (mailto: or https:) to security.txt.",
    "Information disclosure": "Remove version numbers from Server and X-Powered-By style headers.",
}

_TLS_SEVERITY =(("expired", "High"), ("not trusted", "Medium"), ("self-signed", "Medium"),
                 ("outdated protocol", "Medium"), ("weak cipher", "Medium"), ("expires in", "Low"))


@dataclass
class ReportItem:
    title: str
    severity: str
    check: str
    evidence: str
    impact: str = ""
    fix: str = ""
    reproduce: str = ""


@dataclass
class Assessment:
    target: str
    started: str
    items: list = field(default_factory=list)
    grades: dict = field(default_factory=dict)       # check -> "B (72/100)"
    errors: dict = field(default_factory=dict)       # check -> message
    contact: list = field(default_factory=list)      # lines about where to report
    notes: list = field(default_factory=list)

    def counts(self):
        return {s: sum(i.severity == s for i in self.items) for s in SEVERITIES}

    def to_dict(self):
        return asdict(self)


def _reproduce(check, domain):
    return {
        "headers": f"curl -sI https://{domain}",
        "tls": f"openssl s_client -connect {domain}:443 -servername {domain}",
        "mail": f"nslookup -type=TXT {domain}  and  nslookup -type=TXT _dmarc.{domain}",
        "whois": f"python main.py whois {domain}",
        "disclosure": f"curl -s https://{domain}/.well-known/security.txt",
    }.get(check, "")


def _severity(name, status):
    return _SEVERITY.get((name, status), "Low" if status == FAIL else "Informational")


def _items_from_findings(findings, check, domain):
    items = []
    for finding in findings:
        if finding.status not in (FAIL, WARN):
            continue
        items.append(ReportItem(
            title=f"{finding.name}: {finding.detail.split(';')[0].split(' (')[0]}",
            severity=_severity(finding.name, finding.status), check=check, evidence=finding.detail,
            impact=_IMPACT.get(finding.name, ""), fix=finding.fix or _FIX.get(finding.name, ""),
            reproduce=_reproduce(check, domain)))
    return items


def _tls_items(info, domain):
    items = []
    for text in info.get("findings", []):
        severity = next((level for key, level in _TLS_SEVERITY if key in text), "Low")
        items.append(ReportItem(
            title=f"TLS certificate: {text}", severity=severity, check="tls",
            evidence=f"{info['version']}, subject {info['subject']}, issuer {info['issuer']}, "
                     f"valid until {info['not_after']}",
            impact=_IMPACT["TLS"], fix="Renew or replace the certificate with one from a trusted CA, "
                                      "and serve TLS 1.2+ only.", reproduce=_reproduce("tls", domain)))
    return items


def assess(domain, checks=CHECKS, timeout=10.0, dns_server=None):
    """Run the passive checks and collect report items. Never raises for a single check."""
    domain = domain.strip().lower().split("://")[-1].split("/")[0].rstrip(".")
    result = Assessment(target=domain, started=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    if "disclosure" in checks:
        try:
            found = disclosure.find_security_txt(domain, timeout=timeout)
            if found:
                result.contact.append(f"security.txt: {found.url}")
                result.contact += [f"Contact: {c}" for c in found.get("contact")]
                result.contact += [f"Policy: {p}" for p in found.get("policy")]
                result.items += _items_from_findings(found.findings, "disclosure", domain)
            else:
                result.contact.append("No security.txt found. Look for an official bug bounty or "
                                      "vulnerability disclosure programme before reporting.")
                result.items.append(ReportItem(
                    title="No security.txt (RFC 9116)", severity="Informational", check="disclosure",
                    evidence=f"https://{domain}/.well-known/security.txt was not found",
                    impact=_IMPACT["security.txt"], fix="Publish /.well-known/security.txt with Contact "
                                                        "and Expires fields.",
                    reproduce=_reproduce("disclosure", domain)))
        except disclosure.DisclosureError as error:
            result.errors["disclosure"] = str(error)

    if "headers" in checks:
        try:
            report = webaudit.audit_url(domain, timeout=timeout)
            result.grades["headers"] = f"{report.grade} ({report.score}/100)"
            result.items += _items_from_findings(report.findings, "headers", domain)
        except webaudit.FetchError as error:
            result.errors["headers"] = str(error)

    if "tls" in checks:
        try:
            ip = scanning.resolve_target(domain)
            info = scanning.tls_info(ip, 443, timeout=timeout, server_name=domain)
            result.grades["tls"] = "no issues" if not info["findings"] else f"{len(info['findings'])} issue(s)"
            result.items += _tls_items(info, domain)
        except (ValueError, OSError) as error:
            result.errors["tls"] = str(error)

    if "mail" in checks:
        try:
            report = mailsec.audit_domain(domain, server=dns_server)
            result.grades["mail"] = f"{report.grade} ({report.score}/100)"
            result.items += _items_from_findings(report.findings, "mail", domain)
            if report.resolver_warning:
                result.notes.append(report.resolver_warning)
        except dnsclient.DnsError as error:
            result.errors["mail"] = str(error)

    if "whois" in checks:
        try:
            info = whois.lookup(domain, timeout=timeout)
            result.grades["whois"] = f"registered until {info.expires[:10] or 'unknown'}"
            result.items += _items_from_findings(info.findings, "whois", domain)
        except whois.WhoisError as error:
            result.errors["whois"] = str(error)

    result.items.sort(key=lambda item: SEVERITIES.index(item.severity))
    return result


# --- rendering ---------------------------------------------------------------
def to_markdown(result):
    counts = result.counts()
    lines = [
        f"# Security assessment: {result.target}",
        "",
        f"- **Date (UTC):** {result.started}",
        "- **Tool:** NetShield-CLI (passive checks only)",
        "- **Scope:** public information only: one HTTP request, one TLS handshake, public DNS records, "
        "RDAP/WHOIS and security.txt. No scanning, no exploitation, no access to non-public data.",
        "",
        "> Severities are approximate guidance, not CVSS scores. Verify every finding manually before "
        "reporting, and report only through the organisation's official channel.",
        "",
        "## Where to report",
        "",
    ]
    lines += [f"- {line}" for line in result.contact] or ["- (not checked)"]
    lines += ["", "## Summary", "", "| Severity | Count |", "|---|---|"]
    lines += [f"| {severity} | {counts[severity]} |" for severity in SEVERITIES]
    if result.grades:
        lines += ["", "| Check | Result |", "|---|---|"]
        lines += [f"| {check} | {grade} |" for check, grade in result.grades.items()]
    lines += ["", "## Findings", ""]
    if not result.items:
        lines.append("No issues found by the passive checks.")
    for number, item in enumerate(result.items, start=1):
        lines += [f"### {number}. [{item.severity}] {item.title}", "",
                  f"- **Check:** {item.check}", f"- **Evidence:** `{item.evidence}`"]
        if item.impact:
            lines.append(f"- **Impact:** {item.impact}")
        if item.reproduce:
            lines.append(f"- **How to verify:** `{item.reproduce}`")
        if item.fix:
            lines.append(f"- **Recommended fix:** {item.fix}")
        lines.append("")
    if result.errors or result.notes:
        lines += ["## Notes", ""]
        lines += [f"- {check} check could not run: {message}" for check, message in result.errors.items()]
        lines += [f"- {note}" for note in result.notes]
        lines.append("")
    return "\n".join(lines)


def to_json(result):
    return json.dumps(result.to_dict(), indent=2)
