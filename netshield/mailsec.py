"""Email spoofing protection audit: SPF, DMARC, DKIM, MX (+ CAA as info).

Only public DNS records are read. `analyze_spf` / `analyze_dmarc` are pure
functions over TXT strings; `audit_domain` performs the lookups.
"""

import secrets
from dataclasses import asdict, dataclass, field

from netshield import dnsclient
from netshield.webaudit import FAIL, INFO, PASS, WARN, Finding, grade_for

_FACTOR = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}
# Selectors used by common providers; DKIM keys can live under any name, so
# "not found" here never proves DKIM is missing.
COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2",
                         "dkim", "mail", "s1", "s2", "smtp", "mxvault")
_SPF_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists", "redirect"}


@dataclass
class MailReport:
    domain: str
    resolver: str
    mx: list = field(default_factory=list)
    spf: list = field(default_factory=list)
    dmarc: list = field(default_factory=list)
    dmarc_inherited_from: str = None
    dkim_selectors: list = field(default_factory=list)
    caa: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    resolver_warning: str = ""

    def to_dict(self):
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


# --- SPF -------------------------------------------------------------------
def spf_records(txt):
    return [t for t in txt if t.lower().startswith("v=spf1") and (len(t) == 6 or t[6] == " ")]


def _spf_lookup_count(record):
    """Top-level DNS lookups (RFC 7208 limit: 10). Nested includes are not followed."""
    count = 0
    for term in record.split()[1:]:
        term = term.lower().lstrip("+-~?")
        name = term.replace("=", ":").replace("/", ":").split(":", 1)[0]
        if name in _SPF_LOOKUP_MECHANISMS:
            count += 1
    return count


def analyze_spf(txt):
    records = spf_records(txt)
    fix = "Publish one TXT record such as: v=spf1 include:<your mail provider> -all"
    if not records:
        return Finding("SPF", FAIL, "no SPF record: anyone can send mail claiming to be this domain", 35, fix)
    if len(records) > 1:
        return Finding("SPF", FAIL, f"{len(records)} SPF records; more than one is invalid (RFC 7208)", 35,
                       "Merge them into a single v=spf1 record.")
    record = records[0]
    terms = [t.lower() for t in record.split()[1:]]
    issues, status = [], PASS
    all_terms = [t for t in terms if t.lstrip("+-~?") == "all"]
    qualifier = all_terms[-1][0] if all_terms and all_terms[-1][0] in "+-~?" else ("+" if all_terms else None)
    if qualifier == "+":
        return Finding("SPF", FAIL, f"'+all' lets every server on the internet send as this domain: {record}", 35,
                       "Replace +all with -all (or ~all while testing).")
    if qualifier is None and not any(t.startswith("redirect=") for t in terms):
        issues.append("no 'all' mechanism, so unlisted senders are not rejected")
        status = WARN
    elif qualifier == "?":
        issues.append("'?all' is neutral and gives no protection")
        status = WARN
    lookups = _spf_lookup_count(record)
    if lookups > 10:
        return Finding("SPF", FAIL, f"{lookups} DNS lookups (limit is 10, receivers treat it as an error)", 35,
                       "Flatten includes so the record needs 10 lookups or fewer.")
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        issues.append("'ptr' is deprecated and slow")
        status = WARN
    detail = record if not issues else "; ".join(issues) + f" ({record})"
    if status == PASS and qualifier == "~":
        detail = f"softfail (~all), fine together with an enforcing DMARC policy: {record}"
    return Finding("SPF", status, detail, 35, "" if status == PASS else fix)


# --- DMARC -----------------------------------------------------------------
def parse_dmarc(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, _, value = part.strip().partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags


def dmarc_records(txt):
    return [t for t in txt if t.replace(" ", "").lower().startswith("v=dmarc1")]


def effective_policy(txt, inherited_from=None):
    """The policy that applies: p=, or sp= when inherited by a subdomain. None if invalid."""
    records = dmarc_records(txt)
    if len(records) != 1:
        return None
    tags = parse_dmarc(records[0])
    policy = (tags.get("sp") if inherited_from and tags.get("sp") else tags.get("p", "")).lower()
    return policy if policy in ("none", "quarantine", "reject") else None


def analyze_dmarc(txt, inherited_from=None):
    """inherited_from: the parent domain whose _dmarc record applies (RFC 7489 §6.6.3)."""
    records = dmarc_records(txt)
    fix = "Publish at _dmarc.<domain>: v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>"
    if not records:
        return Finding("DMARC", FAIL, "no DMARC record (also none on parent domains): "
                                      "receivers get no policy for spoofed mail", 35, fix)
    if len(records) > 1:
        return Finding("DMARC", FAIL, "more than one DMARC record (receivers ignore all of them)", 35,
                       "Keep exactly one record at _dmarc.<domain>.")
    tags = parse_dmarc(records[0])
    if tags.get("p", "").lower() not in ("none", "quarantine", "reject"):
        return Finding("DMARC", FAIL, f"missing or invalid p= tag: {records[0]}", 35, fix)
    policy = effective_policy(txt, inherited_from) or tags["p"].lower()
    notes = [f"sp={policy}" if inherited_from and tags.get("sp") else f"p={policy}"]
    if inherited_from:
        notes.append(f"inherited from _dmarc.{inherited_from}")
    status = PASS
    if policy == "none":
        status = WARN
        notes.append("monitoring only, spoofed mail is still delivered")
    pct = tags.get("pct", "100")
    if pct.isdigit() and int(pct) < 100:
        status = WARN
        notes.append(f"pct={pct}: only part of the mail is covered")
    if not inherited_from and tags.get("sp", "").lower() == "none" and policy != "none":
        notes.append("sp=none leaves subdomains unprotected")
        status = WARN
    if "rua" not in tags:
        notes.append("no rua= (no aggregate reports)")
    return Finding("DMARC", status, "; ".join(notes), 35,
                   "" if status == PASS else "Move to p=quarantine or p=reject once reports look clean.")


def mitigate_missing_spf(spf_finding, policy):
    """No SPF on a name whose DMARC policy is enforcing: spoofing is still blocked."""
    if spf_finding.status == FAIL and spf_finding.detail.startswith("no SPF record") \
            and policy in ("quarantine", "reject"):
        return Finding("SPF", WARN, f"no SPF record for this name; spoofed mail is still stopped by the "
                                    f"DMARC policy ({policy}), but publish SPF if this name sends mail",
                       35, spf_finding.fix)
    return spf_finding


def find_dmarc(domain, server=None, timeout=3.0):
    """DMARC record for domain, else walk up parent names (not past two labels).

    Returns (records, inherited_from or None). The two-label stop approximates
    the "organisational domain" without a public-suffix list (e.g. for
    shop.example.co.uk the walk stops at co.uk, which has no DMARC record).
    """
    labels = domain.split(".")
    for index in range(len(labels) - 1):
        name = ".".join(labels[index:])
        records = dmarc_records(dnsclient.txt_records(f"_dmarc.{name}", server, timeout))
        if records:
            return records, (name if index else None)
    return [], None


# --- the rest ----------------------------------------------------------------
def is_null_mx(mx):
    """RFC 7505 'null MX' (preference 0, target '.'): the domain accepts no mail."""
    return len(mx) == 1 and mx[0].split(" ", 1)[0] == "0" and mx[0].split(" ", 1)[-1].strip(" .") == ""


def analyze_mx(mx):
    if is_null_mx(mx):
        return Finding("MX", INFO, "null MX (RFC 7505): this domain explicitly accepts no mail")
    if mx:
        return Finding("MX", INFO, ", ".join(mx[:5]))
    return Finding("MX", INFO, "no MX records: domain does not receive mail "
                               "(it should still publish 'v=spf1 -all' and DMARC p=reject)")


def dkim_key_state(record):
    """'valid', 'revoked' (empty p=, RFC 6376) or None if it is not a DKIM key record."""
    tags = parse_dmarc(record)             # same tag=value; syntax
    if "p" not in tags:
        return None
    return "valid" if tags["p"] else "revoked"


def analyze_dkim(selectors, revoked=(), wildcard=False):
    if wildcard:
        return Finding("DKIM", INFO, "a wildcard record answers every selector with a key, "
                                     "so real selectors cannot be told apart")
    if selectors:
        return Finding("DKIM", PASS, "key(s) found at selector(s): " + ", ".join(selectors), 0)
    if revoked:
        return Finding("DKIM", INFO, "only revoked keys (empty p=) at common selectors; "
                                     "typical for a domain that sends no mail")
    return Finding("DKIM", INFO, "no key at common selectors; the real selector may simply be different")


def analyze_caa(caa):
    if caa:
        return Finding("CAA", INFO, "; ".join(caa[:4]))
    return Finding("CAA", INFO, "no CAA records: any certificate authority may issue certificates")


def score_findings(findings):
    scored = [f for f in findings if f.weight]
    total = sum(f.weight for f in scored)
    score = round(100 * sum(f.weight * _FACTOR[f.status] for f in scored) / total) if total else 0
    return score, grade_for(score)


def resolver_rewrites_nxdomain(server=None, timeout=3.0, record_type="A"):
    """True if the resolver invents answers for names that cannot exist.

    Many ISP/router resolvers do this only for A records (to show an ad or
    error page), so check the record type you actually rely on.
    """
    name = f"nx-{secrets.token_hex(8)}.invalid"
    try:
        answer = dnsclient.query(name, record_type, server, timeout)
    except dnsclient.DnsError:
        return False
    return answer.rcode == "NOERROR" and bool(answer.values(record_type))


def audit_domain(domain, server=None, timeout=3.0, check_dkim=True):
    """Look up MX, SPF, DMARC, DKIM (common selectors) and CAA, then grade.

    Raises dnsclient.DnsError if the domain does not exist or no resolver answers.
    """
    domain = domain.strip().lower().rstrip(".")
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0]
    base = dnsclient.query(domain, "TXT", server, timeout)
    if base.rcode == "NXDOMAIN":
        raise dnsclient.DnsError(f"'{domain}' does not exist (NXDOMAIN)")

    report = MailReport(domain=domain, resolver=base.server)
    report.spf = spf_records(base.values("TXT"))
    report.mx = dnsclient.query(domain, "MX", server, timeout).values("MX")
    report.dmarc, report.dmarc_inherited_from = find_dmarc(domain, server, timeout)
    report.caa = dnsclient.query(domain, "CAA", server, timeout).values("CAA")
    revoked, wildcard = [], False
    if check_dkim:
        def key_states(selector):
            return {dkim_key_state(v) for v in
                    dnsclient.txt_records(f"{selector}._domainkey.{domain}", server, timeout)}

        # A selector that cannot exist: if it "has a key", the zone uses a wildcard.
        wildcard = "valid" in key_states(f"netshield-probe-{secrets.token_hex(4)}")
        for selector in () if wildcard else COMMON_DKIM_SELECTORS:
            states = key_states(selector)
            if "valid" in states:
                report.dkim_selectors.append(selector)
            elif "revoked" in states:
                revoked.append(selector)

    policy = effective_policy(report.dmarc, report.dmarc_inherited_from)
    report.findings = [mitigate_missing_spf(analyze_spf(base.values("TXT")), policy),
                       analyze_dmarc(report.dmarc, report.dmarc_inherited_from),
                       analyze_dkim(report.dkim_selectors, revoked, wildcard), analyze_mx(report.mx),
                       analyze_caa(report.caa)]
    report.score, report.grade = score_findings(report.findings)
    if resolver_rewrites_nxdomain(server, timeout, record_type="TXT"):
        report.resolver_warning = (f"resolver {base.server} invents TXT answers for names that do not "
                                   "exist; results may be wrong, try --server 1.1.1.1")
    return report


_MARK = {PASS: "[PASS]", WARN: "[WARN]", FAIL: "[FAIL]", INFO: "[INFO]"}


def report_lines(report):
    lines = [(INFO, f"Email security for {report.domain}   (resolver {report.resolver})")]
    if report.resolver_warning:
        lines.append((WARN, f"[!] {report.resolver_warning}"))
    lines.append((INFO, ""))
    for finding in report.findings:
        lines.append((finding.status, f"{_MARK[finding.status]} {finding.name}: {finding.detail}"))
        if finding.fix and finding.status in (WARN, FAIL):
            lines.append((INFO, f"        fix: {finding.fix}"))
    lines.append((INFO, ""))
    lines.append((PASS if report.score >= 70 else WARN if report.score >= 40 else FAIL,
                  f"Spoofing protection score: {report.score}/100   Grade: {report.grade}"))
    return lines
