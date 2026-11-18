"""HTTP security header audit (securityheaders.com style), standard library only.

Two layers: `analyze_headers` is a pure function over (name, value) pairs and
can be tested without a network; `audit_url` fetches a page and runs it.
The audit sends one ordinary GET request (like a browser would) and reads only
the response headers.
"""

import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"
_FACTOR = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}
_MAX_REDIRECTS = 5
HSTS_MIN_SECONDS = 15552000        # 180 days
HSTS_GOOD_SECONDS = 31536000       # 1 year


class FetchError(ValueError):
    """The page could not be fetched (bad URL, network or TLS failure)."""


@dataclass
class Finding:
    name: str
    status: str          # pass / warn / fail / info
    detail: str
    weight: int = 0      # 0 = informational, not scored
    fix: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class HeaderReport:
    requested_url: str
    url: str                                  # final URL after redirects
    status: int
    redirects: list = field(default_factory=list)   # [(url, status), ...]
    headers: list = field(default_factory=list)     # [(name, value), ...]
    findings: list = field(default_factory=list)
    score: int = 0
    grade: str = "F"

    def to_dict(self):
        data = asdict(self)
        data["findings"] = [f.to_dict() for f in self.findings]
        return data


class _Headers:
    def __init__(self, pairs):
        self.pairs = [(str(k).strip(), str(v).strip()) for k, v in pairs]

    def get(self, name):
        name = name.lower()
        for key, value in self.pairs:
            if key.lower() == name:
                return value
        return None

    def all(self, name):
        name = name.lower()
        return [value for key, value in self.pairs if key.lower() == name]


# --- parsers -----------------------------------------------------------------
def parse_hsts(value):
    """Return (max_age or None, include_subdomains, preload)."""
    max_age, subdomains, preload = None, False, False
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part[len("max-age="):].strip('"'))
            except ValueError:
                max_age = None
        elif part == "includesubdomains":
            subdomains = True
        elif part == "preload":
            preload = True
    return max_age, subdomains, preload


def parse_csp(value):
    """'default-src a b; img-src c' -> {'default-src': ['a','b'], 'img-src': ['c']}."""
    directives = {}
    for directive in value.split(";"):
        parts = directive.strip().split()
        if parts:
            directives.setdefault(parts[0].lower(), parts[1:])
    return directives


# --- individual checks -------------------------------------------------------
def _check_https(requested, final):
    if urllib.parse.urlparse(requested).scheme == "http":
        if urllib.parse.urlparse(final).scheme == "https":
            return Finding("HTTPS", PASS, "plain HTTP request redirects to HTTPS", 15)
        return Finding("HTTPS", FAIL, "served over plain HTTP and never redirects to HTTPS", 15,
                       "Redirect all HTTP traffic to HTTPS and enable HSTS.")
    if urllib.parse.urlparse(final).scheme == "http":
        return Finding("HTTPS", FAIL, "HTTPS request was redirected down to plain HTTP", 15,
                       "Never redirect from HTTPS to HTTP.")
    return Finding("HTTPS", PASS, "served over HTTPS", 15)


def _check_hsts(headers, https):
    value = headers.get("strict-transport-security")
    if not https:
        return Finding("Strict-Transport-Security", INFO, "not applicable on plain HTTP")
    fix = f"Add: Strict-Transport-Security: max-age={HSTS_GOOD_SECONDS}; includeSubDomains"
    if value is None:
        return Finding("Strict-Transport-Security", FAIL, "header is missing", 15, fix)
    max_age, subdomains, preload = parse_hsts(value)
    if max_age is None:
        return Finding("Strict-Transport-Security", FAIL, f"no valid max-age in '{value}'", 15, fix)
    if max_age == 0:
        return Finding("Strict-Transport-Security", FAIL, "max-age=0 switches HSTS off", 15, fix)
    notes = f"max-age={max_age}" + ("; includeSubDomains" if subdomains else "") + ("; preload" if preload else "")
    if max_age < HSTS_MIN_SECONDS:
        return Finding("Strict-Transport-Security", WARN,
                       f"{notes} is shorter than the recommended 6 months", 15, fix)
    return Finding("Strict-Transport-Security", PASS, notes, 15)


def _check_csp(headers):
    value = headers.get("content-security-policy")
    fix = "Add a Content-Security-Policy that restricts script-src (avoid 'unsafe-inline'/'unsafe-eval')."
    if value is None:
        if headers.get("content-security-policy-report-only") is not None:
            return Finding("Content-Security-Policy", WARN,
                           "only a Report-Only policy is set; nothing is enforced", 20, fix)
        return Finding("Content-Security-Policy", FAIL, "header is missing", 20, fix)
    directives = parse_csp(value)
    scripts = directives.get("script-src", directives.get("default-src"))
    if scripts is None:
        return Finding("Content-Security-Policy", WARN,
                       "no script-src or default-src, so scripts are not restricted", 20, fix)
    lowered = [s.lower() for s in scripts]
    # With a nonce/hash/'strict-dynamic', browsers ignore 'unsafe-inline'.
    protected = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or s == "'strict-dynamic'"
                    for s in lowered)
    issues = []
    if "'unsafe-inline'" in lowered and not protected:
        issues.append("'unsafe-inline' allows inline scripts")
    if "'unsafe-eval'" in lowered:
        issues.append("'unsafe-eval' allows eval()")
    if any(s in ("*", "http:", "https:", "data:") for s in lowered):
        issues.append("script sources include a wildcard or whole scheme")
    if issues:
        return Finding("Content-Security-Policy", WARN, "; ".join(issues), 20, fix)
    return Finding("Content-Security-Policy", PASS, f"{len(directives)} directive(s), scripts restricted", 20)


def _check_framing(headers):
    xfo = headers.get("x-frame-options")
    csp = headers.get("content-security-policy")
    if csp and "frame-ancestors" in parse_csp(csp):
        return Finding("Clickjacking protection", PASS, "CSP frame-ancestors is set", 10)
    if xfo:
        if xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
            return Finding("Clickjacking protection", PASS, f"X-Frame-Options: {xfo}", 10)
        return Finding("Clickjacking protection", WARN, f"X-Frame-Options '{xfo}' is obsolete or invalid", 10,
                       "Use X-Frame-Options: DENY|SAMEORIGIN or CSP frame-ancestors.")
    return Finding("Clickjacking protection", FAIL, "no X-Frame-Options and no CSP frame-ancestors", 10,
                   "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none').")


def _check_nosniff(headers):
    value = headers.get("x-content-type-options")
    if value is None:
        return Finding("X-Content-Type-Options", FAIL, "header is missing", 10,
                       "Add: X-Content-Type-Options: nosniff")
    if value.lower() != "nosniff":
        return Finding("X-Content-Type-Options", WARN, f"'{value}' is not 'nosniff'", 10,
                       "Use exactly: nosniff")
    return Finding("X-Content-Type-Options", PASS, "nosniff", 10)


def _check_referrer(headers):
    value = headers.get("referrer-policy")
    if value is None:
        return Finding("Referrer-Policy", WARN,
                       "missing (browsers fall back to strict-origin-when-cross-origin)", 5,
                       "Add: Referrer-Policy: strict-origin-when-cross-origin")
    effective = value.split(",")[-1].strip().lower()   # last supported value wins
    if effective in ("unsafe-url", "no-referrer-when-downgrade", ""):
        return Finding("Referrer-Policy", WARN, f"'{effective or value}' leaks full URLs to other sites", 5,
                       "Use strict-origin-when-cross-origin or stricter.")
    return Finding("Referrer-Policy", PASS, effective, 5)


def _check_permissions(headers):
    if headers.get("permissions-policy") or headers.get("feature-policy"):
        return Finding("Permissions-Policy", PASS, "set", 5)
    return Finding("Permissions-Policy", WARN, "missing (camera, microphone, geolocation... not restricted)", 5,
                   "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()")


def _check_coop(headers):
    value = headers.get("cross-origin-opener-policy")
    if value:
        return Finding("Cross-Origin-Opener-Policy", INFO, value)
    return Finding("Cross-Origin-Opener-Policy", INFO, "not set (optional hardening: same-origin)")


_VERSIONED = re.compile(r"\d+\.\d+")


def _check_leaks(headers):
    leaks = []
    server = headers.get("server")
    if server and _VERSIONED.search(server):
        leaks.append(f"Server: {server}")
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = headers.get(name)
        if value:
            leaks.append(f"{name}: {value}")
    if leaks:
        return Finding("Information disclosure", WARN, "reveals software details: " + ", ".join(leaks), 5,
                       "Remove version numbers and X-Powered-By-style headers.")
    return Finding("Information disclosure", PASS, "no version details in Server/X-Powered-By", 5)


def _check_cookies(headers, https):
    cookies = headers.all("set-cookie")
    if not cookies:
        return Finding("Cookies", INFO, "no cookies set")
    problems, serious = [], False
    for cookie in cookies:
        parts = [p.strip() for p in cookie.split(";")]
        name = parts[0].split("=")[0]
        flags = {p.split("=")[0].lower(): p for p in parts[1:]}
        missing = []
        if "secure" not in flags:
            missing.append("Secure")
            serious = serious or https
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            problems.append(f"{name}: missing {', '.join(missing)}")
    if not problems:
        return Finding("Cookies", PASS, f"{len(cookies)} cookie(s) with Secure, HttpOnly and SameSite", 10)
    return Finding("Cookies", FAIL if serious else WARN, "; ".join(problems), 10,
                   "Set Secure; HttpOnly; SameSite=Lax (or Strict) on every cookie.")


# --- analysis ----------------------------------------------------------------
def grade_for(score):
    for limit, grade in ((95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D")):
        if score >= limit:
            return grade
    return "F"


def analyze_headers(pairs, requested_url, final_url=None):
    """Run every check. Returns (findings, score 0-100, grade)."""
    final_url = final_url or requested_url
    headers = _Headers(pairs)
    https = urllib.parse.urlparse(final_url).scheme == "https"
    findings = [
        _check_https(requested_url, final_url),
        _check_hsts(headers, https),
        _check_csp(headers),
        _check_framing(headers),
        _check_nosniff(headers),
        _check_referrer(headers),
        _check_permissions(headers),
        _check_cookies(headers, https),
        _check_leaks(headers),
        _check_coop(headers),
    ]
    scored = [f for f in findings if f.weight]
    total = sum(f.weight for f in scored)
    earned = sum(f.weight * _FACTOR[f.status] for f in scored)
    score = round(100 * earned / total) if total else 0
    return findings, score, grade_for(score)


# --- fetching ----------------------------------------------------------------
def normalize_url(url):
    url = url.strip()
    if not url:
        raise FetchError("no URL given")
    if "://" not in url:
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise FetchError("only http:// and https:// URLs are supported")
    return url


class _Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = _MAX_REDIRECTS

    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append((req.full_url, code))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def audit_url(url, timeout=10.0, insecure=False):
    """Fetch url (one GET, following up to 5 redirects) and audit its headers.

    insecure=True skips certificate verification, for self-signed test servers.
    Raises FetchError on any network/URL/TLS failure.
    """
    url = normalize_url(url)
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    redirects = _Redirects()
    opener = urllib.request.build_opener(redirects, urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers={"User-Agent": "NetShield-CLI header audit",
                                                   "Accept": "*/*"})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:                # urllib gives up on loops / too many hops
            error.close()
            raise FetchError(f"redirect loop or more than {_MAX_REDIRECTS} redirects "
                             f"(last: {error.code} at {error.geturl()})") from None
        response = error                           # 4xx/5xx pages still carry useful headers
    except urllib.error.URLError as error:
        reason = error.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            raise FetchError(f"certificate verification failed: {reason.verify_message} "
                             "(use --insecure only for hosts you trust)") from None
        raise FetchError(f"could not connect: {reason}") from None
    except (TimeoutError, OSError, ValueError) as error:
        raise FetchError(f"could not fetch {url}: {error}") from None

    try:
        pairs = list(response.headers.items())
        status = response.status if hasattr(response, "status") else response.code
        final_url = response.geturl() if hasattr(response, "geturl") else url
    finally:
        response.close()

    findings, score, grade = analyze_headers(pairs, url, final_url)
    return HeaderReport(requested_url=url, url=final_url, status=status, redirects=redirects.chain,
                        headers=pairs, findings=findings, score=score, grade=grade)


# --- presentation ------------------------------------------------------------
_MARK = {PASS: "[PASS]", WARN: "[WARN]", FAIL: "[FAIL]", INFO: "[INFO]"}


def report_lines(report, show_headers=False):
    """Report as [(status, text)] so UIs can colour each line."""
    lines = [(INFO, f"Security headers for {report.requested_url}")]
    if report.redirects:
        lines.append((INFO, "Redirects: " + " -> ".join(f"{u} ({c})" for u, c in report.redirects)
                      + f" -> {report.url}"))
    lines.append((INFO, f"Final URL: {report.url}   HTTP status: {report.status}"))
    lines.append((INFO, ""))
    for finding in report.findings:
        lines.append((finding.status, f"{_MARK[finding.status]} {finding.name}: {finding.detail}"))
        if finding.fix and finding.status in (WARN, FAIL):
            lines.append((INFO, f"        fix: {finding.fix}"))
    lines.append((INFO, ""))
    lines.append((PASS if report.score >= 70 else WARN if report.score >= 40 else FAIL,
                  f"Score: {report.score}/100   Grade: {report.grade}"))
    if show_headers:
        lines.append((INFO, "\nResponse headers:"))
        lines += [(INFO, f"  {name}: {value}") for name, value in report.headers]
    return lines
