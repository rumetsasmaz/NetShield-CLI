import http.server
import json
import ssl
import threading
from pathlib import Path

import pytest

from netshield import cli, webaudit as wa

DATA = Path(__file__).parent / "data"

GOOD = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
    ("Content-Security-Policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=()"),
    ("Set-Cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
    ("Server", "nginx"),
]


def find(findings, name):
    return next(f for f in findings if f.name == name)


# --- whole-page grading ------------------------------------------------------
def test_well_configured_site_gets_a_plus():
    findings, score, grade = wa.analyze_headers(GOOD, "https://example.com")
    assert (score, grade) == (100, "A+")
    assert all(f.status in (wa.PASS, wa.INFO) for f in findings)


def test_bare_site_fails():
    findings, score, grade = wa.analyze_headers([("Server", "Apache/2.4.41 (Ubuntu)")], "https://example.com")
    assert grade == "F"
    for name in ("Strict-Transport-Security", "Content-Security-Policy",
                 "Clickjacking protection", "X-Content-Type-Options"):
        assert find(findings, name).status == wa.FAIL
    assert "Apache/2.4.41" in find(findings, "Information disclosure").detail


def test_plain_http_without_redirect():
    findings, _score, _grade = wa.analyze_headers([], "http://example.com")
    assert find(findings, "HTTPS").status == wa.FAIL
    assert find(findings, "Strict-Transport-Security").status == wa.INFO   # n/a on HTTP


def test_http_redirecting_to_https_passes():
    findings, _s, _g = wa.analyze_headers(GOOD, "http://example.com", "https://example.com/")
    assert find(findings, "HTTPS").status == wa.PASS


def test_https_downgrade_fails():
    findings, _s, _g = wa.analyze_headers([], "https://example.com", "http://example.com/")
    assert find(findings, "HTTPS").status == wa.FAIL


def test_header_names_are_case_insensitive():
    lower = [(name.lower(), value) for name, value in GOOD]
    assert wa.analyze_headers(lower, "https://example.com")[1] == 100


@pytest.mark.parametrize("score, grade", [(100, "A+"), (95, "A+"), (90, "A"), (70, "B"),
                                          (55, "C"), (40, "D"), (39, "F"), (0, "F")])
def test_grades(score, grade):
    assert wa.grade_for(score) == grade


# --- HSTS ------------------------------------------------------------------
@pytest.mark.parametrize("value, status", [
    ("max-age=31536000; includeSubDomains", wa.PASS),
    ("max-age=15552000", wa.PASS),
    ("max-age=86400", wa.WARN),
    ("max-age=0", wa.FAIL),
    ("includeSubDomains", wa.FAIL),
    ('max-age="31536000"', wa.PASS),
    ("max-age=abc", wa.FAIL),
])
def test_hsts(value, status):
    findings, _s, _g = wa.analyze_headers([("Strict-Transport-Security", value)], "https://x.test")
    assert find(findings, "Strict-Transport-Security").status == status


def test_parse_hsts():
    assert wa.parse_hsts("max-age=60; includeSubDomains; preload") == (60, True, True)
    assert wa.parse_hsts("MAX-AGE=5") == (5, False, False)


# --- CSP -------------------------------------------------------------------
@pytest.mark.parametrize("policy, status", [
    ("default-src 'self'", wa.PASS),
    ("script-src 'self' 'unsafe-inline'", wa.WARN),
    ("script-src 'self' 'unsafe-inline' 'nonce-abc123'", wa.PASS),     # nonce neutralises unsafe-inline
    ("script-src 'strict-dynamic' 'unsafe-inline' 'sha256-xyz'", wa.PASS),
    ("default-src 'self'; script-src 'unsafe-eval'", wa.WARN),
    ("default-src *", wa.WARN),
    ("script-src https:", wa.WARN),
    ("img-src 'self'", wa.WARN),                                         # scripts unrestricted
])
def test_csp(policy, status):
    findings, _s, _g = wa.analyze_headers([("Content-Security-Policy", policy)], "https://x.test")
    assert find(findings, "Content-Security-Policy").status == status


def test_csp_report_only_is_not_enforced():
    findings, _s, _g = wa.analyze_headers([("Content-Security-Policy-Report-Only", "default-src 'self'")],
                                          "https://x.test")
    csp = find(findings, "Content-Security-Policy")
    assert csp.status == wa.WARN and "Report-Only" in csp.detail


def test_parse_csp():
    assert wa.parse_csp("default-src 'self'; img-src a b;;") == {"default-src": ["'self'"], "img-src": ["a", "b"]}


# --- framing / nosniff / referrer / permissions ------------------------------
@pytest.mark.parametrize("pairs, status", [
    ([("X-Frame-Options", "DENY")], wa.PASS),
    ([("X-Frame-Options", "sameorigin")], wa.PASS),
    ([("X-Frame-Options", "ALLOW-FROM https://a.test")], wa.WARN),
    ([("Content-Security-Policy", "frame-ancestors 'self'")], wa.PASS),
    ([], wa.FAIL),
])
def test_clickjacking(pairs, status):
    assert find(wa.analyze_headers(pairs, "https://x.test")[0], "Clickjacking protection").status == status


@pytest.mark.parametrize("value, status", [("nosniff", wa.PASS), ("NoSniff", wa.PASS), ("yes", wa.WARN)])
def test_nosniff(value, status):
    findings = wa.analyze_headers([("X-Content-Type-Options", value)], "https://x.test")[0]
    assert find(findings, "X-Content-Type-Options").status == status


@pytest.mark.parametrize("value, status", [
    ("no-referrer", wa.PASS), ("unsafe-url", wa.WARN),
    ("no-referrer-when-downgrade", wa.WARN), ("unsafe-url, strict-origin", wa.PASS),   # last value wins
])
def test_referrer_policy(value, status):
    findings = wa.analyze_headers([("Referrer-Policy", value)], "https://x.test")[0]
    assert find(findings, "Referrer-Policy").status == status


def test_missing_referrer_and_permissions_are_warnings():
    findings = wa.analyze_headers([], "https://x.test")[0]
    assert find(findings, "Referrer-Policy").status == wa.WARN
    assert find(findings, "Permissions-Policy").status == wa.WARN
    assert find(wa.analyze_headers([("Feature-Policy", "camera 'none'")], "https://x.test")[0],
                "Permissions-Policy").status == wa.PASS


# --- cookies / leaks -------------------------------------------------------
def test_cookie_flags():
    findings = wa.analyze_headers([("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Strict"),
                                   ("Set-Cookie", "b=2; HttpOnly")], "https://x.test")[0]
    cookies = find(findings, "Cookies")
    assert cookies.status == wa.FAIL                       # b has no Secure on an HTTPS site
    assert "b: missing Secure, SameSite" in cookies.detail and "a:" not in cookies.detail


def test_cookie_without_secure_on_http_is_only_a_warning():
    cookies = find(wa.analyze_headers([("Set-Cookie", "b=2")], "http://x.test")[0], "Cookies")
    assert cookies.status == wa.WARN


def test_no_cookies_is_informational():
    assert find(wa.analyze_headers([], "https://x.test")[0], "Cookies").status == wa.INFO


@pytest.mark.parametrize("pairs, status", [
    ([("Server", "nginx")], wa.PASS),
    ([("Server", "nginx/1.18.0")], wa.WARN),
    ([("X-Powered-By", "PHP/8.1")], wa.WARN),
    ([("X-AspNet-Version", "4.0.30319")], wa.WARN),
])
def test_information_disclosure(pairs, status):
    assert find(wa.analyze_headers(pairs, "https://x.test")[0], "Information disclosure").status == status


# --- URL handling ------------------------------------------------------------
def test_normalize_url():
    assert wa.normalize_url("example.com") == "https://example.com"
    assert wa.normalize_url(" http://a.test/x ") == "http://a.test/x"
    for bad in ("", "ftp://a.test", "file:///etc/passwd", "https://"):
        with pytest.raises(wa.FetchError):
            wa.normalize_url(bad)


# --- live fetching against local servers -----------------------------------
def make_handler(routes):
    """routes: path -> (status, [(header, value)])"""

    class Handler(http.server.BaseHTTPRequestHandler):
        def version_string(self):
            # The default "BaseHTTP/0.6 Python/3.x" would (correctly) count as a version leak.
            return "testserver"

        def do_GET(self):
            status, headers = routes.get(self.path, (404, []))
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    return Handler


@pytest.fixture
def web_server():
    servers = []

    def start(routes, tls=False):
        server = http.server.HTTPServer(("127.0.0.1", 0), make_handler(routes))
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(DATA / "localhost.pem", DATA / "localhost.key")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        scheme = "https" if tls else "http"
        return f"{scheme}://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def test_audit_follows_redirects_and_reads_final_headers(web_server):
    base = web_server({"/": (301, [("Location", "/home")]),
                       "/home": (200, [("X-Content-Type-Options", "nosniff"),
                                       ("Set-Cookie", "a=1; HttpOnly"),
                                       ("Set-Cookie", "b=2; HttpOnly; SameSite=Lax")])})
    report = wa.audit_url(base + "/", timeout=5)
    assert report.status == 200 and report.url.endswith("/home")
    assert report.redirects == [(base + "/", 301)]
    assert find(report.findings, "X-Content-Type-Options").status == wa.PASS
    assert len([v for k, v in report.headers if k.lower() == "set-cookie"]) == 2   # both cookies kept


def test_audit_reports_error_pages_too(web_server):
    base = web_server({})
    report = wa.audit_url(base + "/missing", timeout=5)
    assert report.status == 404 and report.findings


def test_redirect_loop_is_a_fetch_error(web_server):
    base = web_server({"/a": (302, [("Location", "/b")]), "/b": (302, [("Location", "/a")])})
    with pytest.raises(wa.FetchError, match="redirect loop"):
        wa.audit_url(base + "/a", timeout=5)


def test_too_many_redirects_is_a_fetch_error(web_server):
    routes = {f"/{i}": (302, [("Location", f"/{i + 1}")]) for i in range(10)}
    base = web_server(routes)
    with pytest.raises(wa.FetchError, match="redirect"):
        wa.audit_url(base + "/0", timeout=5)


def test_python_server_version_is_flagged_as_a_leak():
    pairs = [("Server", "BaseHTTP/0.6 Python/3.14.7")]
    assert find(wa.analyze_headers(pairs, "https://x.test")[0], "Information disclosure").status == wa.WARN


def test_https_self_signed_needs_insecure(web_server):
    base = web_server({"/": (200, GOOD)}, tls=True)
    with pytest.raises(wa.FetchError, match="certificate verification failed"):
        wa.audit_url(base + "/", timeout=5)
    report = wa.audit_url(base + "/", timeout=5, insecure=True)
    assert report.score == 100 and report.grade == "A+"


def test_connection_refused_is_a_fetch_error(closed_udp_port):
    with pytest.raises(wa.FetchError, match="could not connect"):
        wa.audit_url(f"http://127.0.0.1:{closed_udp_port}/", timeout=5)


# --- CLI -------------------------------------------------------------------
def test_cli_headers_table_json_and_fail_under(web_server, tmp_path, capsys):
    base = web_server({"/": (200, [("X-Frame-Options", "DENY")])})
    assert cli.run(["headers", base + "/"]) == 0
    out = capsys.readouterr().out
    assert "[PASS] Clickjacking protection" in out and "[FAIL] HTTPS" in out and "Grade:" in out

    path = tmp_path / "h.json"
    assert cli.run(["headers", base + "/", "--format", "json", "-o", str(path)]) == 0
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["grade"] == wa.grade_for(data["score"]) and data["findings"]

    assert cli.run(["headers", base + "/", "--fail-under", "90"]) == 1
    assert cli.run(["headers", base + "/", "--fail-under", "0"]) == 0


def test_cli_headers_show_headers_and_errors(web_server, capsys):
    base = web_server({"/": (200, [("X-Custom", "hello")])})
    assert cli.run(["headers", base + "/", "--show-headers"]) == 0
    assert "X-Custom: hello" in capsys.readouterr().out
    assert cli.run(["headers", "ftp://a.test"]) == 1
