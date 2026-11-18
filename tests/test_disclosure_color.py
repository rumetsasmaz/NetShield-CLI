import http.server
import json
import ssl
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from netshield import cli, disclosure as ds, theme
from netshield.webaudit import FAIL, INFO, PASS, WARN

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data"

SAMPLE = """# Our security policy
Contact: mailto:security@example.test
Contact: https://example.test/report
Expires: 2099-01-01T00:00:00z
Policy: https://example.test/policy
Preferred-Languages: en, tr
"""


# --- parsing -----------------------------------------------------------------------
def test_parse_security_txt():
    fields, signed = ds.parse_security_txt(SAMPLE)
    assert fields["contact"] == ["mailto:security@example.test", "https://example.test/report"]
    assert fields["policy"] == ["https://example.test/policy"] and signed is False


def test_parse_signed_file_ignores_pgp_armour():
    text = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + SAMPLE +
            "-----BEGIN PGP SIGNATURE-----\nabcdef\n-----END PGP SIGNATURE-----\n")
    fields, signed = ds.parse_security_txt(text)
    assert signed and "hash" not in fields and len(fields["contact"]) == 2


@pytest.mark.parametrize("expires, status", [
    ("2099-01-01T00:00:00Z", PASS), ("2099-01-01T00:00:00z", PASS),     # lower-case z (Google, GitHub)
    ("2099-01-01T00:00:00+03:00", PASS), ("2020-01-01T00:00:00Z", WARN), ("next year", WARN),
])
def test_expires(expires, status):
    findings = ds.analyze_security_txt({"contact": ["mailto:a@b.test"], "expires": [expires]}, False,
                                       now=datetime(2026, 11, 18, tzinfo=timezone.utc))
    assert next(f for f in findings if f.name == "Expires").status == status


def test_missing_contact_and_expires():
    findings = {f.name: f.status for f in ds.analyze_security_txt({}, False)}
    assert findings["Contact"] == FAIL and findings["Expires"] == WARN and findings["Signature"] == INFO


# --- fetching from a local HTTPS server ------------------------------------------------
@pytest.fixture
def https_site():
    servers = []

    def start(routes):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                status, content_type, body = routes.get(self.path, (404, "text/html", b"not here"))
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(DATA / "localhost.pem", DATA / "localhost.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def test_finds_well_known_security_txt(https_site):
    host = https_site({"/.well-known/security.txt": (200, "text/plain; charset=utf-8", SAMPLE.encode())})
    result = ds.find_security_txt(host, timeout=5, insecure=True)
    assert result.url.endswith("/.well-known/security.txt")
    assert result.get("contact")[0] == "mailto:security@example.test"
    assert ds.report_lines(host, result)[2][0] == PASS


def test_falls_back_to_legacy_location(https_site):
    host = https_site({"/security.txt": (200, "text/plain", SAMPLE.encode())})
    assert ds.find_security_txt(host, timeout=5, insecure=True).url.endswith("/security.txt")


def test_html_catch_all_page_is_not_a_security_txt(https_site):
    page = (200, "text/html", b"<html>Contact: us</html>")
    host = https_site({"/.well-known/security.txt": page, "/security.txt": page})
    assert ds.find_security_txt(host, timeout=5, insecure=True) is None


def test_absent_file_gives_responsible_disclosure_advice(https_site):
    host = https_site({})
    assert ds.find_security_txt(host, timeout=5, insecure=True) is None
    lines = ds.report_lines(host, None)
    assert lines[0][0] == WARN and any("TCK 243" in text for _s, text in lines)


def test_unreachable_host(closed_udp_port):
    with pytest.raises(ds.DisclosureError):
        ds.find_security_txt(f"127.0.0.1:{closed_udp_port}", timeout=2)


def test_cli_disclosure_json_none(monkeypatch, capsys):
    monkeypatch.setattr(ds, "find_security_txt", lambda domain, timeout=10.0: None)
    assert cli.run(["disclosure", "nothing.test", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) is None


# --- colour --------------------------------------------------------------------------
def _run_cli(*args, env=None):
    import os
    environment = dict(os.environ, PYTHONIOENCODING="utf-8", **(env or {}))
    environment.pop("NO_COLOR", None) if not env or "NO_COLOR" not in env else None
    return subprocess.run([sys.executable, "main.py", *args], cwd=ROOT, capture_output=True,
                          env=environment, timeout=60).stdout


def test_color_always_never_and_auto_in_a_pipe():
    assert b"\x1b[" in _run_cli("--color", "always", "passwd", "--check", "abc")
    assert b"\x1b[" not in _run_cli("--color", "never", "passwd", "--check", "abc")
    assert b"\x1b[" not in _run_cli("passwd", "--check", "abc")            # auto: a pipe is not a terminal


def test_set_colour_auto_respects_terminal_and_no_color(monkeypatch):
    monkeypatch.setattr(theme, "_colour_enabled", theme._colour_enabled)   # restored after the test
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert theme.set_colour("auto") is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert theme.set_colour("auto") is False
    assert theme.set_colour("never") is False
    assert theme.paint("error", "x") == "x"
