import json

import pytest

from netshield import cli, disclosure, dnsclient, mailsec, report, scanning, webaudit, whois
from netshield.webaudit import FAIL, INFO, PASS, WARN, Finding


@pytest.fixture
def fake_checks(monkeypatch):
    """Replace every network-facing check with canned results; records which ran."""
    ran = []

    def security_txt(domain, timeout=10.0):
        ran.append("disclosure")
        found = disclosure.SecurityTxt(url=f"https://{domain}/.well-known/security.txt",
                                       fields={"contact": ["mailto:sec@shop.test"], "policy": ["https://shop.test/vdp"]})
        found.findings = [Finding("Contact", PASS, "mailto:sec@shop.test"),
                          Finding("Expires", WARN, "expired on 2020-01-01T00:00:00Z")]
        return found

    def headers(url, timeout=10.0, insecure=False):
        ran.append("headers")
        findings = [Finding("HTTPS", FAIL, "served over plain HTTP and never redirects to HTTPS", 15, "Redirect."),
                    Finding("X-Content-Type-Options", PASS, "nosniff", 10),
                    Finding("Content-Security-Policy", FAIL, "header is missing", 20, "Add a CSP."),
                    Finding("Information disclosure", WARN, "reveals software details: Server: nginx/1.18.0", 5)]
        return webaudit.HeaderReport(requested_url=url, url=url, status=200, findings=findings, score=30, grade="F")

    def tls(ip, port=443, timeout=10.0, server_name=None):
        ran.append("tls")
        return {"version": "TLSv1.2", "subject": "shop.test", "issuer": "shop.test",
                "not_after": "Jan  1 00:00:00 2020 GMT", "findings": ["certificate expired 100 day(s) ago",
                                                                    "self-signed certificate"]}

    def mail(domain, server=None, **kwargs):
        ran.append("mail")
        result = mailsec.MailReport(domain=domain, resolver="fake")
        result.findings = [Finding("SPF", WARN, "softfail (~all) without an enforcing DMARC policy", 35, "Use -all."),
                           Finding("DMARC", FAIL, "no DMARC record", 35, "Publish DMARC."),
                           Finding("MX", INFO, "10 mx.shop.test")]
        result.score, result.grade = 17, "F"
        result.resolver_warning = "resolver invents answers"
        return result

    def registration(domain, timeout=10.0):
        ran.append("whois")
        info = whois.DomainInfo(domain=domain, source="rdap", expires="2026-12-01T00:00:00Z")
        info.findings = [Finding("Expiry", WARN, "expires in 13 day(s)")]
        return info

    monkeypatch.setattr(disclosure, "find_security_txt", security_txt)
    monkeypatch.setattr(webaudit, "audit_url", headers)
    monkeypatch.setattr(scanning, "resolve_target", lambda target: "192.0.2.10")
    monkeypatch.setattr(scanning, "tls_info", tls)
    monkeypatch.setattr(mailsec, "audit_domain", mail)
    monkeypatch.setattr(whois, "lookup", registration)
    return ran


def test_assess_collects_and_sorts_by_severity(fake_checks):
    result = report.assess("https://Shop.test/login")
    assert result.target == "shop.test"
    assert fake_checks == ["disclosure", "headers", "tls", "mail", "whois"]
    severities = [item.severity for item in result.items]
    assert severities == sorted(severities, key=report.SEVERITIES.index)
    titles = {item.title: item.severity for item in result.items}
    assert titles["HTTPS: served over plain HTTP and never redirects to HTTPS"] == "High"
    assert titles["TLS certificate: certificate expired 100 day(s) ago"] == "High"
    assert titles["TLS certificate: self-signed certificate"] == "Medium"
    assert titles["DMARC: no DMARC record"] == "Medium"
    assert titles["Expiry: expires in 13 day(s)"] == "Medium"
    assert titles["Information disclosure: reveals software details: Server: nginx/1.18.0"] == "Informational"
    assert not any("nosniff" in title or title.startswith("MX") for title in titles)   # PASS / INFO skipped
    assert result.counts() == {"High": 2, "Medium": 3, "Low": 2, "Informational": 2}


def test_contact_grades_and_notes(fake_checks):
    result = report.assess("shop.test")
    assert result.contact[0] == "security.txt: https://shop.test/.well-known/security.txt"
    assert "Contact: mailto:sec@shop.test" in result.contact and "Policy: https://shop.test/vdp" in result.contact
    assert result.grades["headers"] == "F (30/100)" and result.grades["tls"] == "2 issue(s)"
    assert result.grades["whois"] == "registered until 2026-12-01"
    assert result.notes == ["resolver invents answers"]


def test_every_reported_item_has_impact_fix_and_verification(fake_checks):
    for item in report.assess("shop.test").items:
        assert item.evidence and item.reproduce
        if item.severity in ("High", "Medium"):
            assert item.impact and item.fix, item.title


def test_failed_check_is_recorded_not_raised(fake_checks, monkeypatch):
    def broken(url, timeout=10.0, insecure=False):
        raise webaudit.FetchError("could not connect: refused")

    monkeypatch.setattr(webaudit, "audit_url", broken)
    monkeypatch.setattr(mailsec, "audit_domain", lambda d, server=None, **k: (_ for _ in ()).throw(
        dnsclient.DnsError("no DNS server answered")))
    result = report.assess("shop.test")
    assert result.errors == {"headers": "could not connect: refused", "mail": "no DNS server answered"}
    assert "headers check could not run" in report.to_markdown(result)


def test_subset_of_checks(fake_checks):
    report.assess("shop.test", checks=("tls",))
    assert fake_checks == ["tls"]


def test_missing_security_txt_becomes_informational_item(fake_checks, monkeypatch):
    monkeypatch.setattr(disclosure, "find_security_txt", lambda domain, timeout=10.0: None)
    result = report.assess("shop.test", checks=("disclosure",))
    assert result.items[0].title == "No security.txt (RFC 9116)" and result.items[0].severity == "Informational"
    assert "bug bounty" in result.contact[0]


def test_markdown_structure(fake_checks):
    text = report.to_markdown(report.assess("shop.test"))
    for heading in ("# Security assessment: shop.test", "## Where to report", "## Summary",
                    "## Findings", "## Notes", "| High | 2 |"):
        assert heading in text
    assert "### 1. [High]" in text and "**How to verify:**" in text and "passive checks only" in text
    assert "not CVSS scores" in text


def test_json_round_trip(fake_checks):
    data = json.loads(report.to_json(report.assess("shop.test")))
    assert data["target"] == "shop.test" and len(data["items"]) == 9


def test_clean_site_says_so(monkeypatch):
    monkeypatch.setattr(webaudit, "audit_url", lambda url, timeout=10.0, insecure=False: webaudit.HeaderReport(
        requested_url=url, url=url, status=200, findings=[Finding("HTTPS", PASS, "ok", 15)], score=100, grade="A+"))
    text = report.to_markdown(report.assess("good.test", checks=("headers",)))
    assert "No issues found by the passive checks." in text


# --- CLI --------------------------------------------------------------------------
def test_cli_report_to_file(fake_checks, tmp_path, capsys):
    out = tmp_path / "shop-report.md"
    assert cli.run(["report", "shop.test", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("# Security assessment: shop.test")
    assert "2 High, 3 Medium, 2 Low, 2 Informational" in capsys.readouterr().out


def test_cli_report_json_and_bad_checks(fake_checks, capsys):
    assert cli.run(["report", "shop.test", "--format", "json", "--checks", "headers,mail"]) == 0
    assert json.loads(capsys.readouterr().out)["grades"].keys() == {"headers", "mail"}
    assert cli.run(["report", "shop.test", "--checks", "headers,portscan"]) == 1
