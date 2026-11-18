import socket
import struct

import pytest

from netshield import cli, dnsclient as dc, mailsec as ms
from netshield.webaudit import FAIL, INFO, PASS, WARN
from tests.dnsfake import FakeDnsServer, fake_resolver, reply, rr, txt_rdata


# --- encoding ------------------------------------------------------------------
def test_encode_name():
    assert dc.encode_name("www.example.com.") == b"\x03www\x07example\x03com\x00"
    assert dc.encode_name("türkiye.gov.tr") == b"\x0exn--trkiye-3ya\x03gov\x02tr\x00"   # IDNA (punycode)
    assert dc.encode_name("") == b"\x00"


@pytest.mark.parametrize("bad", ["a..b", "x" * 64 + ".com", ("a" * 60 + ".") * 5 + "com"])
def test_encode_name_rejects(bad):
    with pytest.raises(dc.DnsError):
        dc.encode_name(bad)


def test_build_query_rejects_unknown_type():
    with pytest.raises(dc.DnsError):
        dc.build_query("example.com", "BOGUS", 1)


# --- decoding --------------------------------------------------------------------
def test_parse_all_record_types():
    query = dc.build_query("example.com", "A", 0x1234)
    soa = (b"\x02ns\xc0\x0c" + b"\x05admin\xc0\x0c" + struct.pack("!IIIII", 7, 1, 2, 3, 4))
    answers = [
        rr(1, socket.inet_aton("93.184.216.34")),
        rr(28, socket.inet_pton(socket.AF_INET6, "2001:db8::1")),
        rr(15, struct.pack("!H", 10) + b"\x04mail\xc0\x0c"),
        rr(16, txt_rdata(b"v=spf1 include:a.test ", b"-all")),        # split strings are joined
        rr(5, b"\x03www\xc0\x0c"),
        rr(6, soa),
        rr(257, b"\x00\x05issue" + b"letsencrypt.org"),
        rr(99, b"\xab\xcd"),
    ]
    answer, truncated = dc.parse_response(reply(query, answers), 0x1234)
    assert not truncated and answer.rcode == "NOERROR"
    values = {r.type: r.value for r in answer.records}
    assert values["A"] == "93.184.216.34"
    assert values["AAAA"] == "2001:db8::1"
    assert values["MX"] == "10 mail.example.com"
    assert values["TXT"] == "v=spf1 include:a.test -all"
    assert values["CNAME"] == "www.example.com"
    assert values["SOA"].startswith("ns.example.com admin.example.com serial=7")
    assert values["CAA"] == '0 issue "letsencrypt.org"'
    assert values["99"] == "abcd"


def test_parse_rejects_mismatched_or_short_replies():
    query = dc.build_query("example.com", "A", 1)
    with pytest.raises(dc.DnsError):
        dc.parse_response(reply(query), 2)                 # wrong id
    with pytest.raises(dc.DnsError):
        dc.parse_response(b"\x00\x01", 1)
    with pytest.raises(dc.DnsError):
        dc.parse_response(query, 1)                        # QR bit not set: not a reply


def test_parse_nxdomain_and_truncation_flag():
    query = dc.build_query("nope.test", "A", 5)
    answer, truncated = dc.parse_response(reply(query, rcode=3), 5)
    assert answer.rcode == "NXDOMAIN" and answer.records == []
    _answer, truncated = dc.parse_response(reply(query, truncated=True), 5)
    assert truncated


# --- talking to a (fake) server ------------------------------------------------------
@pytest.fixture
def dns_server():
    servers = []

    def start(handler, host="127.0.0.1"):
        server = FakeDnsServer(handler, host)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def test_query_over_udp(dns_server):
    server = dns_server(lambda q, proto: reply(q, [rr(1, socket.inet_aton("10.1.2.3"))]))
    answer = dc.query("host.test", "A", server="127.0.0.1", port=server.port, timeout=2)
    assert answer.values("A") == ["10.1.2.3"] and answer.server == "127.0.0.1"


def test_truncated_udp_reply_falls_back_to_tcp(dns_server):
    big = [rr(16, txt_rdata(b"x" * 200)) for _ in range(5)]

    def handler(q, proto):
        return reply(q, truncated=True) if proto == "udp" else reply(q, big)

    server = dns_server(handler)
    answer = dc.query("big.test", "TXT", server="127.0.0.1", port=server.port, timeout=2)
    assert len(answer.values("TXT")) == 5
    assert [proto for proto, _ in server.queries] == ["udp", "tcp"]


def test_failing_servers_are_skipped_in_order(monkeypatch):
    """SERVFAIL, REFUSED and silence each move on to the next configured resolver."""
    behaviour = {"10.0.0.1": "servfail", "10.0.0.2": "timeout", "10.0.0.3": "refused", "10.0.0.4": "ok"}
    asked = []

    def fake_udp(server, payload, timeout, port=53):
        asked.append(server)
        kind = behaviour[server]
        if kind == "timeout":
            raise TimeoutError("timed out")
        rcode = {"servfail": 2, "refused": 5, "ok": 0}[kind]
        answers = [rr(1, socket.inet_aton("10.9.9.9"))] if kind == "ok" else []
        return reply(payload, answers, rcode=rcode)

    monkeypatch.setattr(dc, "_ask_udp", fake_udp)
    answer = dc.query("x.test", "A", servers=list(behaviour))
    assert answer.values("A") == ["10.9.9.9"] and answer.server == "10.0.0.4"
    assert asked == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]

    behaviour["10.0.0.4"] = "servfail"
    with pytest.raises(dc.DnsError, match="SERVFAIL"):
        dc.query("x.test", "A", servers=list(behaviour))


def test_silent_server_raises_dns_error(dns_server):
    server = dns_server(lambda q, proto: None)
    with pytest.raises(dc.DnsError, match="no DNS server answered"):
        dc.query("x.test", "A", server="127.0.0.1", port=server.port, timeout=0.3)


def test_split_servers():
    assert dc._split_servers("10.0.0.1, 10.0.0.2 10.0.0.3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert dc._split_servers("") == []


# --- SPF ---------------------------------------------------------------------------
@pytest.mark.parametrize("txt, status", [
    (["v=spf1 include:_spf.google.com -all"], PASS),
    (["v=spf1 mx ~all"], PASS),
    (["v=spf1 mx ?all"], WARN),
    (["v=spf1 mx"], WARN),
    (["v=spf1 redirect=_spf.example.com"], PASS),
    (["v=spf1 +all"], FAIL),
    (["v=spf1 all"], FAIL),                                # no qualifier means "+"
    (["v=spf1 ptr -all"], WARN),
    (["v=spf1 -all", "v=spf1 mx -all"], FAIL),             # two records
    ([], FAIL),
    (["google-site-verification=abc", "v=spf10 nonsense"], FAIL),   # not real SPF records
])
def test_spf(txt, status):
    assert ms.analyze_spf(txt).status == status


@pytest.mark.parametrize("policy, status, text", [
    ("reject", PASS, "backed by DMARC reject"),
    ("quarantine", PASS, "backed by DMARC quarantine"),
    ("none", WARN, "only marked, not blocked"),       # regression: was PASS with "fine with DMARC"
    (None, WARN, "only marked, not blocked"),
])
def test_softfail_depends_on_dmarc(policy, status, text):
    finding = ms.contextualize_softfail(ms.analyze_spf(["v=spf1 include:x.test ~all"]), policy)
    assert finding.status == status and text in finding.detail


def test_hardfail_and_failures_are_not_changed_by_context():
    hard = ms.analyze_spf(["v=spf1 -all"])
    assert ms.contextualize_softfail(hard, None) is hard
    broken = ms.analyze_spf(["v=spf1 +all"])
    assert ms.contextualize_softfail(broken, "reject") is broken


def test_softfail_with_monitoring_only_dmarc_is_graded_down(monkeypatch):
    """The real-world case: ~all together with DMARC p=none."""
    monkeypatch.setattr(dc, "query", fake_resolver({
        ("shop.test", "TXT"): ["v=spf1 include:_spf.host.test ~all"],
        ("_dmarc.shop.test", "TXT"): ["v=DMARC1; p=none"],
        ("shop.test", "MX"): ["10 mx.host.test"],
    }))
    report = ms.audit_domain("shop.test", check_dkim=False)
    statuses = {f.name: f.status for f in report.findings}
    assert statuses["SPF"] == WARN and statuses["DMARC"] == WARN
    assert report.score == 50 and report.grade == "D"


def test_spf_lookup_limit():
    record = "v=spf1 " + " ".join(f"include:s{i}.test" for i in range(11)) + " -all"
    finding = ms.analyze_spf([record])
    assert finding.status == FAIL and "11 DNS lookups" in finding.detail
    assert ms._spf_lookup_count("v=spf1 a mx ip4:1.2.3.4 include:x.test exists:y.test -all") == 4
    # 'all', 'ip4', 'ip6' never cost a lookup; 'a:host', 'mx/24', 'redirect=' do
    assert ms._spf_lookup_count("v=spf1 ip4:1.2.3.4 ip6:::1 -all") == 0
    assert ms._spf_lookup_count("v=spf1 a:mail.test mx/24 redirect=_spf.test") == 3


# --- DMARC -----------------------------------------------------------------------------
@pytest.mark.parametrize("txt, status", [
    (["v=DMARC1; p=reject; rua=mailto:d@x.test"], PASS),
    (["v=DMARC1; p=quarantine"], PASS),
    (["v=DMARC1; p=none; rua=mailto:d@x.test"], WARN),
    (["v=DMARC1; p=reject; pct=50"], WARN),
    (["v=DMARC1; p=reject; sp=none"], WARN),
    (["v=DMARC1; rua=mailto:d@x.test"], FAIL),             # no policy
    (["v=DMARC1; p=bogus"], FAIL),
    (["v=DMARC1; p=reject", "v=DMARC1; p=none"], FAIL),
    ([], FAIL),
])
def test_dmarc(txt, status):
    assert ms.analyze_dmarc(txt).status == status


def test_dmarc_notes_missing_reports():
    assert "no rua=" in ms.analyze_dmarc(["v=DMARC1; p=reject"]).detail


# --- DKIM, MX, scoring -------------------------------------------------------------------
def test_dkim_key_state():
    assert ms.dkim_key_state("v=DKIM1; k=rsa; p=MIGfMA0GCSq") == "valid"
    assert ms.dkim_key_state("v=DKIM1; p=") == "revoked"
    assert ms.dkim_key_state("v=spf1 -all") is None


def test_null_mx():
    assert ms.is_null_mx(["0 "]) and ms.is_null_mx(["0 ."])
    assert not ms.is_null_mx(["0 mail.example.com"]) and not ms.is_null_mx([])
    assert "null MX" in ms.analyze_mx(["0 "]).detail


def test_scores():
    assert ms.score_findings([ms.analyze_spf(["v=spf1 -all"]),
                              ms.analyze_dmarc(["v=DMARC1; p=reject"])]) == (100, "A+")
    assert ms.score_findings([ms.analyze_spf([]), ms.analyze_dmarc([])]) == (0, "F")
    assert ms.score_findings([ms.analyze_spf(["v=spf1 -all"]), ms.analyze_dmarc([])])[0] == 50


# --- full audit with a fake resolver ------------------------------------------------------
GOOD_DOMAIN = {
    ("good.test", "TXT"): ["v=spf1 include:_spf.mail.test -all", "some-verification=1"],
    ("good.test", "MX"): ["10 mx.good.test"],
    ("good.test", "CAA"): ['0 issue "letsencrypt.org"'],
    ("_dmarc.good.test", "TXT"): ["v=DMARC1; p=reject; rua=mailto:r@good.test"],
    ("selector1._domainkey.good.test", "TXT"): ["v=DKIM1; k=rsa; p=MIIBIjANBg"],
    ("default._domainkey.good.test", "TXT"): ["v=DKIM1; p="],
}


def test_audit_domain_good(monkeypatch):
    monkeypatch.setattr(dc, "query", fake_resolver(GOOD_DOMAIN))
    report = ms.audit_domain("https://GOOD.test/some/path")
    assert report.domain == "good.test"
    assert (report.score, report.grade) == (100, "A+")
    assert report.dkim_selectors == ["selector1"]
    assert report.resolver_warning == ""
    assert ms.report_lines(report)[-1][1].endswith("Grade: A+")


def test_subdomain_inherits_parent_dmarc(monkeypatch):
    """www.good.test has no _dmarc record of its own: the parent's policy applies (RFC 7489)."""
    records = dict(GOOD_DOMAIN)
    records[("_dmarc.good.test", "TXT")] = ["v=DMARC1; p=quarantine; sp=reject; rua=mailto:r@good.test"]
    monkeypatch.setattr(dc, "query", fake_resolver(records))
    report = ms.audit_domain("www.good.test", check_dkim=False)
    dmarc = next(f for f in report.findings if f.name == "DMARC")
    assert dmarc.status == PASS and "sp=reject" in dmarc.detail and "inherited from _dmarc.good.test" in dmarc.detail
    assert report.dmarc_inherited_from == "good.test"
    spf = next(f for f in report.findings if f.name == "SPF")
    assert spf.status == WARN and "still stopped by the DMARC policy (reject)" in spf.detail   # mitigated
    assert report.grade != "F"


def test_inherited_policy_uses_p_when_there_is_no_sp():
    assert ms.effective_policy(["v=DMARC1; p=reject"], inherited_from="parent.test") == "reject"
    assert ms.effective_policy(["v=DMARC1; p=reject; sp=none"], inherited_from="parent.test") == "none"
    assert ms.effective_policy(["v=DMARC1; p=reject; sp=none"]) == "reject"
    finding = ms.analyze_dmarc(["v=DMARC1; p=reject; sp=none"], inherited_from="parent.test")
    assert finding.status == WARN


def test_find_dmarc_walk_stops_at_two_labels(monkeypatch):
    asked = []
    real = fake_resolver({})

    def recording(name, record_type="A", *args, **kwargs):
        asked.append(name)
        return real(name, record_type, *args, **kwargs)

    monkeypatch.setattr(dc, "query", recording)
    assert ms.find_dmarc("a.b.example.test") == ([], None)
    assert asked == ["_dmarc.a.b.example.test", "_dmarc.b.example.test", "_dmarc.example.test"]


def test_missing_spf_stays_a_failure_without_enforcing_dmarc():
    failed = ms.analyze_spf([])
    assert ms.mitigate_missing_spf(failed, "none").status == FAIL
    assert ms.mitigate_missing_spf(failed, None).status == FAIL
    assert ms.mitigate_missing_spf(ms.analyze_spf(["v=spf1 +all"]), "reject").status == FAIL  # only *missing* SPF


def test_wildcard_dkim_is_not_reported_as_keys(monkeypatch):
    class WildcardTxt(dict):
        def get(self, key, default=None):
            name, record_type = key
            if name.endswith("._domainkey.good.test") and record_type == "TXT":
                return ["v=DKIM1; p=MIIBIjANBgkqh"]
            return super().get(key, default)

    monkeypatch.setattr(dc, "query", fake_resolver(WildcardTxt(GOOD_DOMAIN)))
    report = ms.audit_domain("good.test")
    dkim = next(f for f in report.findings if f.name == "DKIM")
    assert report.dkim_selectors == [] and dkim.status == INFO and "wildcard" in dkim.detail


def test_audit_domain_unprotected(monkeypatch):
    monkeypatch.setattr(dc, "query", fake_resolver({("bare.test", "TXT"): ["hello"]}))
    report = ms.audit_domain("bare.test", check_dkim=False)
    assert report.grade == "F"
    statuses = {f.name: f.status for f in report.findings}
    assert statuses["SPF"] == FAIL and statuses["DMARC"] == FAIL and statuses["DKIM"] == INFO


def test_audit_domain_nxdomain(monkeypatch):
    monkeypatch.setattr(dc, "query", fake_resolver({}, nxdomain={"missing.test"}))
    with pytest.raises(dc.DnsError, match="does not exist"):
        ms.audit_domain("missing.test")


def test_resolver_hijack_detection(monkeypatch):
    def lying(name, record_type="A", server=None, timeout=3.0, **kw):
        return dc.Answer("NOERROR", [dc.Record(name, record_type, 60, "192.168.1.1")], "liar")

    monkeypatch.setattr(dc, "query", lying)
    assert ms.resolver_rewrites_nxdomain() is True
    monkeypatch.setattr(dc, "query", fake_resolver({}))
    assert ms.resolver_rewrites_nxdomain() is False


# --- CLI -----------------------------------------------------------------------------------
def test_cli_mail_and_dns(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(dc, "query", fake_resolver(GOOD_DOMAIN))
    assert cli.run(["mail", "good.test"]) == 0
    out = capsys.readouterr().out
    assert "[PASS] SPF" in out and "[PASS] DMARC" in out and "Grade: A+" in out

    report = tmp_path / "mail.json"
    assert cli.run(["mail", "good.test", "--format", "json", "-o", str(report)]) == 0
    assert '"grade": "A+"' in report.read_text(encoding="utf-8")

    assert cli.run(["dns", "good.test", "-t", "mx,txt"]) == 0
    out = capsys.readouterr().out
    assert "MX     10 mx.good.test" in out and "v=spf1" in out


def test_cli_mail_fail_under_and_errors(monkeypatch):
    monkeypatch.setattr(dc, "query", fake_resolver({("bare.test", "TXT"): []}, nxdomain={"gone.test"}))
    assert cli.run(["mail", "bare.test", "--no-dkim", "--fail-under", "50"]) == 1
    assert cli.run(["mail", "gone.test"]) == 1
    assert cli.run(["dns", "gone.test"]) == 0          # prints the NXDOMAIN message
    assert cli.run(["mail", "x.test", "--server", "not-an-ip"]) == 1
