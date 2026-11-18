import json
import socket
import threading
import urllib.error
from datetime import datetime, timezone

import pytest

from netshield import cli, whois as wh
from netshield.webaudit import INFO, PASS, WARN

BOOTSTRAP = {"services": [
    [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
    [["org"], ["http://rdap.example-org.test/", "https://rdap.pir.test/rdap"]],
    [["co.uk"], ["https://rdap.nominet.test/couk/"]],
    [["uk"], ["https://rdap.nominet.test/uk/"]],
]}

RDAP = {
    "ldhName": "GITHUB.COM",
    "status": ["client transfer prohibited", "client update prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "2007-10-09T18:20:50Z"},
               {"eventAction": "expiration", "eventDate": "2028-10-09T18:20:50Z"},
               {"eventAction": "last changed", "eventDate": "2024-09-07T09:16:32Z"}],
    "nameservers": [{"ldhName": "DNS1.P08.NSONE.NET"}, {"ldhName": "ns-520.awsdns-01.net"}],
    "secureDNS": {"delegationSigned": False},
    "entities": [{
        "roles": ["registrar"],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]],
        "entities": [{"roles": ["abuse"],
                      "vcardArray": ["vcard", [["email", {}, "text", "abusecomplaints@markmonitor.com"]]]}],
    }],
}

# Shape of a real TRABIS (.tr) reply
TRABIS = """** Domain Name: metu.edu.tr
Domain Status: Active
Frozen Status: -
Transfer Status: The domain is LOCKED to transfer.

** Registrar:
NIC Handle\t\t: tk1036
Organization Name\t: TRABİS KK
Phone\t\t\t: 90-312-2100060

** Domain Servers:
ns1.metu.edu.tr 144.122.144.171 2001:a98:30:cc::4:ad01
ns2.metu.edu.tr 144.122.144.170

** Additional Info:
Created on..............: 2003-Mar-11.
Expires on..............: 2027-Mar-10.
"""

GTLD = """   Domain Name: EXAMPLE.NET
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Updated Date: 2024-08-14T07:01:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2025-08-13T04:00:00Z
   Registrar Abuse Contact Email: abuse@example.test
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
>>> Last update of whois database: 2024-11-18T12:00:00Z <<<
"""

NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)


# --- RDAP --------------------------------------------------------------------------
def test_rdap_base_for_picks_longest_tld_and_https():
    assert wh.rdap_base_for("www.github.com", BOOTSTRAP) == "https://rdap.verisign.com/com/v1/"
    assert wh.rdap_base_for("shop.example.co.uk", BOOTSTRAP) == "https://rdap.nominet.test/couk/"
    assert wh.rdap_base_for("example.uk", BOOTSTRAP) == "https://rdap.nominet.test/uk/"
    assert wh.rdap_base_for("example.org", BOOTSTRAP) == "https://rdap.pir.test/rdap/"   # https, '/' added
    assert wh.rdap_base_for("metu.edu.tr", BOOTSTRAP) is None


def test_parse_rdap():
    info = wh.parse_rdap(RDAP, "github.com")
    assert info.domain == "github.com" and info.registrar == "MarkMonitor Inc."
    assert info.created.startswith("2007") and info.expires.startswith("2028")
    assert info.nameservers == ["dns1.p08.nsone.net", "ns-520.awsdns-01.net"]
    assert info.abuse_email == "abusecomplaints@markmonitor.com" and info.dnssec == "unsigned"


def test_parse_rdap_tolerates_missing_fields():
    info = wh.parse_rdap({"entities": [{"roles": ["registrar"], "vcardArray": "broken"}]}, "x.test")
    assert info.registrar == "" and info.status == [] and info.dnssec == ""


# --- WHOIS text --------------------------------------------------------------------
def test_parse_trabis_sections():
    info = wh.parse_whois_text(TRABIS, "metu.edu.tr", "whois.trabis.gov.tr")
    assert info.registrar == "TRABİS KK"
    assert (info.created, info.expires) == ("2003-Mar-11", "2027-Mar-10")
    assert info.nameservers == ["ns1.metu.edu.tr", "ns2.metu.edu.tr"]
    assert "transfer locked" in info.status


def test_parse_gtld_whois():
    info = wh.parse_whois_text(GTLD, "example.net")
    assert info.registrar.startswith("RESERVED") and info.abuse_email == "abuse@example.test"
    assert info.nameservers == ["a.iana-servers.net", "b.iana-servers.net"]
    assert info.status == ["clientTransferProhibited"] and info.updated.startswith("2024")


def test_whois_referral():
    assert wh.whois_referral("domain: TR\nrefer:        whois.trabis.gov.tr\n") == "whois.trabis.gov.tr"
    assert wh.whois_referral("nothing here") is None


# --- analysis ---------------------------------------------------------------------
@pytest.mark.parametrize("expires, status, text", [
    ("2028-10-09T18:20:50Z", PASS, "expires in"),
    ("2026-12-01T00:00:00Z", WARN, "re-registered by anyone"),
    ("2026-01-01", WARN, "expired"),
    ("2027-Mar-10", PASS, "expires in"),                # TRABIS format
    ("", INFO, "not published"),
])
def test_expiry(expires, status, text):
    info = wh.DomainInfo(domain="x.test", source="rdap", expires=expires)
    finding = next(f for f in wh.analyze(info, now=NOW) if f.name == "Expiry")
    assert finding.status == status and text in finding.detail


def test_transfer_lock_and_dnssec():
    locked = wh.DomainInfo("x.test", "rdap", status=["client transfer prohibited"], dnssec="signed")
    names = {f.name: f.status for f in wh.analyze(locked, now=NOW)}
    assert names["Transfer lock"] == PASS and names["DNSSEC"] == PASS
    assert {f.name: f.status for f in wh.analyze(wh.DomainInfo("x.test", "rdap"), now=NOW)}["Transfer lock"] == INFO


# --- lookup flow (network replaced) ------------------------------------------------------
def http_404(url):
    return urllib.error.HTTPError(url, 404, "Not Found", {}, None)


def test_lookup_walks_up_from_subdomain(monkeypatch):
    asked = []

    def fake_get(url, timeout):
        asked.append(url)
        if url == wh.BOOTSTRAP_URL:
            return BOOTSTRAP
        if url.endswith("/domain/github.com"):
            return RDAP
        raise http_404(url)

    monkeypatch.setattr(wh, "_get_json", fake_get)
    monkeypatch.setattr(wh, "_bootstrap_cache", {})
    info = wh.lookup("https://WWW.GitHub.com/path")
    assert info.domain == "github.com" and info.source == "rdap" and info.findings
    assert asked[-2:] == ["https://rdap.verisign.com/com/v1/domain/www.github.com",
                          "https://rdap.verisign.com/com/v1/domain/github.com"]


def test_lookup_unregistered(monkeypatch):
    monkeypatch.setattr(wh, "_get_json", lambda url, timeout: BOOTSTRAP if url == wh.BOOTSTRAP_URL
                        else (_ for _ in ()).throw(http_404(url)))
    monkeypatch.setattr(wh, "_bootstrap_cache", {})
    with pytest.raises(wh.WhoisError, match="not registered"):
        wh.lookup("free-name.com")


def test_lookup_falls_back_to_whois_for_tld_without_rdap(monkeypatch):
    monkeypatch.setattr(wh, "_get_json", lambda url, timeout: BOOTSTRAP)
    monkeypatch.setattr(wh, "_bootstrap_cache", {})
    replies = {("whois.iana.org", "tr"): "refer: whois.trabis.gov.tr\n",
               ("whois.trabis.gov.tr", "metu.edu.tr"): TRABIS}
    monkeypatch.setattr(wh, "whois_query", lambda server, query, timeout=10.0: replies.get((server, query), ""))
    info = wh.lookup("www.metu.edu.tr")
    assert info.source == "whois" and info.server == "whois.trabis.gov.tr" and info.registrar == "TRABİS KK"


def test_lookup_rejects_bare_words():
    with pytest.raises(wh.WhoisError):
        wh.lookup("localhost")


def test_whois_query_over_tcp():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    received = []

    def serve():
        conn, _ = server.accept()
        received.append(conn.recv(100))
        conn.sendall("Registrar: Örnek A.Ş.\r\n".encode("utf-8"))
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    text = wh.whois_query("127.0.0.1", "türkiye.gov.tr", timeout=5, port=server.getsockname()[1])
    server.close()
    assert received[0] == b"xn--trkiye-3ya.gov.tr\r\n" and "Örnek A.Ş." in text


# --- CLI ----------------------------------------------------------------------------
def test_cli_whois(monkeypatch, capsys):
    info = wh.parse_rdap(RDAP, "github.com")
    info.server, info.findings = "https://rdap.test/", wh.analyze(info, now=NOW)
    monkeypatch.setattr(wh, "lookup", lambda domain, timeout=10.0: info)
    assert cli.run(["whois", "github.com"]) == 0
    out = capsys.readouterr().out
    assert "MarkMonitor Inc." in out and "[PASS] Transfer lock" in out and "not for vulnerabilities" in out
    assert cli.run(["whois", "github.com", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["registrar"] == "MarkMonitor Inc."
