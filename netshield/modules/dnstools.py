from netshield import disclosure, dnsclient, mailsec, whois
from netshield.base import BaseModule
from netshield.theme import STATUS_ROLES, ask, say

DEFAULT_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA")


def lookup_lines(domain, types=DEFAULT_TYPES, server=None):
    """Run lookups and return [(role, text)]. Raises dnsclient.DnsError."""
    lines, resolver = [], ""
    for record_type in types:
        answer = dnsclient.query(domain, record_type, server)
        resolver = answer.server
        if answer.rcode == "NXDOMAIN":
            return [("error", f"{domain} does not exist (NXDOMAIN, resolver {resolver})")]
        for record in answer.records:
            if record.type == record_type:
                value = record.value
                if record_type == "MX" and mailsec.is_null_mx([value]):
                    value = "0 .   (null MX: this domain accepts no mail)"
                lines.append(("ok", f"{record.type:<6} {value}   (ttl {record.ttl})"))
    header = [("title", f"DNS records for {domain}   (resolver {resolver})")]
    if not lines:
        lines = [("warn", "no records of the requested types")]
    if mailsec.resolver_rewrites_nxdomain(server, record_type="A"):
        lines.append(("warn", f"note: resolver {resolver} invents A records for names that do not exist "
                              "(NXDOMAIN hijacking). Use --server 1.1.1.1 to check a name's existence."))
    return header + lines


class DnsLookupModule(BaseModule):
    name = "DNS Lookup"
    description = "A, AAAA, CNAME, MX, NS, TXT and CAA records of a domain"

    def run(self):
        domain = ask("Domain (e.g. example.com):")
        try:
            for role, text in lookup_lines(domain):
                say(role, text)
        except dnsclient.DnsError as error:
            say("error", f"[-] {error}")


class MailSecurityModule(BaseModule):
    name = "Email Security (SPF/DMARC/DKIM)"
    description = "How well a domain is protected against email spoofing"

    def run(self):
        domain = ask("Domain (e.g. example.com):")
        try:
            report = mailsec.audit_domain(domain)
        except dnsclient.DnsError as error:
            say("error", f"[-] {error}")
            return
        for status, text in mailsec.report_lines(report):
            say(STATUS_ROLES[status], text)


class WhoisModule(BaseModule):
    name = "WHOIS / RDAP"
    description = "Registrar, dates, name servers, transfer lock and DNSSEC of a domain"

    def run(self):
        domain = ask("Domain (e.g. example.com):")
        try:
            info = whois.lookup(domain)
        except whois.WhoisError as error:
            say("error", f"[-] {error}")
            return
        for status, text in whois.report_lines(info):
            say(STATUS_ROLES[status], text)


class DisclosureModule(BaseModule):
    name = "Find Disclosure Contact (security.txt)"
    description = "Where and how an organisation wants vulnerabilities reported (RFC 9116)"

    def run(self):
        domain = ask("Domain (e.g. example.com):")
        try:
            result = disclosure.find_security_txt(domain)
        except disclosure.DisclosureError as error:
            say("error", f"[-] {error}")
            return
        for status, text in disclosure.report_lines(domain, result):
            say(STATUS_ROLES[status], text)
