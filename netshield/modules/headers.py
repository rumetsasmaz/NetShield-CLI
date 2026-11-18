from netshield import webaudit
from netshield.base import BaseModule
from netshield.theme import ask, say

_ROLE = {webaudit.PASS: "ok", webaudit.WARN: "warn", webaudit.FAIL: "error", webaudit.INFO: "dim"}


class HttpHeadersModule(BaseModule):
    name = "HTTP Security Headers"
    description = "Grade a website's security headers (HSTS, CSP, cookies, ...) with fix hints"

    def run(self):
        url = ask("URL (e.g. example.com):")
        say("dim", "Sends one normal GET request and reads the response headers.")
        try:
            report = webaudit.audit_url(url)
        except webaudit.FetchError as error:
            say("error", f"[-] {error}")
            return
        for status, text in webaudit.report_lines(report):
            say(_ROLE[status], text)
