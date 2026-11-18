from netshield import report
from netshield.base import BaseModule
from netshield.theme import ask, say

_ROLE = {"High": "error", "Medium": "error", "Low": "warn", "Informational": "plain"}


class ReportModule(BaseModule):
    name = "Assessment Report (Markdown)"
    description = "Run all passive checks on a domain and write a disclosure-ready report"

    def run(self):
        domain = ask("Domain (e.g. example.com):")
        if not domain:
            say("error", "[-] No domain given.")
            return
        say("dim", "Passive checks only: one HTTP request, one TLS handshake, DNS, RDAP and security.txt.")
        result = report.assess(domain)
        counts = result.counts()
        say("title", f"\n{result.target}: " + ", ".join(f"{counts[s]} {s}" for s in report.SEVERITIES))
        for item in result.items:
            say(_ROLE[item.severity], f"  [{item.severity}] {item.title}")
        for check, message in result.errors.items():
            say("warn", f"  ! {check} check could not run: {message}")

        path = ask(f"Save Markdown report to [{result.target}-report.md] (- to skip):") or f"{result.target}-report.md"
        if path == "-":
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(report.to_markdown(result) + "\n")
            say("ok", f"[+] Report written to {path}")
        except OSError as error:
            say("error", f"[-] Could not write {path}: {error}")
