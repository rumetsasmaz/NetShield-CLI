from netshield.base import BaseModule
from netshield.scanning import SERVICES
from netshield.theme import ask, say


def lookup(query):
    """Look up by port number or service name. Returns list of (port, name, risk)."""
    query = query.strip().lower()
    if query.isdigit():
        port = int(query)
        return [(port, *SERVICES[port])] if port in SERVICES else []
    return [(port, name, risk) for port, (name, risk) in SERVICES.items() if query in name]


class PortDatabaseModule(BaseModule):
    name = "Port Database"
    description = "Look up a port number or service name"

    def run(self):
        query = ask("Port number or service name (e.g. 3389 or ssh):")
        if not query:
            say("error", "[-] Nothing entered.")
            return
        rows = lookup(query)
        if not rows:
            say("error", f"[-] '{query}' is not in the database.")
            return
        for port, name, risk in rows:
            say("warn" if risk else "ok", f"[+] {port:>5}/tcp  {name:<14} {risk}")
