from netshield import sniffing
from netshield.base import BaseModule
from netshield.theme import ask, say


def _int_or_none(text):
    return int(text) if text.strip().isdigit() else None


class PacketSnifferModule(BaseModule):
    name = "Packet Sniffer"
    description = "Capture and decode IPv4 traffic (TCP/UDP/ICMP). Needs Administrator/root"

    def run(self):
        say("warn", "[!] Capture only traffic on networks you own or are authorised to monitor.")
        limit = _int_or_none(ask("How many packets (default 20):") or "20") or 20
        protocol = ask("Filter protocol tcp/udp/icmp (Enter for all):").lower() or None
        if protocol not in (None, "tcp", "udp", "icmp"):
            say("error", "[-] Protocol must be tcp, udp or icmp.")
            return
        port = _int_or_none(ask("Filter port (Enter for all):"))
        host = ask("Filter host IP (Enter for all):") or None

        sniffer = sniffing.PacketSniffer()
        try:
            sniffer.open()
        except sniffing.SniffError as error:
            say("error", f"[-] {error}")
            return

        say("info", f"[+] Listening on {sniffer.interface_ip}. Ctrl+C to stop.")
        captured = 0
        try:
            for packet in sniffer.packets():
                if packet is None or not sniffing.matches(packet, protocol, port, host):
                    continue
                say("ok", packet.summary())
                captured += 1
                if captured >= limit:
                    break
        except KeyboardInterrupt:
            say("warn", "\n[!] Stopped.")
        finally:
            sniffer.close()
        say("info", f"[+] Captured {captured} packet(s).")
