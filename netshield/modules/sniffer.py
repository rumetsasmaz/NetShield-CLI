from netshield import sniffing
from netshield.base import BaseModule
from netshield.theme import ask, say


def _int_or_default(text, default):
    return int(text) if text.strip().isdigit() and int(text) > 0 else default


class PacketSnifferModule(BaseModule):
    name = "Packet Sniffer"
    description = "Capture and decode IPv4 traffic, optional pcap save. Needs Administrator/root"

    def run(self):
        say("warn", "[!] Capture only traffic on networks you own or are authorised to monitor.")
        limit = _int_or_default(ask("How many packets (default 20):"), 20)
        expression = ask("Filter, e.g. 'tcp and port 80' (Enter for all):")
        try:
            packet_filter = sniffing.compile_filter(expression)
        except sniffing.FilterError as error:
            say("error", f"[-] Bad filter: {error}")
            return
        path = ask("Save capture as pcap file (Enter to skip):")

        sniffer = sniffing.PacketSniffer()
        try:
            sniffer.open()
            writer = sniffing.PcapWriter(path) if path else None
        except sniffing.SniffError as error:
            say("error", f"[-] {error}")
            return
        except OSError as error:
            sniffer.close()
            say("error", f"[-] Cannot write {path}: {error}")
            return

        say("info", f"[+] Listening on {sniffer.interface_ip}. Ctrl+C to stop.")
        captured = 0
        try:
            for packet in sniffer.packets():
                if packet is None or not packet_filter(packet):
                    continue
                say("ok", packet.summary())
                if writer:
                    writer.write(packet)
                captured += 1
                if captured >= limit:
                    break
        except KeyboardInterrupt:
            say("warn", "\n[!] Stopped.")
        finally:
            sniffer.close()
            if writer:
                writer.close()
        say("info", f"[+] Captured {captured} packet(s)" + (f", saved to {path}" if path else "") + ".")
