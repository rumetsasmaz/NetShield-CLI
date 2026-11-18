from netshield import sniffing
from netshield.base import BaseModule
from netshield.theme import ask, say


class PcapAnalyzerModule(BaseModule):
    name = "Analyze Capture (pcap)"
    description = "Read a .pcap file (also Wireshark captures): filter, list, statistics"

    def run(self):
        path = ask("Path to .pcap file:")
        if not path:
            say("error", "[-] No file given.")
            return
        try:
            packet_filter = sniffing.compile_filter(ask("Filter (Enter for all):"))
            show_stats = ask("Show statistics instead of packets? [y/N]:").lower() in ("y", "yes")
            stats = sniffing.CaptureStats()
            matched = printed = 0
            for packet in sniffing.read_pcap(path):
                if not packet_filter(packet):
                    continue
                matched += 1
                stats.add(packet)
                if not show_stats and printed < 50:
                    say("ok", packet.summary())
                    printed += 1
        except FileNotFoundError:
            say("error", f"[-] File not found: {path}")
            return
        except (ValueError, OSError) as error:
            say("error", f"[-] {error}")
            return

        if not matched:
            say("warn", "No packets matched.")
        elif show_stats:
            say("info", stats.report())
        else:
            say("info", f"\n{matched} packet(s) matched" + (", showing first 50" if matched > 50 else ""))
