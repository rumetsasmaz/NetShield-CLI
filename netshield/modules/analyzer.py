from netshield import sniffing
from netshield.base import BaseModule
from netshield.theme import ask, say


def format_stream_list(streams):
    lines = [f"{'#':<4}{'PROTO':<10}{'CLIENT <-> SERVER':<52}{'PKTS':>5}  {'C->S':>8} {'S->C':>8}"]
    for index, stream in enumerate(streams):
        counts = stream.byte_counts()
        lines.append(f"{index:<4}{stream.guess_protocol() or '-':<10}{stream.label():<52}"
                     f"{len(stream.packets):>5}  {counts['client']:>8} {counts['server']:>8}")
    return "\n".join(lines)


class PcapAnalyzerModule(BaseModule):
    name = "Analyze Capture (pcap)"
    description = "Read a .pcap file (also Wireshark captures): filter, statistics, follow TCP streams"

    def run(self):
        path = ask("Path to .pcap file:")
        if not path:
            say("error", "[-] No file given.")
            return
        try:
            packet_filter = sniffing.compile_filter(ask("Filter (Enter for all):"))
            mode = ask("Show: 1 packets, 2 statistics, 3 TCP streams, 4 follow a stream [1]:") or "1"
            if mode not in ("1", "2", "3", "4"):
                say("error", "[-] Choose 1, 2, 3 or 4.")
                return
            packets = [p for p in sniffing.read_pcap(path) if packet_filter(p)]
        except FileNotFoundError:
            say("error", f"[-] File not found: {path}")
            return
        except (ValueError, OSError) as error:
            say("error", f"[-] {error}")
            return

        if not packets:
            say("warn", "No packets matched.")
        elif mode == "1":
            for packet in packets[:50]:
                say("ok", packet.summary())
            say("info", f"\n{len(packets)} packet(s) matched" + (", showing first 50" if len(packets) > 50 else ""))
        elif mode == "2":
            stats = sniffing.CaptureStats()
            for packet in packets:
                stats.add(packet)
            say("info", stats.report())
        else:
            streams = sniffing.tcp_streams(packets)
            if not streams:
                say("warn", "No TCP streams in the selection.")
                return
            say("ok", format_stream_list(streams))
            if mode == "4":
                choice = ask("Stream number to follow:")
                if not choice.isdigit() or int(choice) >= len(streams):
                    say("error", "[-] Not a valid stream number.")
                    return
                say("ok", "\n" + streams[int(choice)].render())
