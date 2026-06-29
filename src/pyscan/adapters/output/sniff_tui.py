"""Textual TUI: a live scrolling packet view.

Source-agnostic — it consumes any iterator of (ts, linktype, bytes) | None,
so the same UI renders a .pcap replay or a live AF_PACKET capture. textual is
an optional dependency (`pip install pyscan[tui]`); this module is only imported
when the --tui/--live path runs, so the rest of the tool needs nothing extra.
"""

from __future__ import annotations

from collections.abc import Iterator

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.message import Message
from textual.widgets import DataTable, Footer, Header, Static
from textual.worker import get_current_worker

from pyscan.domain.packet import Packet, decode

_PROTO_STYLE = {
    "TCP": "green",
    "UDP": "cyan",
    "ICMP": "yellow",
    "ARP": "magenta",
    "IPv6": "blue",
}

PacketSource = Iterator[tuple[float, int, bytes] | None]


def _addr(ip: str | None, port: int | None) -> str:
    if ip is None:
        return "-"
    return f"{ip}:{port}" if port is not None else ip


class PacketArrived(Message):
    def __init__(self, packet: Packet) -> None:
        self.packet = packet
        super().__init__()


class SniffApp(App):
    TITLE = "pyscan"
    SUB_TITLE = "live packet sniffer"
    CSS = """
    #stats { height: 1; padding: 0 1; background: $panel; color: $text; }
    DataTable { height: 1fr; }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("p", "toggle_pause", "Pause/Resume"),
        ("c", "clear", "Clear"),
    ]

    def __init__(self, source: PacketSource, title_text: str = "pyscan sniff") -> None:
        super().__init__()
        self._source = source
        self._title_text = title_text
        self._paused = False
        self._counts: dict[str, int] = {}
        self._n = 0
        self._t0: float | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="stats")
        yield DataTable(id="packets")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#packets", DataTable)
        table.add_columns("#", "Time", "Source", "Destination", "Proto", "Len", "Info")
        table.cursor_type = "row"
        self._refresh_stats()
        self.capture()

    @work(thread=True, exclusive=True)
    def capture(self) -> None:
        worker = get_current_worker()
        for item in self._source:
            if worker.is_cancelled:
                break
            if item is None:  # heartbeat
                continue
            ts, linktype, frame = item
            self.post_message(PacketArrived(decode(frame, linktype, ts)))

    def on_packet_arrived(self, message: PacketArrived) -> None:
        if self._paused:
            return
        pkt = message.packet
        self._n += 1
        if self._t0 is None:
            self._t0 = pkt.ts
        self._counts[pkt.protocol] = self._counts.get(pkt.protocol, 0) + 1
        style = _PROTO_STYLE.get(pkt.protocol, "white")
        table = self.query_one("#packets", DataTable)
        table.add_row(
            str(self._n),
            f"{pkt.ts - self._t0:.3f}",
            _addr(pkt.src, pkt.sport),
            _addr(pkt.dst, pkt.dport),
            Text(pkt.protocol, style=style),
            str(pkt.length),
            pkt.info,
        )
        table.scroll_end(animate=False)
        self._refresh_stats()

    def _refresh_stats(self) -> None:
        breakdown = "  ".join(f"{k} {v}" for k, v in sorted(self._counts.items()))
        paused = "   [yellow]❚❚ PAUSED[/yellow]" if self._paused else ""
        self.query_one("#stats", Static).update(
            f"[b]{self._title_text}[/b]   packets: {self._n}   {breakdown}{paused}"
        )

    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self._refresh_stats()

    def action_clear(self) -> None:
        self.query_one("#packets", DataTable).clear()
        self._n = 0
        self._counts = {}
        self._t0 = None
        self._refresh_stats()


def run_sniff_tui(source: PacketSource, title_text: str = "pyscan sniff") -> None:
    SniffApp(source, title_text).run()
