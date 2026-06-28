"""Render decoded packets as a rich table — the mini-tshark view."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table

from pyscan.domain.packet import Packet

_PROTO_STYLE = {
    "TCP": "green",
    "UDP": "cyan",
    "ICMP": "yellow",
    "ARP": "magenta",
    "IPv6": "blue",
}


def _addr(ip: str | None, port: int | None) -> str:
    if ip is None:
        return "-"
    return f"{ip}:{port}" if port is not None else ip


class PacketTableSink:
    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def emit(self, packets: list[Packet]) -> None:
        if not packets:
            self._console.print("[dim]No packets matched.[/dim]")
            return
        t0 = packets[0].ts
        table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", pad_edge=False)
        table.add_column("#", justify="right", style="dim")
        table.add_column("TIME", justify="right")
        table.add_column("SOURCE")
        table.add_column("DESTINATION")
        table.add_column("PROTO")
        table.add_column("LEN", justify="right", style="dim")
        table.add_column("INFO")
        for i, p in enumerate(packets, 1):
            style = _PROTO_STYLE.get(p.protocol, "white")
            table.add_row(
                str(i),
                f"{p.ts - t0:.3f}",
                _addr(p.src, p.sport),
                _addr(p.dst, p.dport),
                f"[{style}]{p.protocol}[/{style}]",
                str(p.length),
                p.info,
            )
        self._console.print(table)
        self._console.print(f"[dim]{len(packets)} packets[/dim]")
