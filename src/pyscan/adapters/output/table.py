"""Human-readable terminal output via rich — single host."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.rule import Rule
from rich.table import Table

from pyscan.domain.models import PortState, ScanReport

_STATE_STYLE = {
    PortState.OPEN: "bold green",
    PortState.CLOSED: "red",
    PortState.FILTERED: "yellow",
    PortState.OPEN_FILTERED: "cyan",
    PortState.UNKNOWN: "dim",
}


def version_str(product: str | None, version: str | None) -> str:
    parts = [p for p in (product, version) if p]
    return " ".join(parts) if parts else "-"


def build_port_table(report: ScanReport, show_all: bool = False) -> Table:
    host = report.host
    rows = host.ports if show_all else host.open_ports
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", pad_edge=False)
    table.add_column("PORT", justify="right", style="bold")
    table.add_column("STATE")
    table.add_column("SERVICE", style="magenta")
    table.add_column("VERSION", style="dim")
    table.add_column("LATENCY", justify="right", style="dim")
    for r in rows:
        style = _STATE_STYLE.get(r.state, "")
        latency = f"{r.latency_ms:.1f} ms" if r.latency_ms is not None else "-"
        table.add_row(
            str(r.port),
            f"[{style}]{r.state.value}[/{style}]",
            escape(r.service) if r.service else "-",
            escape(version_str(r.product, r.version)),
            latency,
        )
    return table


class TableSink:
    def __init__(self, show_all: bool = False, console: Console | None = None) -> None:
        self._show_all = show_all
        self._console = console or Console()

    def emit(self, report: ScanReport) -> None:
        host = report.host
        where = host.host + (f" ({host.ip})" if host.ip and host.ip != host.host else "")
        self._console.print(Rule(f"[bold]{escape(where)}[/bold]", style="cyan"))

        rows = host.ports if self._show_all else host.open_ports
        if not rows:
            self._console.print("[dim]No open ports found.[/dim]")
        else:
            self._console.print(build_port_table(report, self._show_all))

        self._console.print(
            f"[dim]{len(host.open_ports)} open · "
            f"{len(host.ports)} scanned in {report.duration_s:.2f}s · "
            f"{report.scan_type}[/dim]\n"
        )
