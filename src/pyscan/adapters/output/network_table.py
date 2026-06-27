"""Network-level inventory output via rich — the asset-discovery table."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from pyscan.adapters.output.table import TableSink
from pyscan.domain.models import NetworkReport


class NetworkTableSink:
    def __init__(self, detail: bool = False, console: Console | None = None) -> None:
        self._detail = detail
        self._console = console or Console()

    def emit(self, report: NetworkReport) -> None:
        summary = (
            f"[bold]{report.up_count}[/bold]/{report.total_candidates} hosts up · "
            f"scanned in {report.duration_s:.2f}s"
        )
        self._console.print(
            Panel(summary, title=f"[bold cyan]sweep {escape(report.network)}[/bold cyan]",
                  box=box.ROUNDED, expand=False)
        )

        table = Table(box=box.ROUNDED, header_style="bold cyan", title="Inventory")
        table.add_column("HOST", style="bold")
        table.add_column("OPEN", justify="right")
        table.add_column("SERVICES", style="magenta")
        for host_report in report.hosts:
            host = host_report.host
            open_ports = host.open_ports
            count = len(open_ports)
            count_cell = f"[green]{count}[/green]" if count else "[dim]0[/dim]"
            services = ", ".join(
                f"{p.port}/{p.service or '?'}" for p in open_ports[:8]
            )
            if count > 8:
                services += f" +{count - 8}"
            table.add_row(
                escape(host.ip or host.host),
                count_cell,
                escape(services) if services else "[dim]-[/dim]",
            )
        self._console.print(table)

        if self._detail:
            self._console.print()
            detail_sink = TableSink(console=self._console)
            for host_report in report.hosts:
                if host_report.host.open_ports:
                    detail_sink.emit(host_report)
