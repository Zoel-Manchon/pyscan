"""Terminal output for OT alerts — the mini-IDS view.

Severity drives colour, and every alert prints the same three lines: what
happened, which ATT&CK for ICS technique it maps to, and what to do about it.
That third line is the one that matters at 3am, so it is never optional.
"""

from __future__ import annotations

from datetime import UTC, datetime

from rich.console import Console
from rich.markup import escape

from pyscan.domain.ot_detect import Alert, Detector, Severity

_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.INFO: "cyan",
}


def _clock(ts: float) -> str:
    if not ts:
        return "--:--:--"
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%H:%M:%S")


class AlertConsoleSink:
    """Prints alerts as they arrive, then a closing summary."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def emit(self, alert: Alert) -> None:
        style = _STYLE.get(alert.severity, "white")
        self._console.print(
            f"[{style}][{alert.severity.value:>8}][/{style}] "
            f"[dim]{_clock(alert.ts)}[/dim] "
            f"[bold]{escape(alert.src):>15}[/bold] -> [bold]{escape(alert.dst):<15}[/bold] "
            f"[cyan]{alert.protocol}[/cyan]  {escape(alert.summary)}"
        )
        self._console.print(
            f"           [dim]ATT&CK:[/dim] {escape(alert.technique)}\n"
            f"           [green]Action:[/green] {escape(alert.action)}"
        )

    def summary(self, detector: Detector) -> None:
        sources = ", ".join(sorted(detector.hostile_sources)) or "-"
        operations = ", ".join(sorted(detector.observed_operations)) or "-"
        self._console.print(
            f"\n[dim]{detector.packets} OT packets - {detector.alerts} alerts[/dim]"
        )
        self._console.print(f"[dim]Hostile sources: {escape(sources)}[/dim]")
        self._console.print(f"[dim]Operations seen: {escape(operations)}[/dim]")
