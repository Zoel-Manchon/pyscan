"""Wordmark splash (ANSI Shadow), shown on intro/help and `pyscan version`.

Never printed on a scan, so piped/JSON output stays clean. Pure rich markup
over a baked figlet wordmark — no runtime figlet dependency.
"""

from __future__ import annotations

from rich.console import Console

from pyscan import __version__

WORDMARK = r"""[bold green]
██████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
██╔═══╝   ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║        ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝        ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝[/bold green]"""

TAGLINE = "hexagonal port & OT-protocol scanner · live packet sniffer"


def render(console: Console | None = None) -> None:
    console = console or Console()
    console.print(WORDMARK)
    console.print(f"  [dim]{TAGLINE}[/dim]")
    console.print(f"  [green]›[/green] [dim]v{__version__}   scan · sweep · sniff[/dim]\n")
