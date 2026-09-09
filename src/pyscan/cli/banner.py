"""Wordmark splash, shown on the intro/help screen and `pyscan version`.

Never printed during a scan, so piped and machine-readable output stays clean.

The block-drawing wordmark is Unicode, and a Windows console still running a
legacy code page (cp1252) cannot encode it — printing it there raises
UnicodeEncodeError and takes the whole command down. So the encoding is checked
first and an ASCII wordmark stands in when the terminal cannot cope. A splash
screen is never worth a crash.
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

ASCII_WORDMARK = r"""[bold green]
 _ __  _   _ ___  ___ __ _ _ __
| '_ \| | | / __|/ __/ _` | '_ \
| |_) | |_| \__ \ (_| (_| | | | |
| .__/ \__, |___/\___\__,_|_| |_|
|_|    |___/[/bold green]"""

TAGLINE = "hexagonal port & OT-protocol scanner · packet sniffer · ICS detection"
ASCII_TAGLINE = "hexagonal port & OT-protocol scanner - packet sniffer - ICS detection"


def _can_encode(console: Console, text: str) -> bool:
    encoding = getattr(console.file, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def render(console: Console | None = None) -> None:
    console = console or Console()
    unicode_ok = _can_encode(console, WORDMARK + TAGLINE)
    wordmark = WORDMARK if unicode_ok else ASCII_WORDMARK
    tagline = TAGLINE if unicode_ok else ASCII_TAGLINE
    arrow = "›" if unicode_ok else ">"

    console.print(wordmark)
    console.print(f"  [dim]{tagline}[/dim]")
    console.print(
        f"  [green]{arrow}[/green] [dim]v{__version__}   "
        f"scan · sweep · sniff · monitor[/dim]\n"
        if unicode_ok
        else f"  [green]{arrow}[/green] [dim]v{__version__}   "
        f"scan - sweep - sniff - monitor[/dim]\n"
    )
