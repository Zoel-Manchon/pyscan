"""ASCII-art splash: two mirrored cobras facing the wordmark.

Shown on intro/help and `pyscan version` — never on a scan, so piped/JSON
output stays clean. Colours: green bodies, yellow eyes, red forked tongues.
Pure ASCII line-art (no Braille/Unicode blocks) so it renders in PowerShell.
"""

from __future__ import annotations

from rich.console import Console

from pyscan import __version__

SNAKE = r"""[green]
       .-~~~-.                  .-~~~-.
      /  _ _  \                /  _ _  \
     |  / [bold yellow]o[/bold yellow] \  |              |  / [bold yellow]o[/bold yellow] \  |
   __|  \   /  |              |  \   /  |__
[/green][red]>=[/red][green]'   \  '-'  /                \  '-'  /   '[/green][red]=<[/red][green]
       '~. .~'                  '~. .~'
       .-' '-.                  .-' '-.
      /  ___  \                /  ___  \
     |  /   \  |              |  /   \  |
      \ \   / /                \ \   / /
       '~'-'~'                  '~'-'~'
[/green]"""

WORDMARK = r"""[bold green]
            _ __ _  _ ___ __ __ _ _ _
           | '_ \ || (_-</ _/ _` | ' \
           | .__/\_, /__/\__\__,_|_||_|
           |_|   |__/[/bold green]"""


def render(console: Console | None = None) -> None:
    console = console or Console()
    console.print(SNAKE)
    console.print(WORDMARK)
    console.print(
        f"           [dim]port / service / version / ICS recon   v{__version__}[/dim]\n"
    )
