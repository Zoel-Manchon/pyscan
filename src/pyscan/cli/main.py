"""CLI — the composition root.

Parse arguments, build the right adapters, hand them to the application
service. No scanning or identification logic lives here. The ASCII splash is
shown only on the intro/help screen and `pyscan version`, never during a scan,
so machine-readable output stays clean.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer

from pyscan.adapters.capture.pcap_reader import read_pcap
from pyscan.adapters.discovery.tcp_ping import TcpPingDiscovery
from pyscan.adapters.output.csv_sink import CsvSink
from pyscan.adapters.output.json_sink import JsonSink
from pyscan.adapters.output.network_json import NetworkJsonSink
from pyscan.adapters.output.network_table import NetworkTableSink
from pyscan.adapters.output.packet_table import PacketTableSink
from pyscan.adapters.output.table import TableSink
from pyscan.adapters.strategies import available, get_strategy
from pyscan.application.scan_service import ScanService
from pyscan.application.sweep_service import SweepService
from pyscan.cli.banner import render as render_banner
from pyscan.domain.models import Protocol, ScanTarget
from pyscan.domain.packet import decode
from pyscan.domain.port_spec import parse_port_spec
from pyscan.domain.targets import expand_targets
from pyscan.domain.top_ports import top_ports

# A curated top-ports set for fast network inventory (not a full 1-1024 sweep).
DEFAULT_SWEEP_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,"
    "993,995,1723,3306,3389,5432,5900,8080,8443"
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="pyscan — a tiny, modular port scanner.",
)


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    # Bare `pyscan` -> splash + help. Subcommands skip this entirely.
    if ctx.invoked_subcommand is None:
        render_banner()
        typer.echo(ctx.get_help())


@app.command()
def scan(
    host: str = typer.Argument(..., help="Target host or IP."),
    ports: str = typer.Option(
        "1-1024", "--ports", "-p", help="e.g. '22,80,443' or '1-1024' or '1-100,8080'."
    ),
    scan_type: str = typer.Option(
        "tcp-connect", "--type", "-t", help="Scan strategy (see `pyscan strategies`)."
    ),
    concurrency: int = typer.Option(
        200, "--concurrency", "-c", help="Max simultaneous probes."
    ),
    timeout: float = typer.Option(1.0, "--timeout", help="Per-port timeout (seconds)."),
    show_all: bool = typer.Option(
        False, "--all", "-a", help="Show closed/filtered ports, not just open."
    ),
    banner: bool = typer.Option(
        True, "--banner/--no-banner", help="Read service banners on open ports."
    ),
    json_out: Optional[Path] = typer.Option(
        None, "--json", help="Also write results as JSON to this path."
    ),
    csv_out: Optional[Path] = typer.Option(
        None, "--csv", help="Also write results as CSV to this path."
    ),
    top: Optional[int] = typer.Option(
        None, "--top-ports", help="Scan the N most common ports instead of -p."
    ),
    max_rate: Optional[float] = typer.Option(
        None, "--max-rate", help="Cap probes per second (gentler on fragile/OT hosts)."
    ),
) -> None:
    """Scan HOST for open TCP ports, with service/version detection."""
    if len(expand_targets(host)) > 1:
        raise typer.BadParameter(
            f"{host!r} is a network range. Use:  pyscan sweep {host}"
        )

    try:
        port_list = top_ports(top) if top is not None else parse_port_spec(ports)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))

    try:
        strategy = get_strategy(scan_type, grab_banner=banner)
    except KeyError as exc:
        raise typer.BadParameter(str(exc))
    except RuntimeError as exc:  # e.g. SYN scan without scapy
        typer.echo(f"error: {exc}")
        raise typer.Exit(code=1)

    sinks = [TableSink(show_all=show_all)]
    if json_out is not None:
        sinks.append(JsonSink(path=json_out))
    if csv_out is not None:
        sinks.append(CsvSink(path=csv_out))

    target = ScanTarget(host=host, ports=tuple(port_list), protocol=Protocol.TCP)
    service = ScanService(strategy=strategy, sinks=sinks)
    try:
        asyncio.run(service.run(target, concurrency=concurrency, timeout=timeout, max_rate=max_rate))
    except RuntimeError as exc:  # e.g. SYN scan without raw-socket privileges
        typer.echo(f"error: {exc}")
        raise typer.Exit(code=1)


@app.command()
def sweep(
    network: str = typer.Argument(..., help="CIDR or host, e.g. '192.168.1.0/24'."),
    ports: str = typer.Option(
        DEFAULT_SWEEP_PORTS, "--ports", "-p", help="Ports to scan on live hosts."
    ),
    scan_type: str = typer.Option("tcp-connect", "--type", "-t", help="Scan strategy."),
    timeout: float = typer.Option(1.0, "--timeout", help="Per-probe timeout (seconds)."),
    discovery: bool = typer.Option(
        True, "--discovery/--no-discovery", help="Ping-sweep first, then scan up hosts."
    ),
    detail: bool = typer.Option(
        False, "--detail", "-d", help="Also print a per-host port table."
    ),
    json_out: Optional[Path] = typer.Option(
        None, "--json", help="Write the inventory as JSON to this path."
    ),
) -> None:
    """Discover live hosts across a range and build a port inventory."""
    try:
        port_list = parse_port_spec(ports)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    try:
        strategy = get_strategy(scan_type, grab_banner=True)
    except KeyError as exc:
        raise typer.BadParameter(str(exc))

    sinks = [NetworkTableSink(detail=detail)]
    if json_out is not None:
        sinks.append(NetworkJsonSink(path=json_out))

    scanner = ScanService(strategy=strategy)  # no per-host sinks; sweep aggregates
    service = SweepService(
        scanner=scanner,
        discovery=TcpPingDiscovery(),
        ports=tuple(port_list),
        sinks=sinks,
    )
    try:
        asyncio.run(service.run(network, timeout=timeout, discover=discovery))
    except ValueError as exc:
        raise typer.BadParameter(str(exc))


@app.command()
def sniff(
    pcap: Path = typer.Argument(..., help="Path to a .pcap capture file."),
    proto: Optional[str] = typer.Option(
        None, "--proto", help="Only show this protocol (tcp/udp/icmp/arp)."
    ),
    count: Optional[int] = typer.Option(None, "--count", "-n", help="Stop after N packets."),
) -> None:
    """Decode and display packets from a .pcap file (mini-tshark)."""
    want = proto.upper() if proto else None
    packets = []
    try:
        for ts, linktype, frame in read_pcap(pcap):
            pkt = decode(frame, linktype, ts)
            if want and pkt.protocol != want:
                continue
            packets.append(pkt)
            if count and len(packets) >= count:
                break
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise typer.BadParameter(str(exc))
    PacketTableSink().emit(packets)


@app.command(name="strategies")
def list_strategies() -> None:
    """List available scan strategies."""
    for name in available():
        typer.echo(name)


@app.command()
def version() -> None:
    """Show version with the splash."""
    render_banner()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
