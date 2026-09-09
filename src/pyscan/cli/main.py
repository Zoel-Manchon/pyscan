"""CLI — the composition root.

Parse arguments, build the right adapters, hand them to the application
service. No scanning, identification or detection logic lives here. The ASCII
splash is shown only on the intro/help screen and `pyscan version`, never
during a scan, so machine-readable output stays clean.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import TypeAlias

import typer

from pyscan.adapters.capture.pcap_reader import read_pcap
from pyscan.adapters.capture.pcap_writer import write_pcap
from pyscan.adapters.discovery.tcp_ping import TcpPingDiscovery
from pyscan.adapters.output.alert_console import AlertConsoleSink
from pyscan.adapters.output.csv_sink import CsvSink
from pyscan.adapters.output.json_sink import JsonSink
from pyscan.adapters.output.network_json import NetworkJsonSink
from pyscan.adapters.output.network_table import NetworkTableSink
from pyscan.adapters.output.packet_table import PacketTableSink
from pyscan.adapters.output.table import TableSink
from pyscan.adapters.strategies import available, get_strategy
from pyscan.application.monitor_service import MonitorService
from pyscan.application.scan_service import ScanService
from pyscan.application.sweep_service import SweepService
from pyscan.cli.banner import render as render_banner
from pyscan.domain.models import Protocol, ScanTarget
from pyscan.domain.ot_detect import Baseline, Detector, Severity
from pyscan.domain.ot_traffic import build_frames
from pyscan.domain.packet import decode
from pyscan.domain.port_spec import parse_port_spec
from pyscan.domain.ports import NetworkSink, ResultSink
from pyscan.domain.targets import expand_targets
from pyscan.domain.top_ports import top_ports

# A curated top-ports set for fast network inventory (not a full 1-1024 sweep).
FrameSource: TypeAlias = Iterator[tuple[float, int, bytes] | None]

DEFAULT_SWEEP_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,443,445,"
    "993,995,1723,3306,3389,5432,5900,8080,8443"
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="pyscan — a modular port, OT-protocol and traffic scanner.",
)


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context) -> None:
    # Bare `pyscan` -> splash + help. Subcommands skip this entirely.
    if ctx.invoked_subcommand is None:
        render_banner()
        typer.echo(ctx.get_help())


@app.command()
def scan(
    host: str = typer.Argument(..., help="Target host or IP (IPv4 or IPv6)."),
    ports: str = typer.Option(
        "1-1024", "--ports", "-p", help="e.g. '22,80,443' or '1-1024' or '1-100,8080'."
    ),
    scan_type: str = typer.Option(
        "tcp-connect", "--type", "-t", help="Scan strategy (see `pyscan strategies`)."
    ),
    concurrency: int = typer.Option(200, "--concurrency", "-c", help="Max simultaneous probes."),
    timeout: float = typer.Option(1.0, "--timeout", help="Per-port timeout (seconds)."),
    retries: int = typer.Option(
        0, "--retries", help="Retransmit ports that stayed silent (filtered/open|filtered)."
    ),
    show_all: bool = typer.Option(
        False, "--all", "-a", help="Show closed/filtered ports, not just open."
    ),
    banner: bool = typer.Option(
        True, "--banner/--no-banner", help="Read service banners on open ports."
    ),
    ipv6: bool = typer.Option(
        False, "--ipv6", "-6", help="Prefer the IPv6 address when a host has both."
    ),
    json_out: Path | None = typer.Option(
        None, "--json", help="Also write results as JSON to this path."
    ),
    csv_out: Path | None = typer.Option(
        None, "--csv", help="Also write results as CSV to this path."
    ),
    top: int | None = typer.Option(
        None, "--top-ports", help="Scan the N most common ports instead of -p."
    ),
    max_rate: float | None = typer.Option(
        None, "--max-rate", help="Cap probes per second (gentler on fragile/OT hosts)."
    ),
) -> None:
    """Scan HOST for open ports, with service/version detection."""
    if len(expand_targets(host)) > 1:
        raise typer.BadParameter(f"{host!r} is a network range. Use:  pyscan sweep {host}")

    try:
        port_list = top_ports(top) if top is not None else parse_port_spec(ports)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    try:
        strategy = get_strategy(scan_type, grab_banner=banner)
    except KeyError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except RuntimeError as exc:  # e.g. SYN scan without scapy
        _fail(str(exc))

    sinks: list[ResultSink] = [TableSink(show_all=show_all)]
    if json_out is not None:
        sinks.append(JsonSink(path=json_out))
    if csv_out is not None:
        sinks.append(CsvSink(path=csv_out))

    target = ScanTarget(host=host, ports=tuple(port_list), protocol=Protocol.TCP)
    service = ScanService(strategy=strategy, sinks=sinks)
    try:
        asyncio.run(
            service.run(
                target,
                concurrency=concurrency,
                timeout=timeout,
                max_rate=max_rate,
                retries=retries,
                prefer_ipv6=ipv6,
            )
        )
    except RuntimeError as exc:  # e.g. SYN scan without raw-socket privileges
        _fail(str(exc))


@app.command()
def sweep(
    network: str = typer.Argument(..., help="CIDR or host, e.g. '192.168.1.0/24'."),
    ports: str = typer.Option(
        DEFAULT_SWEEP_PORTS, "--ports", "-p", help="Ports to scan on live hosts."
    ),
    scan_type: str = typer.Option("tcp-connect", "--type", "-t", help="Scan strategy."),
    timeout: float = typer.Option(1.0, "--timeout", help="Per-probe timeout (seconds)."),
    retries: int = typer.Option(0, "--retries", help="Retransmit probes that stayed silent."),
    discovery: bool = typer.Option(
        True, "--discovery/--no-discovery", help="Ping-sweep first, then scan up hosts."
    ),
    detail: bool = typer.Option(False, "--detail", "-d", help="Also print a per-host port table."),
    max_rate: float | None = typer.Option(
        None,
        "--max-rate",
        help="Cap probes per second across the WHOLE sweep (essential on OT segments).",
    ),
    json_out: Path | None = typer.Option(
        None, "--json", help="Write the inventory as JSON to this path."
    ),
) -> None:
    """Discover live hosts across a range and build a port inventory."""
    try:
        port_list = parse_port_spec(ports)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    try:
        strategy = get_strategy(scan_type, grab_banner=True)
    except KeyError as exc:
        raise typer.BadParameter(str(exc)) from exc

    sinks: list[NetworkSink] = [NetworkTableSink(detail=detail)]
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
        asyncio.run(
            service.run(
                network,
                timeout=timeout,
                discover=discovery,
                max_rate=max_rate,
                retries=retries,
            )
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def sniff(
    capture: Path | None = typer.Argument(
        None, help="Path to a .pcap or .pcapng file (omit with --live)."
    ),
    proto: str | None = typer.Option(
        None, "--proto", help="Only show this protocol (tcp/udp/icmp/arp)."
    ),
    count: int | None = typer.Option(None, "--count", "-n", help="Stop after N packets."),
    tui: bool = typer.Option(False, "--tui", help="Open the live scrolling TUI."),
    live: bool = typer.Option(False, "--live", help="Capture live (Linux, root)."),
    iface: str | None = typer.Option(None, "--iface", "-i", help="Interface, e.g. eth0."),
) -> None:
    """Decode packets from a capture (table or --tui), or capture live (--live)."""
    if live:
        source = _open_live(iface)
        _run_sniff_tui(source, f"pyscan sniff · live{(' · ' + iface) if iface else ''}")
        return

    if capture is None:
        raise typer.BadParameter("Provide a .pcap/.pcapng file, or use --live to capture.")

    if tui:
        frames = list(_read_capture(capture))
        _run_sniff_tui(iter(frames), f"pyscan sniff · {capture.name}")
        return

    want = proto.upper() if proto else None
    packets = []
    for ts, linktype, frame in _read_capture(capture):
        pkt = decode(frame, linktype, ts)
        if want and pkt.protocol != want:
            continue
        packets.append(pkt)
        if count and len(packets) >= count:
            break
    PacketTableSink().emit(packets)


@app.command()
def monitor(
    capture: Path | None = typer.Argument(
        None, help="Capture to replay (omit with --live)."
    ),
    hmi: str = typer.Option(
        "", "--hmi", help="Comma-separated address(es) of the legitimate HMI."
    ),
    plc: str = typer.Option(
        "", "--plc", help="Comma-separated PLC/RTU addresses (blank = every OT destination)."
    ),
    live: bool = typer.Option(False, "--live", help="Watch an interface (Linux, root)."),
    iface: str | None = typer.Option(None, "--iface", "-i", help="Interface, e.g. eth0."),
    tui: bool = typer.Option(False, "--tui", help="Open the OT command centre TUI."),
    min_severity: str = typer.Option(
        "MEDIUM", "--min-severity", help="INFO, MEDIUM, HIGH or CRITICAL."
    ),
    report: Path | None = typer.Option(
        None, "--report", help="Write a Markdown incident report here when the run ends."
    ),
) -> None:
    """Watch OT traffic for unauthorised writes and control commands.

    Reads Modbus/TCP, IEC 60870-5-104 and S7comm with the same pure codecs the
    scanner uses, and rates every finding against a baseline of who is allowed
    to drive the process.
    """
    try:
        floor = Severity(min_severity.upper())
    except ValueError as exc:
        raise typer.BadParameter(
            f"--min-severity must be one of: {', '.join(s.value for s in Severity)}"
        ) from exc

    baseline = Baseline.of(hmi, plc)

    if tui:
        _run_monitor_tui(baseline, capture, iface, _open_live(iface) if live else None)
        return

    source = _open_live(iface) if live else _read_capture(_require_capture(capture))
    service = MonitorService(Detector(baseline=baseline), min_severity=floor)
    console = AlertConsoleSink()
    try:
        for alert in service.run(source):
            console.emit(alert)
    except KeyboardInterrupt:
        typer.echo("")
    console.summary(service.detector)

    if report is not None:
        from pyscan.adapters.output.incident_report import write_report

        written = write_report(report, service.detector)
        typer.echo(f"incident report written to {written}")


@app.command()
def lab(
    out: Path = typer.Argument(Path("capture.pcap"), help="Where to write the capture."),
) -> None:
    """Generate a practice capture with an OT attack inside it.

    Baseline HMI polling, then a new talker, reconnaissance, Modbus writes and
    an IEC-104 control command followed by STOPDT. Feed it to `pyscan monitor`
    or open it in Wireshark.
    """
    frames = build_frames()
    written = write_pcap(out, frames)
    typer.echo(f"{written} packets written to {out}")
    typer.echo(f"  replay it:  pyscan monitor {out} --hmi 10.10.30.10 --plc 10.10.30.21,10.10.40.7")


@app.command(name="strategies")
def list_strategies() -> None:
    """List available scan strategies."""
    for name in available():
        typer.echo(name)


@app.command()
def version() -> None:
    """Show version with the splash."""
    render_banner()


# ---------------------------------------------------------------------------
# small CLI helpers — argument plumbing only, no domain logic
# ---------------------------------------------------------------------------
def _fail(message: str) -> None:
    typer.echo(f"error: {message}")
    raise typer.Exit(code=1)


def _require_capture(capture: Path | None) -> Path:
    if capture is None:
        raise typer.BadParameter("Provide a capture file, or use --live.")
    return capture


def _read_capture(path: Path) -> Iterator[tuple[float, int, bytes]]:
    """Read a capture, turning file-level problems into clean CLI errors."""
    try:
        yield from read_pcap(path)
    except (ValueError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc


def _open_live(iface: str | None) -> Iterator[tuple[float, int, bytes] | None]:
    from pyscan.adapters.capture.live_capture import live_capture

    try:
        return live_capture(iface)
    except RuntimeError as exc:
        _fail(str(exc))
        raise  # unreachable; keeps the return type honest


def _run_sniff_tui(source: FrameSource, title_text: str) -> None:
    try:
        from pyscan.adapters.output.sniff_tui import run_sniff_tui
    except ImportError:
        _fail("the TUI needs textual. Install:  pip install 'pyscan[tui]'")
        return
    run_sniff_tui(source, title_text)


def _run_monitor_tui(
    baseline: Baseline,
    capture: Path | None,
    iface: str | None,
    source: FrameSource | None,
) -> None:
    try:
        from pyscan.adapters.output.monitor_tui import run_monitor_tui
    except ImportError:
        _fail("the TUI needs textual. Install:  pip install 'pyscan[tui]'")
        return
    run_monitor_tui(baseline, capture=capture, iface=iface, source=source)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
