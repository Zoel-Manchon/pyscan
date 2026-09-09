"""Adapters: the strategy registry, discovery, the UDP probe, and every sink.

The UDP scan is exercised against a real loopback socket because its whole
design claim — that a connected datagram socket can tell CLOSED from
OPEN|FILTERED without root — is only true if the kernel agrees.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from rich.console import Console

from pyscan.adapters.discovery.tcp_ping import TcpPingDiscovery
from pyscan.adapters.output.alert_console import AlertConsoleSink
from pyscan.adapters.output.csv_sink import CsvSink
from pyscan.adapters.output.incident_report import build_report
from pyscan.adapters.output.json_sink import JsonSink
from pyscan.adapters.output.network_json import NetworkJsonSink
from pyscan.adapters.output.network_table import NetworkTableSink
from pyscan.adapters.output.packet_table import PacketTableSink
from pyscan.adapters.output.table import TableSink
from pyscan.adapters.strategies import available, get_strategy
from pyscan.adapters.strategies.udp import UdpScan
from pyscan.domain.models import (
    HostResult,
    NetworkReport,
    PortResult,
    PortState,
    ScanReport,
    ScanTarget,
)
from pyscan.domain.ot_detect import Baseline, Detector, Severity
from pyscan.domain.ot_traffic import modbus_write_coil
from pyscan.domain.packet import Packet


def a_report(ports=None) -> ScanReport:
    ports = ports or [
        PortResult(22, PortState.OPEN, service="ssh", product="OpenSSH",
                   version="9.6p1", latency_ms=1.234, banner="SSH-2.0-OpenSSH_9.6p1"),
        PortResult(80, PortState.CLOSED),
    ]
    return ScanReport(
        target=ScanTarget("example.test", tuple(p.port for p in ports)),
        host=HostResult(host="example.test", ip="10.0.0.1", ports=ports),
        scan_type="tcp-connect",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        duration_s=0.5,
    )


def quiet_console(record: bool = True) -> Console:
    return Console(record=record, width=100, force_terminal=False, no_color=True)


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------
def test_every_builtin_strategy_is_registered():
    assert set(available()) >= {"tcp-connect", "syn", "udp", "modbus", "iec104", "s7comm"}


def test_get_strategy_returns_an_instance_with_its_name():
    assert get_strategy("tcp-connect").name == "tcp-connect"


def test_unknown_strategy_names_the_alternatives():
    with pytest.raises(KeyError, match="Available"):
        get_strategy("telepathy")


def test_strategies_ignore_options_they_do_not_use():
    assert get_strategy("udp", grab_banner=True, nonsense=1).name == "udp"


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------
async def test_tcp_ping_finds_a_listening_host(tcp_server):
    host, port = tcp_server
    assert await TcpPingDiscovery(ping_ports=(port,)).is_up(host, timeout=1.0)


async def test_tcp_ping_treats_a_refusal_as_alive(monkeypatch):
    """A RST is proof of life: the host answered, it just said no.

    Injected rather than provoked, because whether a closed port refuses or
    silently drops is the operating system's choice, not ours — Windows
    loopback drops. The rule being tested is ours.
    """
    import asyncio

    async def refuse(*_args, **_kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr(asyncio, "open_connection", refuse)
    assert await TcpPingDiscovery(ping_ports=(9,)).is_up("10.0.0.1", timeout=1.0)


async def test_tcp_ping_reports_silence_as_down():
    # TEST-NET-1 is reserved and never routable. Whether the network blackholes
    # the packet or answers "unreachable" is up to the host running this, and
    # both must read as down - so do not tighten this to one of them.
    assert not await TcpPingDiscovery(ping_ports=(80,)).is_up("192.0.2.1", timeout=0.2)


# --------------------------------------------------------------------------
# the UDP strategy
# --------------------------------------------------------------------------
async def test_udp_scan_sees_a_reply_as_open(udp_server):
    host, port = udp_server
    result = await UdpScan().scan_port(host, port, timeout=2.0)
    assert result.state is PortState.OPEN
    assert result.banner and result.banner.startswith("udp reply")
    assert result.latency_ms is not None


async def test_udp_scan_reports_silence_as_open_filtered(udp_silent):
    """Silence is genuinely ambiguous in UDP, and must not be called closed."""
    host, port = udp_silent
    result = await UdpScan().scan_port(host, port, timeout=0.3)
    assert result.state is PortState.OPEN_FILTERED


async def test_udp_scan_handles_an_unusable_address():
    result = await UdpScan().scan_port("not a host", 53, timeout=0.2)
    assert result.state is PortState.FILTERED


# --------------------------------------------------------------------------
# result sinks
# --------------------------------------------------------------------------
def test_table_sink_shows_open_ports_only_by_default():
    console = quiet_console()
    TableSink(console=console).emit(a_report())
    text = console.export_text()
    assert "22" in text and "OpenSSH" in text and "closed" not in text


def test_table_sink_show_all_includes_closed_ports():
    console = quiet_console()
    TableSink(show_all=True, console=console).emit(a_report())
    assert "closed" in console.export_text()


def test_table_sink_says_so_when_nothing_is_open():
    console = quiet_console()
    TableSink(console=console).emit(a_report(ports=[PortResult(80, PortState.CLOSED)]))
    assert "No open ports" in console.export_text()


def test_json_sink_writes_the_full_record_including_the_banner(tmp_path):
    path = tmp_path / "r.json"
    JsonSink(path=path).emit(a_report())
    payload = json.loads(path.read_text())
    assert payload["ip"] == "10.0.0.1"
    assert payload["ports"][0]["banner"].startswith("SSH-2.0")
    assert payload["ports"][0]["latency_ms"] == 1.23


def test_json_sink_prints_when_given_no_path(capsys):
    JsonSink().emit(a_report())
    assert json.loads(capsys.readouterr().out)["host"] == "example.test"


def test_csv_sink_writes_a_header_and_a_row_per_port(tmp_path):
    path = tmp_path / "r.csv"
    CsvSink(path=path).emit(a_report())
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert lines[0].startswith("port,state,service")
    assert len(lines) == 3


def test_csv_sink_writes_to_stdout_when_given_no_path(capsys):
    CsvSink().emit(a_report())
    assert "port,state,service" in capsys.readouterr().out


# --------------------------------------------------------------------------
# network sinks
# --------------------------------------------------------------------------
def a_network_report() -> NetworkReport:
    return NetworkReport(
        network="10.0.0.0/30", hosts=[a_report()], total_candidates=2, up_count=1, duration_s=1.0
    )


def test_network_table_sink_renders_an_inventory():
    console = quiet_console()
    NetworkTableSink(console=console).emit(a_network_report())
    assert "10.0.0.1" in console.export_text()


def test_network_table_sink_detail_adds_per_host_tables():
    console = quiet_console()
    NetworkTableSink(detail=True, console=console).emit(a_network_report())
    assert "OpenSSH" in console.export_text()


def test_network_json_sink_writes_the_inventory(tmp_path):
    path = tmp_path / "net.json"
    NetworkJsonSink(path=path).emit(a_network_report())
    payload = json.loads(path.read_text())
    assert payload["network"] == "10.0.0.0/30" and payload["up_count"] == 1


# --------------------------------------------------------------------------
# packet table
# --------------------------------------------------------------------------
def test_packet_table_renders_rows():
    console = quiet_console()
    packets = [
        Packet(ts=1.0, length=60, protocol="TCP", src="1.1.1.1", dst="2.2.2.2",
               sport=1234, dport=502, info="[S]"),
    ]
    PacketTableSink(console=console).emit(packets)
    assert "502" in console.export_text()


def test_packet_table_handles_an_empty_capture():
    console = quiet_console()
    PacketTableSink(console=console).emit([])
    assert "No packets" in console.export_text()


# --------------------------------------------------------------------------
# OT output
# --------------------------------------------------------------------------
def an_alerting_detector() -> Detector:
    detector = Detector(baseline=Baseline.of("10.10.30.10", "10.10.30.21"))
    packet = Packet(
        ts=1_700_000_000.0, length=80, protocol="TCP", src="10.10.30.142",
        dst="10.10.30.21", sport=50412, dport=502,
        payload=modbus_write_coil(0, closed=False), flags="PA",
    )
    detector.feed(packet)
    return detector


def test_alert_console_prints_severity_technique_and_action():
    console = quiet_console()
    detector = an_alerting_detector()
    sink = AlertConsoleSink(console=console)
    for alert in detector.feed(
        Packet(ts=1.0, length=80, protocol="TCP", src="10.10.30.142", dst="10.10.30.21",
               dport=502, payload=modbus_write_coil(0, closed=True), flags="PA")
    ):
        sink.emit(alert)
    sink.summary(detector)
    text = console.export_text()
    assert "CRITICAL" in text and "T0855" in text
    assert "Hostile sources: 10.10.30.142" in text


def test_alert_console_handles_a_missing_timestamp():
    console = quiet_console()
    from pyscan.domain.ot_detect import Alert

    AlertConsoleSink(console=console).emit(
        Alert(0.0, Severity.INFO, "a", "b", "Modbus", "s", "t", "act")
    )
    assert "--:--:--" in console.export_text()


def test_incident_report_carries_iocs_and_the_timeline():
    report = build_report(
        an_alerting_detector(),
        timeline=[("12:00:00", "CRITICAL", "write to the feeder")],
        now=datetime(2026, 3, 1, 9, 30, tzinfo=UTC),
    )
    assert "INC-20260301-01" in report
    assert "10.10.30.142" in report
    assert "Modbus FC5" in report
    assert "write to the feeder" in report


def test_incident_report_is_valid_with_nothing_observed():
    report = build_report(Detector())
    assert "no events recorded" in report
    assert "Hostile source(s): `-`" in report
