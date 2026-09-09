"""End-to-end CLI tests through Typer's runner.

The CLI is the composition root, so these assert wiring, not logic: that flags
reach the services, that a bad argument fails cleanly instead of showing a
traceback, and that the commands people actually type produce output.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from pyscan.cli.main import app

runner = CliRunner()


def lab_capture(tmp_path):
    path = tmp_path / "lab.pcap"
    assert runner.invoke(app, ["lab", str(path)]).exit_code == 0
    return path


# --------------------------------------------------------------------------
# top level
# --------------------------------------------------------------------------
def test_bare_invocation_shows_the_splash_and_help():
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "scan" in result.stdout and "sniff" in result.stdout


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0


def test_strategies_lists_every_registered_technique():
    result = runner.invoke(app, ["strategies"])
    assert result.exit_code == 0
    for name in ("tcp-connect", "syn", "udp", "modbus", "iec104", "s7comm"):
        assert name in result.stdout


# --------------------------------------------------------------------------
# argument validation — clean errors, never tracebacks
# --------------------------------------------------------------------------
def test_scan_rejects_a_cidr_and_points_at_sweep():
    result = runner.invoke(app, ["scan", "192.168.1.0/24"])
    assert result.exit_code != 0
    assert "pyscan sweep" in result.output


def test_scan_rejects_an_unknown_strategy():
    result = runner.invoke(app, ["scan", "127.0.0.1", "--type", "nope"])
    assert result.exit_code != 0
    assert "Unknown scan strategy" in result.output


def test_scan_rejects_a_bad_port_spec():
    result = runner.invoke(app, ["scan", "127.0.0.1", "-p", "not-ports"])
    assert result.exit_code != 0


def test_scan_rejects_a_top_ports_count_below_one():
    assert runner.invoke(app, ["scan", "127.0.0.1", "--top-ports", "0"]).exit_code != 0


def test_sweep_rejects_a_bad_port_spec():
    assert runner.invoke(app, ["sweep", "10.0.0.0/30", "-p", "?"]).exit_code != 0


def test_sniff_without_a_file_or_live_fails_cleanly():
    result = runner.invoke(app, ["sniff"])
    assert result.exit_code != 0
    assert "--live" in result.output


def test_sniff_rejects_a_file_that_is_not_a_capture(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"definitely not a capture file")
    result = runner.invoke(app, ["sniff", str(junk)])
    assert result.exit_code != 0
    assert "magic" in result.output


def test_monitor_rejects_an_unknown_severity(tmp_path):
    result = runner.invoke(
        app, ["monitor", str(lab_capture(tmp_path)), "--min-severity", "URGENT"]
    )
    assert result.exit_code != 0
    assert "min-severity" in result.output


def test_monitor_without_a_capture_or_live_fails_cleanly():
    result = runner.invoke(app, ["monitor"])
    assert result.exit_code != 0


# --------------------------------------------------------------------------
# lab -> sniff -> monitor, the whole offline pipeline
# --------------------------------------------------------------------------
def test_lab_writes_a_capture(tmp_path):
    path = tmp_path / "out.pcap"
    result = runner.invoke(app, ["lab", str(path)])
    assert result.exit_code == 0
    assert path.exists() and path.stat().st_size > 24
    assert "packets written" in result.stdout


def test_sniff_prints_a_packet_table(tmp_path):
    result = runner.invoke(app, ["sniff", str(lab_capture(tmp_path)), "-n", "3"])
    assert result.exit_code == 0
    assert "10.10.30" in result.stdout


def test_sniff_can_filter_by_protocol(tmp_path):
    result = runner.invoke(app, ["sniff", str(lab_capture(tmp_path)), "--proto", "udp"])
    assert result.exit_code == 0
    assert "No packets matched" in result.stdout  # the lab capture is all TCP


def test_monitor_finds_the_attack_in_the_lab_capture(tmp_path):
    result = runner.invoke(
        app,
        [
            "monitor", str(lab_capture(tmp_path)),
            "--hmi", "10.10.30.10",
            "--plc", "10.10.30.21,10.10.40.7",
        ],
    )
    assert result.exit_code == 0
    assert "CRITICAL" in result.stdout
    assert "T0855" in result.stdout
    assert "10.10.30.142" in result.stdout


def test_monitor_min_severity_filters_the_output(tmp_path):
    capture = lab_capture(tmp_path)
    everything = runner.invoke(app, ["monitor", str(capture), "--hmi", "10.10.30.10"])
    critical = runner.invoke(
        app, ["monitor", str(capture), "--hmi", "10.10.30.10", "--min-severity", "CRITICAL"]
    )
    assert critical.stdout.count("ATT&CK:") < everything.stdout.count("ATT&CK:")


def test_monitor_writes_an_incident_report(tmp_path):
    report = tmp_path / "incident.md"
    result = runner.invoke(
        app,
        [
            "monitor", str(lab_capture(tmp_path)),
            "--hmi", "10.10.30.10",
            "--report", str(report),
        ],
    )
    assert result.exit_code == 0
    body = report.read_text(encoding="utf-8")
    assert "OT incident" in body and "10.10.30.142" in body


# --------------------------------------------------------------------------
# scanning against a socket we control
# --------------------------------------------------------------------------
def test_scan_reports_an_open_port(tcp_server):
    host, port = tcp_server
    result = runner.invoke(app, ["scan", host, "-p", str(port), "--no-banner"])
    assert result.exit_code == 0
    assert str(port) in result.stdout and "open" in result.stdout


def test_scan_writes_json_and_csv(tcp_server, tmp_path):
    host, port = tcp_server
    out_json = tmp_path / "r.json"
    out_csv = tmp_path / "r.csv"
    result = runner.invoke(
        app,
        ["scan", host, "-p", str(port), "--no-banner", "--json", str(out_json),
         "--csv", str(out_csv)],
    )
    assert result.exit_code == 0
    payload = json.loads(out_json.read_text())
    assert payload["ports"][0]["port"] == port
    assert "port,state,service" in out_csv.read_text()


def test_scan_honours_max_rate_and_retries(tcp_server):
    host, port = tcp_server
    result = runner.invoke(
        app, ["scan", host, "-p", str(port), "--max-rate", "50", "--retries", "1"]
    )
    assert result.exit_code == 0


def test_sweep_produces_a_json_inventory(tcp_server, tmp_path):
    host, port = tcp_server
    out = tmp_path / "net.json"
    result = runner.invoke(
        app, ["sweep", host, "-p", str(port), "--json", str(out), "--max-rate", "100"]
    )
    assert result.exit_code == 0
    payload = json.loads(out.read_text())
    assert payload["up_count"] >= 0


# --------------------------------------------------------------------------
# the splash, on a terminal that cannot render it
# --------------------------------------------------------------------------
def test_banner_falls_back_to_ascii_on_a_legacy_console():
    """A splash screen is never worth a crash on a cp1252 Windows console."""
    import io

    from rich.console import Console

    from pyscan.cli.banner import render

    buffer = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    console = Console(file=buffer, width=80, force_terminal=False)
    render(console)  # would raise UnicodeEncodeError without the fallback

    buffer.seek(0)
    text = buffer.buffer.getvalue().decode("cp1252")
    assert "pyscan" not in text.split("\n")[0]  # the ASCII wordmark, not a title
    assert "v" in text and "scan - sweep - sniff - monitor" in text


def test_banner_uses_the_block_wordmark_when_utf8_is_available():
    import io

    from rich.console import Console

    from pyscan.cli.banner import render

    buffer = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    console = Console(file=buffer, width=80, force_terminal=False)
    render(console)

    buffer.seek(0)
    assert "█" in buffer.buffer.getvalue().decode("utf-8")
