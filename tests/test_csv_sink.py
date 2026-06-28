import csv
import tempfile
from datetime import datetime
from pathlib import Path

from pyscan.adapters.output.csv_sink import CsvSink
from pyscan.domain.models import (
    HostResult,
    PortResult,
    PortState,
    Protocol,
    ScanReport,
    ScanTarget,
)


def _report():
    host = HostResult(
        host="example.test",
        ip="1.2.3.4",
        ports=[
            PortResult(22, PortState.OPEN, service="ssh", product="OpenSSH",
                       version="9.6", latency_ms=12.345),
            PortResult(80, PortState.CLOSED),
        ],
    )
    target = ScanTarget(host="example.test", ports=(22, 80), protocol=Protocol.TCP)
    return ScanReport(target, host, "tcp-connect", datetime.now(), 0.5)


def test_csv_has_header_and_rows():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "out.csv"
        CsvSink(path=path).emit(_report())
        rows = list(csv.DictReader(path.read_text().splitlines()))
    assert [r["port"] for r in rows] == ["22", "80"]
    assert rows[0]["service"] == "ssh"
    assert rows[0]["version"] == "9.6"
    assert rows[0]["latency_ms"] == "12.35"
    assert rows[1]["state"] == "closed"
    assert rows[1]["service"] == ""  # None -> empty cell
