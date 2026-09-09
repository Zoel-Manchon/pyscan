"""CSV output — a ResultSink for spreadsheets / diffing scans.

Another drop-in: it implements the same ResultSink port as the table and JSON
sinks, so wiring it in touched zero engine code — the whole point of the hexagon.
"""

from __future__ import annotations

import contextlib
import csv
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO

from pyscan.domain.models import ScanReport

_FIELDS = ["port", "state", "service", "product", "version", "latency_ms", "banner"]


@contextlib.contextmanager
def _sink(path: Path | None) -> Iterator[TextIO]:
    """A file when given a path, stdout otherwise — closing only what we opened."""
    if path is None:
        yield sys.stdout
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        yield handle


class CsvSink:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path

    def emit(self, report: ScanReport) -> None:
        with _sink(self._path) as handle:
            writer = csv.DictWriter(handle, fieldnames=_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for p in report.host.ports:
                writer.writerow(
                    {
                        "port": p.port,
                        "state": p.state.value,
                        "service": p.service or "",
                        "product": p.product or "",
                        "version": p.version or "",
                        "latency_ms": round(p.latency_ms, 2) if p.latency_ms is not None else "",
                        "banner": p.banner or "",
                    }
                )
