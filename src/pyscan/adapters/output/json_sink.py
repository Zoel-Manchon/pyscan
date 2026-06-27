"""Machine-readable JSON output — to stdout or a file.

The full record (including the raw banner the terminal table omits) lives here,
so this is what you'd diff between scans or feed into the sniffer later.
"""

from __future__ import annotations

import json
from pathlib import Path

from pyscan.domain.models import ScanReport


class JsonSink:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path

    def emit(self, report: ScanReport) -> None:
        payload = {
            "host": report.host.host,
            "ip": report.host.ip,
            "scan_type": report.scan_type,
            "started_at": report.started_at.isoformat(),
            "duration_s": round(report.duration_s, 4),
            "ports": [
                {
                    "port": p.port,
                    "state": p.state.value,
                    "service": p.service,
                    "product": p.product,
                    "version": p.version,
                    "latency_ms": round(p.latency_ms, 2) if p.latency_ms is not None else None,
                    "banner": p.banner,
                }
                for p in report.host.ports
            ],
        }
        text = json.dumps(payload, indent=2)
        if self._path:
            self._path.write_text(text + "\n")
        else:
            print(text)
