"""Machine-readable JSON for a full network sweep."""

from __future__ import annotations

import json
from pathlib import Path

from pyscan.domain.models import NetworkReport


class NetworkJsonSink:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path

    def emit(self, report: NetworkReport) -> None:
        payload = {
            "network": report.network,
            "total_candidates": report.total_candidates,
            "up_count": report.up_count,
            "duration_s": round(report.duration_s, 4),
            "hosts": [
                {
                    "host": hr.host.host,
                    "ip": hr.host.ip,
                    "open_ports": [
                        {
                            "port": p.port,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                            "banner": p.banner,
                        }
                        for p in hr.host.open_ports
                    ],
                }
                for hr in report.hosts
            ],
        }
        text = json.dumps(payload, indent=2)
        if self._path:
            self._path.write_text(text + "\n")
        else:
            print(text)
