"""Application layer: the scan use case.

This is where orchestration lives — resolving the host, fanning probes out
across ports with a concurrency cap, timing the run, and emitting results.
It depends ONLY on the port interfaces (ScanStrategy, ResultSink), never on a
concrete adapter. That dependency direction is what makes the core swappable.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import replace
from datetime import datetime, timezone

from pyscan.domain.fingerprint import identify
from pyscan.domain.models import HostResult, PortState, ScanReport, ScanTarget
from pyscan.domain.ports import ResultSink, ScanStrategy


class ScanService:
    def __init__(self, strategy: ScanStrategy, sinks: list[ResultSink] | None = None) -> None:
        self._strategy = strategy
        self._sinks = sinks or []

    async def run(
        self,
        target: ScanTarget,
        *,
        concurrency: int = 200,
        timeout: float = 1.0,
    ) -> ScanReport:
        report = await self.scan_host(target, concurrency=concurrency, timeout=timeout)
        for sink in self._sinks:
            sink.emit(report)
        return report

    async def scan_host(
        self,
        target: ScanTarget,
        *,
        concurrency: int = 200,
        timeout: float = 1.0,
    ) -> ScanReport:
        """Scan one host and return its report WITHOUT emitting.

        This is the reusable unit: the single-host `run` emits to sinks, and the
        network sweep calls this per up-host and aggregates the reports itself.
        """
        ip = self._resolve(target.host)
        probe_host = ip or target.host

        # One semaphore caps how many ports are in flight at once. This is the
        # single knob that turns "scan 65k ports" from a fork bomb into a
        # well-behaved, tunable workload.
        sem = asyncio.Semaphore(concurrency)

        async def bounded(port: int):
            async with sem:
                return await self._strategy.scan_port(probe_host, port, timeout)

        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        results = await asyncio.gather(*(bounded(p) for p in target.ports))
        duration = time.perf_counter() - t0

        enriched = [self._identify(r) for r in results]

        host = HostResult(
            host=target.host,
            ip=ip,
            ports=sorted(enriched, key=lambda r: r.port),
        )
        return ScanReport(
            target=target,
            host=host,
            scan_type=self._strategy.name,
            started_at=started,
            duration_s=duration,
        )

    @staticmethod
    def _identify(result):
        """Enrichment stage: turn a raw banner into service/product/version.

        Pure, side-effect-free — it just maps a PortResult to a richer one.
        Only open ports are worth fingerprinting.
        """
        if result.state is not PortState.OPEN:
            return result
        info = identify(result.banner, result.port)
        return replace(
            result,
            service=info.service or result.service,
            product=info.product,
            version=info.version,
        )

    @staticmethod
    def _resolve(host: str) -> str | None:
        try:
            return socket.gethostbyname(host)
        except OSError:
            return None
