"""Network sweep use case: discover live hosts, then scan them.

Two bounded phases:
  1. Discovery — TCP-ping every candidate, keep the ones that answer.
  2. Scan — port-scan only the live hosts, reusing ScanService.scan_host.

This composes the existing single-host scanner rather than duplicating it,
which is the payoff of having split scan_host out of run earlier.
"""

from __future__ import annotations

import asyncio
import time

from pyscan.application.scan_service import ScanService
from pyscan.domain.models import NetworkReport, ScanReport, ScanTarget
from pyscan.domain.ports import HostDiscovery, NetworkSink
from pyscan.domain.targets import expand_targets


class SweepService:
    def __init__(
        self,
        scanner: ScanService,
        discovery: HostDiscovery,
        ports: tuple[int, ...],
        sinks: list[NetworkSink] | None = None,
    ) -> None:
        self._scanner = scanner
        self._discovery = discovery
        self._ports = ports
        self._sinks = sinks or []

    async def run(
        self,
        spec: str,
        *,
        timeout: float = 1.0,
        discover: bool = True,
        host_concurrency: int = 64,
    ) -> NetworkReport:
        candidates = expand_targets(spec)
        t0 = time.perf_counter()

        if discover:
            up_hosts = await self._discover(candidates, timeout, host_concurrency)
        else:
            up_hosts = candidates

        reports = await self._scan_all(up_hosts, timeout, host_concurrency)
        duration = time.perf_counter() - t0

        report = NetworkReport(
            network=spec,
            hosts=reports,
            total_candidates=len(candidates),
            up_count=len(up_hosts),
            duration_s=duration,
        )
        for sink in self._sinks:
            sink.emit(report)
        return report

    async def _discover(
        self, hosts: list[str], timeout: float, concurrency: int
    ) -> list[str]:
        sem = asyncio.Semaphore(concurrency)

        async def check(host: str) -> tuple[str, bool]:
            async with sem:
                return host, await self._discovery.is_up(host, timeout)

        checked = await asyncio.gather(*(check(h) for h in hosts))
        return [host for host, up in checked if up]

    async def _scan_all(
        self, hosts: list[str], timeout: float, concurrency: int
    ) -> list[ScanReport]:
        sem = asyncio.Semaphore(concurrency)

        async def scan_one(host: str) -> ScanReport:
            async with sem:
                target = ScanTarget(host=host, ports=self._ports)
                # ports list is small (top ports), so scan them all at once
                return await self._scanner.scan_host(
                    target, concurrency=len(self._ports), timeout=timeout
                )

        reports = await asyncio.gather(*(scan_one(h) for h in hosts))
        return sorted(reports, key=lambda r: r.host.ip or r.host.host)
