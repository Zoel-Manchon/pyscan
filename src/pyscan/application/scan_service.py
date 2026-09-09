"""Application layer: the scan use case.

This is where orchestration lives — resolving the host, fanning probes out
across ports with a concurrency cap, retrying the ones that stayed silent,
timing the run, and emitting results. It depends ONLY on the port interfaces
(ScanStrategy, ResultSink), never on a concrete adapter. That dependency
direction is what makes the core swappable.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import replace
from datetime import UTC, datetime

from pyscan.application.rate_limiter import AsyncRateLimiter
from pyscan.domain.fingerprint import identify
from pyscan.domain.models import HostResult, PortResult, PortState, ScanReport, ScanTarget
from pyscan.domain.ports import ResultSink, ScanStrategy

# States that mean "nothing came back", i.e. the ones a retransmission can
# still turn into a real answer. OPEN and CLOSED are conclusive; retrying them
# would only add traffic.
_INCONCLUSIVE = frozenset({PortState.FILTERED, PortState.OPEN_FILTERED})


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
        max_rate: float | None = None,
        retries: int = 0,
        prefer_ipv6: bool = False,
    ) -> ScanReport:
        report = await self.scan_host(
            target,
            concurrency=concurrency,
            timeout=timeout,
            max_rate=max_rate,
            retries=retries,
            prefer_ipv6=prefer_ipv6,
        )
        for sink in self._sinks:
            sink.emit(report)
        return report

    async def scan_host(
        self,
        target: ScanTarget,
        *,
        concurrency: int = 200,
        timeout: float = 1.0,
        max_rate: float | None = None,
        retries: int = 0,
        prefer_ipv6: bool = False,
        limiter: AsyncRateLimiter | None = None,
    ) -> ScanReport:
        """Scan one host and return its report WITHOUT emitting.

        This is the reusable unit: the single-host `run` emits to sinks, and the
        network sweep calls this per up-host and aggregates the reports itself.

        A caller may pass its own `limiter` to share one rate budget across many
        hosts — that is how a sweep keeps `--max-rate` meaning probes per second
        in total, rather than per host multiplied by the host concurrency.
        """
        ip = await self._resolve(target.host, prefer_ipv6=prefer_ipv6)
        probe_host = ip or target.host

        # One semaphore caps how many ports are in flight at once. This is the
        # single knob that turns "scan 65k ports" from a fork bomb into a
        # well-behaved, tunable workload.
        sem = asyncio.Semaphore(concurrency)
        if limiter is None and max_rate:
            limiter = AsyncRateLimiter(max_rate)

        async def probe_once(port: int) -> PortResult:
            # The rate gate sits OUTSIDE the semaphore so waiting to pace does
            # not tie up a concurrency slot.
            if limiter is not None:
                await limiter.acquire()
            async with sem:
                return await self._strategy.scan_port(probe_host, port, timeout)

        async def bounded(port: int) -> PortResult:
            result = await probe_once(port)
            # Silence is not evidence: a dropped probe looks exactly like a
            # filtered port. Retransmit before believing it.
            for _ in range(max(0, retries)):
                if result.state not in _INCONCLUSIVE:
                    break
                result = await probe_once(port)
            return result

        started = datetime.now(UTC)
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
    def _identify(result: PortResult) -> PortResult:
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
    async def _resolve(host: str, *, prefer_ipv6: bool = False) -> str | None:
        """Resolve a hostname without blocking the event loop.

        `socket.gethostbyname` is a blocking call AND IPv4-only; the loop's
        getaddrinfo runs in an executor and returns both families, so one fix
        buys non-blocking DNS and IPv6 support at once.
        """
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError):
            return None

        wanted = socket.AF_INET6 if prefer_ipv6 else socket.AF_INET
        addresses = {family: str(sockaddr[0]) for family, _t, _p, _c, sockaddr in infos}
        return addresses.get(wanted) or next(iter(addresses.values()), None)
