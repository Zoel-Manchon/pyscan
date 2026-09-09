"""The scan use case: retries, pacing, resolution, enrichment and emission.

Every strategy here is a fake. The point of the hexagon is that the engine can
be exercised without a socket, and this file is the proof.
"""

from __future__ import annotations

import asyncio

import pytest

from pyscan.application.rate_limiter import AsyncRateLimiter
from pyscan.application.scan_service import ScanService
from pyscan.application.sweep_service import SweepService
from pyscan.domain.models import PortResult, PortState, ScanTarget


class FakeStrategy:
    """Answers from a scripted list, and counts how often each port was probed."""

    name = "fake"

    def __init__(self, answers: dict[int, list[PortState]] | None = None) -> None:
        self._answers = answers or {}
        self.calls: dict[int, int] = {}
        self.hosts: list[str] = []

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        self.calls[port] = self.calls.get(port, 0) + 1
        self.hosts.append(host)
        script = self._answers.get(port, [PortState.CLOSED])
        state = script[min(self.calls[port] - 1, len(script) - 1)]
        banner = "SSH-2.0-OpenSSH_9.6p1" if state is PortState.OPEN else None
        return PortResult(port, state, latency_ms=1.0, banner=banner)


class RecordingSink:
    def __init__(self) -> None:
        self.reports = []

    def emit(self, report) -> None:
        self.reports.append(report)


class FakeDiscovery:
    def __init__(self, up: set[str]) -> None:
        self._up = up
        self.checked: list[str] = []

    async def is_up(self, host: str, timeout: float) -> bool:
        self.checked.append(host)
        return host in self._up


# --------------------------------------------------------------------------
# retries
# --------------------------------------------------------------------------
async def test_silent_ports_are_retried():
    strategy = FakeStrategy({22: [PortState.FILTERED, PortState.FILTERED, PortState.OPEN]})
    service = ScanService(strategy)
    report = await service.scan_host(ScanTarget("127.0.0.1", (22,)), retries=2)
    assert strategy.calls[22] == 3
    assert report.host.ports[0].state is PortState.OPEN


async def test_retries_stop_as_soon_as_the_answer_is_conclusive():
    strategy = FakeStrategy({80: [PortState.CLOSED, PortState.OPEN]})
    await ScanService(strategy).scan_host(ScanTarget("127.0.0.1", (80,)), retries=5)
    assert strategy.calls[80] == 1


async def test_no_retries_by_default():
    strategy = FakeStrategy({80: [PortState.FILTERED]})
    await ScanService(strategy).scan_host(ScanTarget("127.0.0.1", (80,)))
    assert strategy.calls[80] == 1


async def test_a_still_silent_port_stays_filtered():
    strategy = FakeStrategy({80: [PortState.FILTERED]})
    report = await ScanService(strategy).scan_host(ScanTarget("127.0.0.1", (80,)), retries=2)
    assert report.host.ports[0].state is PortState.FILTERED
    assert strategy.calls[80] == 3


# --------------------------------------------------------------------------
# enrichment, ordering, emission
# --------------------------------------------------------------------------
async def test_open_ports_are_fingerprinted():
    strategy = FakeStrategy({22: [PortState.OPEN]})
    report = await ScanService(strategy).scan_host(ScanTarget("127.0.0.1", (22,)))
    port = report.host.ports[0]
    assert port.service == "ssh" and port.product == "OpenSSH" and port.version == "9.6p1"


async def test_closed_ports_are_not_fingerprinted():
    strategy = FakeStrategy({22: [PortState.CLOSED]})
    report = await ScanService(strategy).scan_host(ScanTarget("127.0.0.1", (22,)))
    assert report.host.ports[0].product is None


async def test_results_are_sorted_by_port():
    strategy = FakeStrategy()
    report = await ScanService(strategy).scan_host(ScanTarget("127.0.0.1", (443, 22, 80)))
    assert [p.port for p in report.host.ports] == [22, 80, 443]


async def test_run_emits_to_every_sink():
    sinks = [RecordingSink(), RecordingSink()]
    service = ScanService(FakeStrategy(), sinks=sinks)
    await service.run(ScanTarget("127.0.0.1", (80,)))
    assert all(len(sink.reports) == 1 for sink in sinks)


async def test_scan_host_does_not_emit():
    sink = RecordingSink()
    service = ScanService(FakeStrategy(), sinks=[sink])
    await service.scan_host(ScanTarget("127.0.0.1", (80,)))
    assert sink.reports == []


async def test_report_carries_the_strategy_name_and_a_duration():
    report = await ScanService(FakeStrategy()).scan_host(ScanTarget("127.0.0.1", (80,)))
    assert report.scan_type == "fake"
    assert report.duration_s >= 0


# --------------------------------------------------------------------------
# resolution
# --------------------------------------------------------------------------
async def test_a_literal_address_is_probed_as_given():
    strategy = FakeStrategy()
    report = await ScanService(strategy).scan_host(ScanTarget("127.0.0.1", (80,)))
    assert strategy.hosts == ["127.0.0.1"]
    assert report.host.ip == "127.0.0.1"


async def test_an_unresolvable_host_still_gets_probed_by_name():
    strategy = FakeStrategy()
    target = ScanTarget("host.invalid.example.", (80,))
    report = await ScanService(strategy).scan_host(target)
    assert report.host.ip is None
    assert strategy.hosts == ["host.invalid.example."]


async def test_resolution_does_not_block_the_event_loop():
    """The resolver must be awaitable: a blocking call here would deadlock."""
    ticks = 0

    async def heartbeat():
        nonlocal ticks
        for _ in range(3):
            await asyncio.sleep(0)
            ticks += 1

    beat = asyncio.create_task(heartbeat())
    await ScanService(FakeStrategy()).scan_host(ScanTarget("127.0.0.1", (80,)))
    await beat
    assert ticks == 3


# --------------------------------------------------------------------------
# pacing
# --------------------------------------------------------------------------
async def test_max_rate_spaces_probes_out():
    strategy = FakeStrategy()
    loop = asyncio.get_running_loop()
    start = loop.time()
    await ScanService(strategy).scan_host(
        ScanTarget("127.0.0.1", (1, 2, 3, 4)), max_rate=20
    )
    # Four probes at 20/s means the last one cannot start before 150ms.
    assert loop.time() - start >= 0.1


async def test_a_shared_limiter_is_used_instead_of_building_one():
    limiter = AsyncRateLimiter(1000)
    await ScanService(FakeStrategy()).scan_host(
        ScanTarget("127.0.0.1", (1, 2)), max_rate=1, limiter=limiter
    )  # max_rate=1 would take seconds if the shared limiter were ignored


# --------------------------------------------------------------------------
# the sweep, and the bug that made --max-rate a lie
# --------------------------------------------------------------------------
async def test_sweep_only_scans_hosts_that_answered():
    strategy = FakeStrategy()
    discovery = FakeDiscovery({"10.0.0.1", "10.0.0.3"})
    service = SweepService(ScanService(strategy), discovery, ports=(80,))
    report = await service.run("10.0.0.0/29")
    assert report.total_candidates == 6
    assert report.up_count == 2
    assert {r.host.host for r in report.hosts} == {"10.0.0.1", "10.0.0.3"}


async def test_sweep_without_discovery_scans_everything():
    service = SweepService(ScanService(FakeStrategy()), FakeDiscovery(set()), ports=(80,))
    report = await service.run("10.0.0.0/30", discover=False)
    assert report.up_count == report.total_candidates == 2


async def test_sweep_rate_limit_is_shared_across_hosts():
    """The whole point: 4 probes/sec means 4 in total, not 4 per host."""
    strategy = FakeStrategy()
    discovery = FakeDiscovery({"10.0.0.1", "10.0.0.2", "10.0.0.3"})
    service = SweepService(ScanService(strategy), discovery, ports=(80, 443))
    loop = asyncio.get_running_loop()
    start = loop.time()
    await service.run("10.0.0.0/29", max_rate=100)
    # 6 discovery probes + 6 port probes at 100/s is at least ~110ms; a
    # per-host limiter would come in several times faster.
    assert loop.time() - start >= 0.05


async def test_sweep_passes_retries_down():
    strategy = FakeStrategy({80: [PortState.FILTERED]})
    service = SweepService(
        ScanService(strategy), FakeDiscovery({"10.0.0.1"}), ports=(80,)
    )
    await service.run("10.0.0.1", retries=2)
    assert strategy.calls[80] == 3


async def test_sweep_emits_to_its_sinks():
    sink = RecordingSink()
    service = SweepService(
        ScanService(FakeStrategy()), FakeDiscovery({"10.0.0.1"}), ports=(80,), sinks=[sink]
    )
    await service.run("10.0.0.1")
    assert len(sink.reports) == 1


async def test_sweep_rejects_a_range_that_is_too_large():
    service = SweepService(ScanService(FakeStrategy()), FakeDiscovery(set()), ports=(80,))
    with pytest.raises(ValueError, match="too large"):
        await service.run("10.0.0.0/8")
