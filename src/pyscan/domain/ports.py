"""Ports — the boundary of the hexagon.

These are the contracts the application layer depends on. Concrete adapters
(socket scanners, table/JSON output) implement them, but the core never
imports the adapters. New scan techniques and new output formats plug in here
without the engine ever changing.

We use typing.Protocol (structural typing) rather than ABCs: an adapter is a
valid ScanStrategy simply by having the right shape, so there is zero
inheritance coupling back to this module.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pyscan.domain.models import NetworkReport, PortResult, ScanReport


@runtime_checkable
class ScanStrategy(Protocol):
    """Knows how to probe ONE port. The 'how' of scanning lives here.

    The application layer owns concurrency and orchestration; a strategy only
    answers the question 'is this single port open?'.
    """

    name: str

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult: ...


@runtime_checkable
class HostDiscovery(Protocol):
    """Knows how to decide whether a host is alive (the ping-sweep step)."""

    async def is_up(self, host: str, timeout: float) -> bool: ...


@runtime_checkable
class ResultSink(Protocol):
    """Knows how to present/persist a single-host scan. The 'where to' of output."""

    def emit(self, report: ScanReport) -> None: ...


@runtime_checkable
class NetworkSink(Protocol):
    """Knows how to present/persist a multi-host sweep."""

    def emit(self, report: NetworkReport) -> None: ...
