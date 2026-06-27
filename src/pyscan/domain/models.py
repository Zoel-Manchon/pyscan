"""Core domain model. Pure data — no sockets, no I/O, no framework imports.

Everything in here can be constructed and tested in memory. That is the whole
point of keeping the domain isolated: the interesting logic stays trivial to
reason about and to unit-test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"  # no response — firewall/drop, or host down
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """What we were asked to scan."""

    host: str
    ports: tuple[int, ...]
    protocol: Protocol = Protocol.TCP


@dataclass(frozen=True, slots=True)
class PortResult:
    """Outcome for a single probed port."""

    port: int
    state: PortState
    service: str | None = None
    product: str | None = None
    version: str | None = None
    latency_ms: float | None = None
    banner: str | None = None


@dataclass(slots=True)
class HostResult:
    """All port outcomes for one host."""

    host: str
    ip: str | None
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state is PortState.OPEN]


@dataclass(slots=True)
class ScanReport:
    """The full result of a single-host scan, ready for any output sink."""

    target: ScanTarget
    host: HostResult
    scan_type: str
    started_at: datetime
    duration_s: float


@dataclass(slots=True)
class NetworkReport:
    """Aggregate of a host-discovery sweep: one ScanReport per UP host."""

    network: str
    hosts: list[ScanReport]
    total_candidates: int
    up_count: int
    duration_s: float
