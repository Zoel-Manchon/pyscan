"""IEC 60870-5-104 identification strategy — read-only OT liveness check.

SAFETY: sends a single TESTFR (test/keepalive) frame and reads the reply. It
never starts data transfer, never issues a control command, never fuzzes.
Even so: SIMULATORS / lab gear you own only. In OT, the scan can be the incident.
"""

from __future__ import annotations

import asyncio
import time

from pyscan.adapters.strategies.registry import register
from pyscan.domain.iec104 import build_testfr_act, describe, parse_response
from pyscan.domain.models import PortResult, PortState


@register("iec104")
class Iec104Scan:
    name = "iec104"

    def __init__(self, **_ignored) -> None:
        pass

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except asyncio.TimeoutError:
            return PortResult(port, PortState.FILTERED)
        except ConnectionRefusedError:
            latency = (time.perf_counter() - start) * 1000
            return PortResult(port, PortState.CLOSED, latency_ms=latency)
        except OSError:
            return PortResult(port, PortState.FILTERED)

        latency = (time.perf_counter() - start) * 1000
        banner = None
        try:
            writer.write(build_testfr_act())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(64), timeout=timeout)
            banner = describe(parse_response(data))
        except (asyncio.TimeoutError, OSError):
            banner = None

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

        return PortResult(port, PortState.OPEN, latency_ms=latency, banner=banner)
