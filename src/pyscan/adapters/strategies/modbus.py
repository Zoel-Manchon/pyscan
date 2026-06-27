"""Modbus/TCP identification strategy — read-only OT asset discovery.

SAFETY: this sends exactly one 'Read Device Identification' request and reads
the reply. It never writes, never sends control commands, never fuzzes. Even
so, only run it against SIMULATORS or lab equipment you own — active probing of
live OT can disrupt a real PLC. In OT, the scan itself can be the incident.
"""

from __future__ import annotations

import asyncio
import time

from pyscan.adapters.strategies.registry import register
from pyscan.domain.models import PortResult, PortState
from pyscan.domain.modbus import build_device_id_request, describe, parse_response


@register("modbus")
class ModbusScan:
    name = "modbus"

    def __init__(self, *, unit: int = 1, **_ignored) -> None:
        self._unit = unit

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
            tid = 1
            writer.write(build_device_id_request(self._unit, tid))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            banner = describe(parse_response(data, tid))
        except (asyncio.TimeoutError, OSError):
            banner = None

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

        return PortResult(port, PortState.OPEN, latency_ms=latency, banner=banner)
