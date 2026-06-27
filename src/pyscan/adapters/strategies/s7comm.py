"""S7comm identification strategy — read-only Siemens S7 PLC discovery.

Drives the three-step handshake (COTP connect -> S7 setup -> Read SZL) and
extracts the module order number. It never writes, never controls the CPU,
never downloads blocks.

SAFETY: SIMULATORS / lab gear you own only. Never against live OT.
"""

from __future__ import annotations

import asyncio
import time

from pyscan.adapters.strategies.registry import register
from pyscan.domain.models import PortResult, PortState
from pyscan.domain.s7comm import (
    build_connection_request,
    build_read_szl,
    build_setup_communication,
    describe,
    is_connection_confirm,
    is_s7_response,
    parse_szl,
)


@register("s7comm")
class S7CommScan:
    name = "s7comm"

    def __init__(self, *, rack: int = 0, slot: int = 2, **_ignored) -> None:
        self._rack = rack
        self._slot = slot

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
        banner = await self._identify(reader, writer, timeout)

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

        return PortResult(port, PortState.OPEN, latency_ms=latency, banner=banner)

    async def _identify(self, reader, writer, timeout) -> str | None:
        try:
            # 1. COTP connection
            writer.write(build_connection_request(self._rack, self._slot))
            await writer.drain()
            if not is_connection_confirm(await self._read_tpkt(reader, timeout)):
                return None  # open, but not speaking COTP/S7

            # 2. S7 setup communication
            writer.write(build_setup_communication())
            await writer.drain()
            await self._read_tpkt(reader, timeout)

            # 3. Read SZL (module identification)
            writer.write(build_read_szl())
            await writer.drain()
            response = await self._read_tpkt(reader, timeout)
        except (asyncio.TimeoutError, OSError, asyncio.IncompleteReadError):
            return None

        info = parse_szl(response)
        if info is None:
            return "S7comm" if is_s7_response(response) else None
        return describe(info)

    @staticmethod
    async def _read_tpkt(reader, timeout) -> bytes:
        """Read exactly one TPKT message (4-byte header carries total length)."""
        header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if header[0] != 0x03:
            return header
        total = (header[2] << 8) | header[3]
        rest = await asyncio.wait_for(reader.readexactly(total - 4), timeout=timeout)
        return header + rest
