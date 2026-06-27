"""TCP connect scan — unprivileged probing with banner collection.

This strategy is now strictly the I/O half of recon. It decides port state and
collects the best raw banner it can; it does NOT interpret that banner. Turning
bytes into "OpenSSH 9.6" is the job of the pure fingerprint engine, run as a
later enrichment stage. Keeping probe and identify apart is what lets each be
tested and extended on its own.

State logic:
  - handshake succeeds        -> OPEN
  - connection refused (RST)  -> CLOSED
  - timeout / no response     -> FILTERED

Banner logic on OPEN ports:
  - read what the service volunteers (SSH/FTP/SMTP/... speak first)
  - if it stays silent and http_probe is on, send one minimal HEAD request to
    coax a 'Server:' header out of web servers (which speak only when spoken to)
"""

from __future__ import annotations

import asyncio
import time

from pyscan.adapters.strategies.registry import register
from pyscan.domain.models import PortResult, PortState

_HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"


@register("tcp-connect")
class TcpConnectScan:
    name = "tcp-connect"

    def __init__(
        self,
        *,
        grab_banner: bool = True,
        http_probe: bool = True,
        banner_bytes: int = 512,
        **_ignored,
    ) -> None:
        self._grab_banner = grab_banner
        self._http_probe = http_probe
        self._banner_bytes = banner_bytes

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
        if self._grab_banner:
            banner = await self._read(reader, timeout)
            if self._http_probe and not banner:
                banner = await self._nudge(reader, writer, timeout)

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

        return PortResult(port, PortState.OPEN, latency_ms=latency, banner=banner)

    async def _read(self, reader: asyncio.StreamReader, timeout: float) -> str | None:
        try:
            data = await asyncio.wait_for(reader.read(self._banner_bytes), timeout=timeout)
        except (asyncio.TimeoutError, OSError):
            return None
        return self._clean(data)

    async def _nudge(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float,
    ) -> str | None:
        try:
            writer.write(_HTTP_PROBE)
            await writer.drain()
        except OSError:
            return None
        return await self._read(reader, timeout)

    @staticmethod
    def _clean(data: bytes) -> str | None:
        if not data:
            return None
        # latin-1 maps every byte so binary banners never crash the decode.
        text = data.decode("latin-1", errors="replace")
        # Replace non-printables with spaces and collapse whitespace, so a
        # multi-line HTTP response becomes one searchable line that still
        # contains "Server: nginx/1.24.0" for the fingerprinter to find.
        text = "".join(ch if ch.isprintable() else " " for ch in text)
        text = " ".join(text.split())
        return text[:200] or None
