"""UDP scan strategy — unprivileged, async, with protocol-aware payloads.

The trick that avoids raw sockets: a *connected* UDP socket. When you connect a
UDP socket and the target port is closed, the OS delivers the ICMP
port-unreachable back as a connection error — so we can tell CLOSED from OPEN
without root. The three outcomes:

  - a reply            -> OPEN
  - connection error   -> CLOSED  (ICMP port-unreachable was received)
  - timeout            -> OPEN_FILTERED  (silence is genuinely ambiguous in UDP)

Each port gets a protocol-correct payload (DNS, SNMP, NTP, DNP3, Modbus/UDP)
so silent-by-default services actually answer.

This runs on asyncio's own datagram endpoints rather than threads. That matters
for more than tidiness: a thread-per-probe design is silently capped by the
default executor (min(32, cpu+4) workers), so `--concurrency 500` used to be a
promise the UDP scanner could not keep. Now the concurrency knob is real, and
IPv6 targets work by picking the address family from the target itself.
"""

from __future__ import annotations

import asyncio
import time

from pyscan.adapters.strategies.registry import register
from pyscan.domain.models import PortResult, PortState
from pyscan.domain.targets import family_of
from pyscan.domain.udp_probes import payload_for


def _ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000


def _preview(data: bytes) -> str:
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:24])
    return f"udp reply {len(data)}B: {text}"


class _ProbeProtocol(asyncio.DatagramProtocol):
    """Resolves a future on the first reply or the first socket error."""

    def __init__(self, done: asyncio.Future[bytes]) -> None:
        self._done = done

    def datagram_received(self, data: bytes, addr: object) -> None:
        if not self._done.done():
            self._done.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._done.done():
            self._done.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None and not self._done.done():
            self._done.set_exception(exc)


@register("udp")
class UdpScan:
    name = "udp"

    def __init__(self, **_ignored: object) -> None:
        pass

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        loop = asyncio.get_running_loop()
        done: asyncio.Future[bytes] = loop.create_future()
        start = time.perf_counter()

        try:
            transport, _protocol = await loop.create_datagram_endpoint(
                lambda: _ProbeProtocol(done),
                remote_addr=(host, port),
                family=family_of(host),
            )
        except OSError:
            return PortResult(port, PortState.FILTERED)

        try:
            transport.sendto(payload_for(port))
            data = await asyncio.wait_for(done, timeout=timeout)
        except TimeoutError:
            return PortResult(port, PortState.OPEN_FILTERED)
        except (ConnectionRefusedError, ConnectionResetError):
            # Windows surfaces the same ICMP as a reset rather than a refusal.
            return PortResult(port, PortState.CLOSED, latency_ms=_ms(start))
        except OSError:
            return PortResult(port, PortState.FILTERED)
        finally:
            transport.close()

        return PortResult(port, PortState.OPEN, latency_ms=_ms(start), banner=_preview(data))
