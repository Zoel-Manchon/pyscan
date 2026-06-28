"""UDP scan strategy — unprivileged, with protocol-aware payloads.

The trick that avoids raw sockets: a *connected* UDP socket. When you connect()
a UDP socket and the target port is closed, the OS delivers the ICMP
port-unreachable back as a ConnectionRefusedError on recv — so we can tell
CLOSED from OPEN without root. The three outcomes:

  - a reply            -> OPEN
  - ConnectionRefused  -> CLOSED  (ICMP port-unreachable was received)
  - timeout            -> OPEN_FILTERED  (silence is genuinely ambiguous in UDP)

Each port gets a protocol-correct payload (DNS, SNMP, NTP, DNP3, Modbus/UDP)
so silent-by-default services actually answer.
"""

from __future__ import annotations

import asyncio
import socket
import time

from pyscan.adapters.strategies.registry import register
from pyscan.domain.models import PortResult, PortState
from pyscan.domain.udp_probes import payload_for


def _ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000


def _preview(data: bytes) -> str:
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:24])
    return f"udp reply {len(data)}B: {text}"


@register("udp")
class UdpScan:
    name = "udp"

    def __init__(self, **_ignored) -> None:
        pass

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        return await asyncio.to_thread(self._probe, host, port, timeout)

    @staticmethod
    def _probe(host: str, port: int, timeout: float) -> PortResult:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.perf_counter()
        try:
            sock.connect((host, port))
            sock.send(payload_for(port))
            data = sock.recv(2048)
        except ConnectionRefusedError:
            return PortResult(port, PortState.CLOSED, latency_ms=_ms(start))
        except (TimeoutError, socket.timeout):
            return PortResult(port, PortState.OPEN_FILTERED)
        except OSError:
            return PortResult(port, PortState.FILTERED)
        finally:
            sock.close()
        return PortResult(port, PortState.OPEN, latency_ms=_ms(start), banner=_preview(data))
