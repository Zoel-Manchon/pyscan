"""SYN (half-open) scan strategy — requires scapy + raw-socket privileges.

This is the one strategy that drops below the OS socket layer, so it needs
root (Linux: sudo) or admin + Npcap (Windows), or just run it from WSL2. scapy
is an OPTIONAL dependency: `pip install 'pyscan[syn]'`. The package is imported
lazily so the rest of the tool works fine without it — only `--type syn` needs it.

The blocking scapy send/recv runs in a worker thread so it fits the async engine.
"""

from __future__ import annotations

import asyncio
import time

from pyscan.adapters.strategies.registry import register
from pyscan.domain.models import PortResult, PortState
from pyscan.domain.syn import classify

_HINT = (
    "SYN scan needs scapy + raw-socket privileges. "
    "Install: pip install 'pyscan[syn]'. Run as root (Linux: sudo) or as admin "
    "with Npcap (Windows), or from WSL2."
)


@register("syn")
class SynScan:
    name = "syn"

    def __init__(self, **_ignored) -> None:
        try:
            import scapy  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(_HINT) from exc

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        return await asyncio.to_thread(self._probe, host, port, timeout)

    @staticmethod
    def _probe(host: str, port: int, timeout: float) -> PortResult:
        from scapy.all import ICMP, IP, TCP, conf, send, sr1

        conf.verb = 0
        start = time.perf_counter()
        try:
            resp = sr1(IP(dst=host) / TCP(dport=port, flags="S"), timeout=timeout)
        except PermissionError as exc:
            raise RuntimeError(_HINT) from exc
        except OSError:
            return PortResult(port, PortState.FILTERED)

        latency = (time.perf_counter() - start) * 1000
        if resp is None:
            return PortResult(port, PortState.FILTERED)

        if resp.haslayer(TCP):
            flags = int(resp[TCP].flags)
            state = classify(flags)
            if state is PortState.OPEN:
                # Half-open: tear the connection down with a RST instead of
                # completing the handshake (stealthier, lighter on the target).
                try:
                    send(IP(dst=host) / TCP(dport=port, flags="R", seq=resp[TCP].ack), verbose=0)
                except OSError:
                    pass
            return PortResult(port, state, latency_ms=latency)

        if resp.haslayer(ICMP):
            return PortResult(port, classify(None, icmp_unreachable=True), latency_ms=latency)

        return PortResult(port, PortState.FILTERED, latency_ms=latency)
