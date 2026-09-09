"""SYN (half-open) scan strategy — requires scapy + raw-socket privileges.

This is the one strategy that drops below the OS socket layer, so it needs
root (Linux: sudo) or admin + Npcap (Windows), or just run it from WSL2. scapy
is an OPTIONAL dependency: `pip install 'pyscan[syn]'`. The package is imported
lazily so the rest of the tool works fine without it — only `--type syn` needs it.

scapy's send/receive is blocking, so each probe runs in a worker thread to fit
the async engine. That means SYN concurrency is bounded by asyncio's default
thread pool (min(32, cpu+4)) rather than by `--concurrency`; for a privileged
scan of a handful of ports that is the right trade, and for a wide sweep the
unprivileged connect scan is both faster and honest about its limits.
"""

from __future__ import annotations

import asyncio
import contextlib
import time

from pyscan.adapters.strategies.registry import register
from pyscan.domain.models import PortResult, PortState
from pyscan.domain.syn import classify
from pyscan.domain.targets import is_ipv6

_HINT = (
    "SYN scan needs scapy + raw-socket privileges. "
    "Install: pip install 'pyscan[syn]'. Run as root (Linux: sudo) or as admin "
    "with Npcap (Windows), or from WSL2."
)


@register("syn")
class SynScan:
    name = "syn"

    def __init__(self, **_ignored: object) -> None:
        try:
            import scapy  # noqa: F401
        except ImportError as exc:
            raise RuntimeError(_HINT) from exc

    async def scan_port(self, host: str, port: int, timeout: float) -> PortResult:
        return await asyncio.to_thread(self._probe, host, port, timeout)

    @staticmethod
    def _probe(host: str, port: int, timeout: float) -> PortResult:
        from scapy.all import ICMP, IP, TCP, IPv6, conf, send, sr1
        from scapy.layers.inet6 import ICMPv6DestUnreach

        conf.verb = 0
        # Same TCP layer either way; only the network layer differs.
        network = IPv6(dst=host) if is_ipv6(host) else IP(dst=host)
        unreachable = (ICMP, ICMPv6DestUnreach)

        start = time.perf_counter()
        try:
            resp = sr1(network / TCP(dport=port, flags="S"), timeout=timeout)
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
                with contextlib.suppress(OSError):
                    send(network / TCP(dport=port, flags="R", seq=resp[TCP].ack), verbose=0)
            return PortResult(port, state, latency_ms=latency)

        if any(resp.haslayer(layer) for layer in unreachable):
            return PortResult(port, classify(None, icmp_unreachable=True), latency_ms=latency)

        return PortResult(port, PortState.FILTERED, latency_ms=latency)
