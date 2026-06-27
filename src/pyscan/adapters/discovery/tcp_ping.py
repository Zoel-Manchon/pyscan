"""TCP-ping host discovery — the unprivileged ping sweep.

ICMP echo (a real ping) needs raw sockets / root and is awkward on Windows, so
instead we knock on a few common ports. The key insight: we don't care whether
the port is open. If the host sends back ANYTHING — an open handshake OR a
refusal (RST) — it's alive. Only total silence (timeout) on every ping port
means down/filtered. That's exactly nmap's TCP-ping logic, no privileges needed.
"""

from __future__ import annotations

import asyncio

DEFAULT_PING_PORTS = (80, 443, 22, 3389)


class TcpPingDiscovery:
    def __init__(self, ping_ports: tuple[int, ...] = DEFAULT_PING_PORTS, **_ignored) -> None:
        self._ports = tuple(ping_ports)

    async def is_up(self, host: str, timeout: float) -> bool:
        async def probe(port: int) -> bool:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
            except ConnectionRefusedError:
                return True  # RST -> the host is there
            except (asyncio.TimeoutError, OSError):
                return False  # silence -> assume down/filtered
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return True  # open handshake -> definitely up

        results = await asyncio.gather(*(probe(p) for p in self._ports))
        return any(results)
