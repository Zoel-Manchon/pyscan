"""Strategy tests that prove open/closed logic against a real local socket.

No socket mocking — we use a real ephemeral 127.0.0.1 port, which is fast,
deterministic, and needs no privileges. Probes are wrapped in wait_for so a
regression turns into a quick failure instead of a hang.
"""

import asyncio
import socket

from pyscan.adapters.strategies.tcp_connect import TcpConnectScan
from pyscan.domain.models import PortState


async def _handler(reader, writer):
    writer.close()


async def test_open_port_detected():
    server = await asyncio.start_server(_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await asyncio.wait_for(
            TcpConnectScan().scan_port("127.0.0.1", port, timeout=1.0), timeout=5
        )
        assert result.state is PortState.OPEN
        assert result.latency_ms is not None
    finally:
        server.close()  # deliberately no wait_closed(): it can hang on lingering conns


async def test_unopened_port_is_not_open():
    # Reserve an ephemeral port, then release it so nothing is listening.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    result = await asyncio.wait_for(
        TcpConnectScan().scan_port("127.0.0.1", port, timeout=1.0), timeout=5
    )
    # CLOSED (RST received) on Linux, FILTERED (no reply) on Windows — both are
    # valid "not accepting connections" outcomes. The invariant that holds
    # everywhere is: a port nobody listens on must never come back OPEN.
    assert result.state is not PortState.OPEN
    assert result.state in {PortState.CLOSED, PortState.FILTERED}


async def test_banner_is_captured():
    async def banner_handler(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(banner_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await asyncio.wait_for(
            TcpConnectScan(grab_banner=True).scan_port("127.0.0.1", port, 1.0), timeout=5
        )
        assert result.state is PortState.OPEN
        assert result.banner is not None
        assert "OpenSSH" in result.banner
    finally:
        server.close()


async def test_banner_can_be_disabled():
    async def banner_handler(reader, writer):
        writer.write(b"hello\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(banner_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await asyncio.wait_for(
            TcpConnectScan(grab_banner=False).scan_port("127.0.0.1", port, 1.0), timeout=5
        )
        assert result.state is PortState.OPEN
        assert result.banner is None
    finally:
        server.close()
