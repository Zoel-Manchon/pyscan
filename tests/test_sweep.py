"""Sweep tests against real loopback sockets.

The whole 127.0.0.0/8 block is loopback, so 127.0.0.1 and 127.0.0.2 both answer
(open handshake or RST) — which lets us exercise multi-host discovery and the
NetworkReport aggregation without any external network.
"""

import asyncio

from pyscan.adapters.discovery.tcp_ping import TcpPingDiscovery
from pyscan.adapters.strategies.tcp_connect import TcpConnectScan
from pyscan.application.scan_service import ScanService
from pyscan.application.sweep_service import SweepService
from pyscan.domain.models import PortState


async def _server_on_loopback():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def test_discovery_marks_listening_host_up():
    server, port = await _server_on_loopback()
    try:
        disco = TcpPingDiscovery(ping_ports=(port,))
        assert await disco.is_up("127.0.0.1", timeout=1.0) is True
    finally:
        server.close()


async def test_discovery_silent_host_is_down(monkeypatch):
    # Force every probe to hang so wait_for times out -> the 'down' path,
    # deterministically, without depending on real network behaviour.
    from pyscan.adapters.discovery import tcp_ping

    async def hang(*args, **kwargs):
        await asyncio.sleep(10)

    monkeypatch.setattr(tcp_ping.asyncio, "open_connection", hang)
    disco = TcpPingDiscovery(ping_ports=(80, 443))
    assert await disco.is_up("10.255.255.1", timeout=0.2) is False


async def test_sweep_builds_inventory():
    server, port = await _server_on_loopback()
    try:
        scanner = ScanService(strategy=TcpConnectScan(grab_banner=False))
        sweep = SweepService(
            scanner=scanner,
            discovery=TcpPingDiscovery(ping_ports=(port,)),
            ports=(port,),
        )
        report = await sweep.run("127.0.0.1", timeout=1.0)
        assert report.up_count == 1
        assert report.total_candidates == 1
        host = report.hosts[0].host
        assert any(p.port == port and p.state is PortState.OPEN for p in host.open_ports)
    finally:
        server.close()
