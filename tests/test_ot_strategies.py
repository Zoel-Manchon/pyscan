"""The OT identification strategies, against scripted asyncio servers.

Each fake speaks just enough of the protocol to answer the one read-only probe
pyscan sends, which is also a check that the probe really is read-only: a server
that only knows how to answer a device-id request would break on anything else.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable

import pytest

from pyscan.adapters.strategies import get_strategy
from pyscan.domain import modbus, s7comm
from pyscan.domain.models import PortState

Responder = Callable[[bytes], bytes | None]


class Server:
    """A loopback server that answers each request with a scripted reply."""

    def __init__(self, responder: Responder) -> None:
        self._responder = responder
        self.requests: list[bytes] = []
        self._server: asyncio.AbstractServer | None = None

    async def __aenter__(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self._server.sockets[0].getsockname()[:2]

    async def __aexit__(self, *_exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader, writer) -> None:
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    return
                self.requests.append(data)
                reply = self._responder(data)
                if reply is None:
                    return
                writer.write(reply)
                await writer.drain()
        except (ConnectionError, OSError):
            return
        finally:
            # The server MUST close its half. Leaving it open makes the client's
            # wait_closed() hang forever on Windows.
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()


# --------------------------------------------------------------------------
# Modbus
# --------------------------------------------------------------------------
def modbus_device_id_reply(_request: bytes) -> bytes:
    objects = b""
    for obj_id, value in ((0, b"pyscan-lab"), (1, b"VPLC-01"), (2, b"1.4.2")):
        objects += bytes([obj_id, len(value)]) + value
    body = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x03]) + objects
    return modbus.build_device_id_request()[:6] + bytes([0x01]) + body


async def test_modbus_identifies_a_device():
    async with Server(modbus_device_id_reply) as (host, port):
        result = await get_strategy("modbus").scan_port(host, port, 2.0)
    assert result.state is PortState.OPEN
    assert result.banner == "Modbus/TCP pyscan-lab VPLC-01 v1.4.2"


async def test_modbus_sends_exactly_one_read_only_request():
    server = Server(modbus_device_id_reply)
    async with server as (host, port):
        await get_strategy("modbus").scan_port(host, port, 2.0)
    assert len(server.requests) == 1
    # 0x2B is Read Device Identification: a read, and the only thing we send.
    assert modbus.read_function_code(server.requests[0]) == 0x2B


async def test_modbus_port_open_but_silent_has_no_banner():
    async with Server(lambda _r: None) as (host, port):
        result = await get_strategy("modbus").scan_port(host, port, 0.3)
    assert result.state is PortState.OPEN and result.banner is None


async def test_modbus_reports_a_closed_port(unused_port):
    result = await get_strategy("modbus").scan_port("127.0.0.1", unused_port, 0.3)
    assert result.state in (PortState.CLOSED, PortState.FILTERED)


# --------------------------------------------------------------------------
# IEC-104
# --------------------------------------------------------------------------
async def test_iec104_confirms_liveness_with_a_testfr():
    def respond(_request: bytes) -> bytes:
        return bytes([0x68, 0x04, 0x83, 0x00, 0x00, 0x00])  # TESTFR con

    server = Server(respond)
    async with server as (host, port):
        result = await get_strategy("iec104").scan_port(host, port, 2.0)
    assert result.state is PortState.OPEN
    assert result.banner == "IEC 60870-5-104 (TESTFR con)"
    assert server.requests == [bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])]


async def test_iec104_ignores_a_reply_that_is_not_iec104():
    async with Server(lambda _r: b"HTTP/1.1 400 Bad Request\r\n\r\n") as (host, port):
        result = await get_strategy("iec104").scan_port(host, port, 2.0)
    assert result.state is PortState.OPEN and result.banner is None


# --------------------------------------------------------------------------
# S7comm
# --------------------------------------------------------------------------
def _tpkt(payload: bytes) -> bytes:
    return bytes([0x03, 0x00, 0x00, 4 + len(payload)]) + payload


def s7_plc(order: bytes = b"6ES7 315-2EH14-0AB0 "):
    """A fake S7 CPU: connection confirm, setup ack, then an SZL response."""
    step = {"n": 0}

    def respond(_request: bytes) -> bytes:
        step["n"] += 1
        if step["n"] == 1:
            return _tpkt(bytes([0x11, s7comm.COTP_CC]) + bytes(15))
        if step["n"] == 2:
            return _tpkt(bytes([0x02, 0xF0, 0x80]) + bytes([0x32, 0x03]) + bytes(10))
        header = bytes([0x02, 0xF0, 0x80]) + bytes([0x32, 0x07, 0, 0, 0, 2, 0, 8, 0, 0])
        parameter = bytes(8)
        data = bytes([0xFF, 0x09, 0x00, 0x00]) + bytes(8) + order + bytes(8)
        return _tpkt(header + parameter + data)

    return respond


async def test_s7comm_reads_the_module_order_number():
    async with Server(s7_plc()) as (host, port):
        result = await get_strategy("s7comm").scan_port(host, port, 2.0)
    assert result.state is PortState.OPEN
    assert result.banner is not None and result.banner.startswith("S7comm")
    assert "6ES7" in result.banner


async def test_s7comm_gives_up_politely_when_cotp_is_refused():
    async with Server(lambda _r: _tpkt(bytes([0x11, 0x80]) + bytes(15))) as (host, port):
        result = await get_strategy("s7comm").scan_port(host, port, 2.0)
    assert result.state is PortState.OPEN and result.banner is None


async def test_s7comm_survives_a_server_that_hangs_up():
    async with Server(lambda _r: None) as (host, port):
        result = await get_strategy("s7comm").scan_port(host, port, 0.5)
    assert result.state is PortState.OPEN and result.banner is None


# --------------------------------------------------------------------------
# the connect scan, for comparison
# --------------------------------------------------------------------------
async def test_tcp_connect_without_banner_grabbing_just_reports_the_state():
    async with Server(lambda _r: None) as (host, port):
        strategy = get_strategy("tcp-connect", grab_banner=False)
        result = await strategy.scan_port(host, port, 1.0)
    assert result.state is PortState.OPEN and result.banner is None


async def test_tcp_connect_nudges_a_silent_http_server():
    def respond(request: bytes) -> bytes:
        if request.startswith(b"HEAD "):
            return b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"
        return b""

    async with Server(respond) as (host, port):
        result = await get_strategy("tcp-connect").scan_port(host, port, 1.0)
    assert result.banner is not None and "nginx/1.24.0" in result.banner


async def test_tcp_connect_reports_a_dead_host_as_filtered():
    result = await get_strategy("tcp-connect").scan_port("192.0.2.1", 80, 0.2)
    assert result.state is PortState.FILTERED


@pytest.fixture
def unused_port() -> int:
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port
