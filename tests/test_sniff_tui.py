import asyncio
import socket
import struct

import pytest

pytest.importorskip("textual")

from textual.widgets import DataTable  # noqa: E402

from pyscan.adapters.output.sniff_tui import SniffApp  # noqa: E402


def _ipv4(proto, payload):
    return struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
        socket.inet_aton("1.1.1.1"), socket.inet_aton("2.2.2.2"),
    ) + payload


def _tcp_syn():
    return struct.pack(">HHIIBBHHH", 1111, 80, 0, 0, 0x50, 0x02, 0, 0, 0)


def _frames():
    eth = bytes(12) + b"\x08\x00" + _ipv4(6, _tcp_syn())
    return [(0.0, 1, eth), (0.1, 1, eth), (0.2, 1, eth)]


def test_tui_renders_packets_from_source():
    app = SniffApp(iter(_frames()), "test")

    async def drive():
        async with app.run_test() as pilot:
            await pilot.pause()
            for _ in range(40):  # wait for the thread worker to post messages
                await asyncio.sleep(0.05)
                if app._n >= 3:
                    break
            await pilot.pause()
            table = app.query_one("#packets", DataTable)
            assert table.row_count == 3
            assert app._counts.get("TCP") == 3
            # clear action empties the table
            await pilot.press("c")
            await pilot.pause()
            assert app.query_one("#packets", DataTable).row_count == 0

    asyncio.run(drive())

