"""Shared fixtures.

The only real sockets in the whole suite live here: a loopback TCP listener and
a loopback UDP responder, both ephemeral. They exist so the two adapters that
genuinely cannot be faked — the connect scan and the UDP scan — are still
exercised against a real kernel socket rather than a mock of one.
"""

from __future__ import annotations

import contextlib
import socket
import threading

import pytest


@pytest.fixture
def tcp_server():
    """A loopback listener that accepts and immediately closes. Yields (host, port)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    stop = threading.Event()

    def serve() -> None:
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except (TimeoutError, OSError):
                continue
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()


@pytest.fixture
def udp_server():
    """A loopback UDP responder that echoes back whatever it is sent."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    stop = threading.Event()

    def serve() -> None:
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            with contextlib.suppress(OSError):
                sock.sendto(data or b"pong", addr)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()
