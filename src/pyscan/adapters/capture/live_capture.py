"""Live packet capture via AF_PACKET (Linux, privileged).

The live counterpart to pcap_reader: same output shape — a stream of
(timestamp, linktype, raw_bytes) — so anything that consumes captures (the
table, the TUI) doesn't care whether frames come from a file or the wire.

AF_PACKET is Linux-only and needs CAP_NET_RAW (root). On a timeout it yields
None as a heartbeat, so a consumer (the TUI) can notice a quit request between
packets instead of blocking forever inside recvfrom.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator

from pyscan.domain.packet import LINKTYPE_ETHERNET

_ETH_P_ALL = 0x0003
_HINT = (
    "Live capture needs Linux AF_PACKET + root. Try: sudo .venv/bin/pyscan ... "
    "(or read a .pcap file instead with: pyscan sniff capture.pcap)."
)


def live_capture(
    iface: str | None = None, poll: float = 0.3
) -> Iterator[tuple[float, int, bytes] | None]:
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("Live capture requires Linux (AF_PACKET). Use a .pcap on this OS.")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
    except PermissionError as exc:
        raise RuntimeError(_HINT) from exc
    except OSError as exc:
        raise RuntimeError(_HINT) from exc
    if iface:
        sock.bind((iface, 0))
    sock.settimeout(poll)
    try:
        while True:
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                yield None  # heartbeat: lets the consumer check for a quit
                continue
            yield time.time(), LINKTYPE_ETHERNET, data
    finally:
        sock.close()
