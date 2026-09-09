"""Write frames to a classic .pcap file — the mirror image of pcap_reader.

Small on purpose: the traffic generator that builds practice captures needs to
produce a real, Wireshark-openable file, and that is 24 bytes of global header
plus 16 bytes per record. Having it here means the OT lab no longer pulls in
scapy just to write a pcap.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from pathlib import Path

from pyscan.domain.packet import LINKTYPE_ETHERNET

_MAGIC_USEC_LE = 0xA1B2C3D4
_SNAPLEN = 65535


def write_pcap(
    path: str | Path,
    frames: Iterable[tuple[float, bytes]],
    linktype: int = LINKTYPE_ETHERNET,
) -> int:
    """Write (timestamp, frame bytes) pairs as a little-endian microsecond pcap.

    Returns the number of records written.
    """
    count = 0
    with Path(path).open("wb") as handle:
        handle.write(
            struct.pack("<IHHiIII", _MAGIC_USEC_LE, 2, 4, 0, 0, _SNAPLEN, linktype)
        )
        for ts, frame in frames:
            seconds = int(ts)
            micros = int(round((ts - seconds) * 1_000_000))
            if micros >= 1_000_000:  # rounding can tip over a whole second
                seconds += 1
                micros -= 1_000_000
            handle.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            handle.write(frame)
            count += 1
    return count
