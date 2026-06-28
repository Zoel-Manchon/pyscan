"""Read a classic .pcap file -> a stream of (timestamp, linktype, raw_bytes).

Parses the libpcap format directly (global header + per-record headers),
handling both byte orders via the magic number. File I/O only; the decoding
of the bytes is the domain's job.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path

_MAGIC_LE = 0xA1B2C3D4  # little-endian (microsecond) capture
_MAGIC_BE = 0xD4C3B2A1


def read_pcap(path: str | Path) -> Iterator[tuple[float, int, bytes]]:
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise ValueError("File too short to be a pcap.")

    magic = struct.unpack("<I", data[:4])[0]
    if magic == _MAGIC_LE:
        endian = "<"
    elif struct.unpack(">I", data[:4])[0] == _MAGIC_BE:
        endian = ">"
    else:
        raise ValueError("Not a pcap file (bad magic number).")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
            endian + "IIII", data[offset:offset + 16]
        )
        offset += 16
        frame = data[offset:offset + incl_len]
        offset += incl_len
        if len(frame) < incl_len:
            break  # truncated final record
        yield ts_sec + ts_usec / 1_000_000, linktype, frame
