"""Read a capture file -> a stream of (timestamp, linktype, raw_bytes).

Two on-disk formats are supported, chosen by the magic number:

  * classic libpcap (.pcap) — global header + fixed 16-byte record headers, in
    either byte order and with either microsecond or nanosecond timestamps.
  * pcapng (.pcapng) — the block-structured successor, and what Wireshark
    writes by DEFAULT. Section Header, Interface Description, Enhanced Packet
    and Simple Packet blocks are understood; every other block (name
    resolution, statistics, ...) is skipped by its own length field.

The file is read incrementally, never slurped whole, so a multi-gigabyte
capture from a real exercise streams through in constant memory. Decoding the
frame bytes is the domain's job (`pyscan.domain.packet`); this module only
knows about file containers.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

# Classic libpcap magics. The 3C/4D pair marks nanosecond-resolution captures.
_MAGIC_USEC_LE = b"\xd4\xc3\xb2\xa1"
_MAGIC_USEC_BE = b"\xa1\xb2\xc3\xd4"
_MAGIC_NSEC_LE = b"\x4d\x3c\xb2\xa1"
_MAGIC_NSEC_BE = b"\xa1\xb2\x3c\x4d"
_CLASSIC_MAGICS = (_MAGIC_USEC_LE, _MAGIC_USEC_BE, _MAGIC_NSEC_LE, _MAGIC_NSEC_BE)

# pcapng block types we care about.
_BT_SHB = 0x0A0D0D0A
_BT_IDB = 0x00000001
_BT_PB = 0x00000002  # obsolete Packet Block, still found in old files
_BT_SPB = 0x00000003
_BT_EPB = 0x00000006

_SHB_MAGIC = 0x1A2B3C4D  # byte-order magic, read with the guessed endianness
_MAX_BLOCK = 64 * 1024 * 1024  # sanity cap: refuse absurd block lengths


def read_pcap(path: str | Path) -> Iterator[tuple[float, int, bytes]]:
    """Yield (epoch_seconds, pcap linktype, frame bytes) for every packet.

    Accepts classic pcap and pcapng alike, so a capture straight out of
    Wireshark works with no conversion step.
    """
    with Path(path).open("rb") as handle:
        magic = handle.read(4)
        if len(magic) < 4:
            raise ValueError("File too short to be a capture.")
        if magic in _CLASSIC_MAGICS:
            yield from _read_classic(handle, magic)
        elif _BT_SHB in (struct.unpack("<I", magic)[0], struct.unpack(">I", magic)[0]):
            yield from _read_pcapng(handle)
        else:
            raise ValueError("Not a pcap or pcapng file (bad magic number).")


# ---------------------------------------------------------------------------
# classic libpcap
# ---------------------------------------------------------------------------
def _read_classic(handle: BinaryIO, magic: bytes) -> Iterator[tuple[float, int, bytes]]:
    endian = "<" if magic in (_MAGIC_USEC_LE, _MAGIC_NSEC_LE) else ">"
    # Nanosecond captures store the sub-second field in ns, not us.
    divisor = 1e9 if magic in (_MAGIC_NSEC_LE, _MAGIC_NSEC_BE) else 1e6

    rest = handle.read(20)  # the remaining 20 bytes of the 24-byte global header
    if len(rest) < 20:
        raise ValueError("Truncated pcap global header.")
    linktype = struct.unpack(endian + "I", rest[16:20])[0]

    header = struct.Struct(endian + "IIII")
    while True:
        raw = handle.read(16)
        if len(raw) < 16:
            return  # clean EOF, or a truncated trailing record
        ts_sec, ts_frac, incl_len, _orig_len = header.unpack(raw)
        if incl_len > _MAX_BLOCK:
            raise ValueError(f"Implausible record length ({incl_len} bytes) - corrupt capture.")
        frame = handle.read(incl_len)
        if len(frame) < incl_len:
            return  # truncated final packet: stop rather than yield a partial frame
        yield ts_sec + ts_frac / divisor, linktype, frame


# ---------------------------------------------------------------------------
# pcapng
# ---------------------------------------------------------------------------
def _read_pcapng(handle: BinaryIO) -> Iterator[tuple[float, int, bytes]]:
    handle.seek(0)
    # Interfaces are declared as the file goes; a packet names its interface by
    # index, and that index carries the linktype and the timestamp resolution.
    interfaces: list[tuple[int, float]] = []
    endian = "<"

    while True:
        head = handle.read(8)
        if len(head) < 8:
            return
        block_type = struct.unpack(endian + "I", head[:4])[0]

        if block_type == _BT_SHB:
            endian, total = _read_shb_header(handle, head)
            interfaces = []  # a new section resets the interface table
            # 12 bytes are already consumed (type, length, byte-order magic);
            # skip the rest of the body AND the trailing total-length field, or
            # every following block reads off by four bytes.
            remaining = total - 16
            if len(handle.read(remaining)) < remaining or len(handle.read(4)) < 4:
                return
            continue

        total = struct.unpack(endian + "I", head[4:8])[0]
        if total < 12 or total > _MAX_BLOCK:
            raise ValueError(f"Implausible pcapng block length ({total} bytes) - corrupt capture.")
        body = handle.read(total - 12)
        if len(body) < total - 12 or len(handle.read(4)) < 4:
            return

        if block_type == _BT_IDB:
            interfaces.append(_parse_idb(body, endian))
        elif block_type == _BT_EPB:
            packet = _parse_epb(body, endian, interfaces)
            if packet is not None:
                yield packet
        elif block_type == _BT_SPB:
            if len(body) >= 4:
                linktype, _divisor = _interface(interfaces, 0)
                yield 0.0, linktype, body[4:]
        elif block_type == _BT_PB:
            packet = _parse_obsolete_pb(body, endian, interfaces)
            if packet is not None:
                yield packet
        # Anything else is skipped by its length - which is exactly the point
        # of pcapng being self-describing.


def _read_shb_header(handle: BinaryIO, head: bytes) -> tuple[str, int]:
    """Pin this section's byte order down from the SHB; return (endian, length).

    Leaves the handle positioned right after the byte-order magic, i.e. 16
    bytes into the block.
    """
    magic = handle.read(4)
    if len(magic) < 4:
        raise ValueError("Truncated pcapng section header.")
    endian = "<" if struct.unpack("<I", magic)[0] == _SHB_MAGIC else ">"
    if struct.unpack(endian + "I", magic)[0] != _SHB_MAGIC:
        raise ValueError("Bad pcapng byte-order magic.")
    total = struct.unpack(endian + "I", head[4:8])[0]
    if total < 16 or total > _MAX_BLOCK:
        raise ValueError(f"Implausible pcapng section length ({total} bytes).")
    return endian, total


def _parse_idb(body: bytes, endian: str) -> tuple[int, float]:
    """Interface Description Block -> (linktype, timestamp divisor)."""
    if len(body) < 8:
        return 1, 1e6
    linktype = struct.unpack(endian + "H", body[:2])[0]
    return linktype, _timestamp_divisor(body[8:], endian)


def _timestamp_divisor(options: bytes, endian: str) -> float:
    """Read if_tsresol (option 9): timestamps count units of 1/divisor seconds.

    A set high bit means the value is a power of two, otherwise a power of ten.
    An absent option means microseconds, which is what almost every writer emits.
    """
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[offset : offset + 4])
        if code == 0:  # opt_endofopt
            break
        value = options[offset + 4 : offset + 4 + length]
        if code == 9 and length >= 1:
            raw = value[0]
            return float(2 ** (raw & 0x7F)) if raw & 0x80 else float(10**raw)
        offset += 4 + length + (-length % 4)  # options are padded to 4 bytes
    return 1e6


def _parse_epb(
    body: bytes, endian: str, interfaces: list[tuple[int, float]]
) -> tuple[float, int, bytes] | None:
    if len(body) < 20:
        return None
    iface_id, ts_high, ts_low, caplen, _origlen = struct.unpack(endian + "IIIII", body[:20])
    linktype, divisor = _interface(interfaces, iface_id)
    frame = body[20 : 20 + caplen]
    if len(frame) < caplen:
        return None
    return ((ts_high << 32) | ts_low) / divisor, linktype, frame


def _parse_obsolete_pb(
    body: bytes, endian: str, interfaces: list[tuple[int, float]]
) -> tuple[float, int, bytes] | None:
    if len(body) < 20:
        return None
    iface_id, _drops, ts_high, ts_low, caplen, _origlen = struct.unpack(
        endian + "HHIIII", body[:20]
    )
    linktype, divisor = _interface(interfaces, iface_id)
    frame = body[20 : 20 + caplen]
    if len(frame) < caplen:
        return None
    return ((ts_high << 32) | ts_low) / divisor, linktype, frame


def _interface(interfaces: list[tuple[int, float]], index: int) -> tuple[int, float]:
    if 0 <= index < len(interfaces):
        return interfaces[index]
    return 1, 1e6  # a packet before any IDB: assume Ethernet / microseconds
