"""Capture containers: classic pcap in both byte orders and both time bases,
pcapng as Wireshark actually writes it, and a write/read round trip.

The pcapng cases exist because Wireshark's DEFAULT save format used to be a
file this tool refused to open.
"""

from __future__ import annotations

import struct

import pytest

from pyscan.adapters.capture.pcap_reader import read_pcap
from pyscan.adapters.capture.pcap_writer import write_pcap
from pyscan.domain.ot_traffic import build_frames


# --------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------
def classic(frames, magic=0xA1B2C3D4, endian="<", linktype=1, frac=0):
    out = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for i, frame in enumerate(frames):
        out += struct.pack(endian + "IIII", 1000 + i, frac, len(frame), len(frame)) + frame
    return out


def _block(block_type: str, body: bytes, endian: str = "<") -> bytes:
    total = len(body) + 12
    return (
        struct.pack(endian + "I", int(block_type, 16))
        + struct.pack(endian + "I", total)
        + body
        + struct.pack(endian + "I", total)
    )


def pcapng(frames, endian="<", linktype=1, tsresol=None):
    shb_body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    options = b""
    if tsresol is not None:
        options = struct.pack(endian + "HH", 9, 1) + bytes([tsresol, 0, 0, 0])
        options += struct.pack(endian + "HH", 0, 0)
    idb_body = struct.pack(endian + "HHI", linktype, 0, 65535) + options

    out = _block("0A0D0D0A", shb_body, endian) + _block("00000001", idb_body, endian)
    for i, frame in enumerate(frames):
        padding = b"\x00" * (-len(frame) % 4)
        epb_body = (
            struct.pack(endian + "IIIII", 0, 0, 1_000_000 + i, len(frame), len(frame))
            + frame
            + padding
        )
        out += _block("00000006", epb_body, endian)
    return out


# --------------------------------------------------------------------------
# classic pcap
# --------------------------------------------------------------------------
def test_reads_records_in_order(tmp_path):
    frames = [b"\xaa" * 20, b"\xbb" * 30, b"\xcc" * 14]
    path = tmp_path / "t.pcap"
    path.write_bytes(classic(frames))
    records = list(read_pcap(path))
    assert [len(f) for _, _, f in records] == [20, 30, 14]
    assert records[0][0] == 1000.0


def test_reads_big_endian_captures(tmp_path):
    path = tmp_path / "be.pcap"
    # A big-endian capture carries the SAME magic value, written the other way up.
    path.write_bytes(classic([b"\x01" * 16], endian=">"))
    assert [len(f) for _, _, f in read_pcap(path)] == [16]


def test_microsecond_and_nanosecond_timestamps_differ(tmp_path):
    micro = tmp_path / "us.pcap"
    nano = tmp_path / "ns.pcap"
    micro.write_bytes(classic([b"\x00" * 8], frac=500_000))
    nano.write_bytes(classic([b"\x00" * 8], magic=0xA1B23C4D, frac=500_000_000))
    assert next(iter(read_pcap(micro)))[0] == pytest.approx(1000.5)
    assert next(iter(read_pcap(nano)))[0] == pytest.approx(1000.5)


def test_linktype_comes_from_the_global_header(tmp_path):
    path = tmp_path / "raw.pcap"
    path.write_bytes(classic([b"\x45" + b"\x00" * 19], linktype=101))
    assert next(iter(read_pcap(path)))[1] == 101


def test_truncated_final_record_is_dropped_not_yielded(tmp_path):
    path = tmp_path / "cut.pcap"
    path.write_bytes(classic([b"\xaa" * 20])[:-5])
    assert list(read_pcap(path)) == []


def test_rejects_non_capture_files(tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(b"not a pcap file at all..........")
    with pytest.raises(ValueError, match="bad magic"):
        list(read_pcap(path))


def test_rejects_an_empty_file(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    with pytest.raises(ValueError, match="too short"):
        list(read_pcap(path))


def test_rejects_an_implausible_record_length(tmp_path):
    path = tmp_path / "huge.pcap"
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    path.write_bytes(header + struct.pack("<IIII", 0, 0, 2**30, 2**30))
    with pytest.raises(ValueError, match="Implausible record"):
        list(read_pcap(path))


# --------------------------------------------------------------------------
# pcapng
# --------------------------------------------------------------------------
def test_reads_pcapng(tmp_path):
    frames = [b"\xaa" * 20, b"\xbb" * 33]
    path = tmp_path / "t.pcapng"
    path.write_bytes(pcapng(frames))
    records = list(read_pcap(path))
    assert [len(f) for _, _, f in records] == [20, 33]
    assert records[0][0] == pytest.approx(1.0)  # 1_000_000 us


def test_reads_big_endian_pcapng(tmp_path):
    path = tmp_path / "be.pcapng"
    path.write_bytes(pcapng([b"\x01" * 12], endian=">"))
    assert [len(f) for _, _, f in read_pcap(path)] == [12]


def test_pcapng_linktype_comes_from_the_interface_block(tmp_path):
    path = tmp_path / "sll.pcapng"
    path.write_bytes(pcapng([b"\x00" * 20], linktype=113))
    assert next(iter(read_pcap(path)))[1] == 113


def test_pcapng_honours_if_tsresol(tmp_path):
    path = tmp_path / "ns.pcapng"
    path.write_bytes(pcapng([b"\x00" * 8], tsresol=9))  # nanoseconds
    assert next(iter(read_pcap(path)))[0] == pytest.approx(0.001)


def test_pcapng_skips_unknown_blocks(tmp_path):
    path = tmp_path / "extra.pcapng"
    data = pcapng([b"\xaa" * 16])
    data += _block("00000005", b"\x00" * 16)  # an Interface Statistics block
    data += pcapng([b"\xbb" * 16])[len(pcapng([])) :]  # one more packet block
    path.write_bytes(data)
    assert [len(f) for _, _, f in read_pcap(path)] == [16, 16]


def test_pcapng_simple_packet_block(tmp_path):
    body = struct.pack("<I", 12) + b"\xcd" * 12
    data = pcapng([]) + _block("00000003", body)
    path = tmp_path / "spb.pcapng"
    path.write_bytes(data)
    assert [len(f) for _, _, f in read_pcap(path)] == [12]


def test_pcapng_with_a_corrupt_block_length_is_rejected(tmp_path):
    data = bytearray(pcapng([b"\xaa" * 16]))
    struct.pack_into("<I", data, len(pcapng([])) + 4, 2**30)
    path = tmp_path / "bad.pcapng"
    path.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="Implausible pcapng"):
        list(read_pcap(path))


# --------------------------------------------------------------------------
# writing
# --------------------------------------------------------------------------
def test_write_then_read_round_trip(tmp_path):
    frames = [(1_700_000_000.25, b"\xaa" * 40), (1_700_000_001.75, b"\xbb" * 60)]
    path = tmp_path / "out.pcap"
    assert write_pcap(path, frames) == 2

    records = list(read_pcap(path))
    assert [len(f) for _, _, f in records] == [40, 60]
    assert records[0][0] == pytest.approx(1_700_000_000.25)
    assert records[1][0] == pytest.approx(1_700_000_001.75)


def test_scenario_survives_a_round_trip(tmp_path):
    path = tmp_path / "lab.pcap"
    write_pcap(path, build_frames())
    assert len(list(read_pcap(path))) == len(build_frames())
