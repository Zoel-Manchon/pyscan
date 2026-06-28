import struct
import tempfile
from pathlib import Path

from pyscan.adapters.capture.pcap_reader import read_pcap


def _build_pcap(frames, linktype=1):
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1000 + i, 0, len(f), len(f)) + f
    return out


def test_reads_records_in_order():
    frames = [b"\xaa" * 20, b"\xbb" * 30, b"\xcc" * 14]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "t.pcap"
        path.write_bytes(_build_pcap(frames))
        records = list(read_pcap(path))
    assert [len(f) for _, _, f in records] == [20, 30, 14]
    assert records[0][0] == 1000.0  # timestamp from ts_sec


def test_rejects_non_pcap():
    import pytest
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "x.bin"
        path.write_bytes(b"not a pcap file at all..........")
        with pytest.raises(ValueError):
            list(read_pcap(path))
