import struct

from pyscan.domain.s7comm import (
    S7Info,
    build_connection_request,
    describe,
    is_connection_confirm,
    parse_szl,
)


def _tpkt(payload):
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(payload)) + payload


def test_connection_request_is_well_formed():
    cr = build_connection_request(rack=0, slot=2)
    assert cr[0] == 0x03           # TPKT version
    assert cr[5] == 0xE0           # COTP Connection Request
    assert cr[-2:] == bytes([0x01, 0x02])  # dst TSAP: conn-type 1, rack0/slot2


def test_connection_confirm_detection():
    cc = _tpkt(bytes([0x06, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00]))
    assert is_connection_confirm(cc)
    assert not is_connection_confirm(build_connection_request())


def test_parse_szl_extracts_order_number():
    cotp = bytes([0x02, 0xF0, 0x80])
    param = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
    record = b"6ES7 315-2EH14-0AB0 " + bytes(8)
    section = bytes([0xFF, 0x09, 0x00, 0x20, 0x00, 0x11, 0x00, 0x01, 0x00, 0x1C, 0x00, 0x01]) + record
    s7 = bytes([0x32, 0x07, 0x00, 0x00, 0x00, 0x02]) + struct.pack(">HH", len(param), len(section))
    frame = _tpkt(cotp + s7 + param + section)

    info = parse_szl(frame)
    assert info.is_s7
    assert info.order_number == "6ES7 315-2EH14-0AB0"


def test_parse_non_s7_returns_none():
    assert parse_szl(b"HTTP/1.1 200 OK\r\n\r\n") is None


def test_describe():
    assert describe(S7Info(True, "6ES7 315-2EH14-0AB0")) == "S7comm 6ES7 315-2EH14-0AB0"
    assert describe(S7Info(True)) == "S7comm"
    assert describe(None) is None
