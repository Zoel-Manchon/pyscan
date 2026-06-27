from pyscan.domain.modbus import (
    ModbusInfo,
    build_device_id_request,
    describe,
    parse_response,
)


def test_request_is_well_formed():
    req = build_device_id_request(unit=1, tid=1)
    # MBAP: tid=0001 proto=0000 len=0005 unit=01 ; PDU: 2B 0E 01 00
    assert req == bytes.fromhex("000100000005012B0E0100")


def test_parse_device_identification():
    # Build a canned 'Read Device ID' response: vendor=Acme, product=PLC-1000, ver=1.2
    def obj(oid, val):
        return bytes([oid, len(val)]) + val
    objs = obj(0x00, b"Acme") + obj(0x01, b"PLC-1000") + obj(0x02, b"1.2")
    pdu = bytes([0x2B, 0x0E, 0x01, 0x81, 0x00, 0x00, 0x03]) + objs
    mbap = bytes.fromhex("000100000000") + bytes([len(pdu) + 1, 0x01])[1:]  # placeholder
    # Construct MBAP properly: tid=1 proto=0 len=len(pdu)+1 unit=1
    import struct
    mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1)
    info = parse_response(mbap + pdu, tid=1)
    assert info == ModbusInfo(is_modbus=True, vendor="Acme", product="PLC-1000", version="1.2")


def test_parse_exception_is_still_modbus():
    import struct
    pdu = bytes([0xAB, 0x01])  # 0x2B|0x80 exception, code 01
    frame = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1) + pdu
    info = parse_response(frame, tid=1)
    assert info.is_modbus and info.is_exception


def test_non_modbus_framing_returns_none():
    assert parse_response(b"HTTP/1.1 200 OK\r\n\r\n", tid=1) is None


def test_describe_formats_banner():
    info = ModbusInfo(is_modbus=True, vendor="Acme", product="PLC-1000", version="1.2")
    assert describe(info) == "Modbus/TCP Acme PLC-1000 v1.2"
    assert describe(ModbusInfo(is_modbus=True, is_exception=True)) == "Modbus/TCP (no device id)"
    assert describe(None) is None
