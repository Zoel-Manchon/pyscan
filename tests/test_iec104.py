from pyscan.domain.iec104 import (
    Iec104Info,
    build_testfr_act,
    describe,
    parse_response,
)


def test_testfr_act_frame_bytes():
    assert build_testfr_act() == bytes.fromhex("680443000000")


def test_parse_testfr_con():
    info = parse_response(bytes.fromhex("680483000000"))
    assert info == Iec104Info(is_iec104=True, frame="TESTFR con")


def test_parse_startdt_con():
    info = parse_response(bytes.fromhex("68040B000000"))
    assert info.is_iec104 and info.frame == "STARTDT con"


def test_non_iec104_returns_none():
    assert parse_response(b"SSH-2.0-OpenSSH_9.6\r\n") is None
    assert parse_response(b"\x68") is None  # too short


def test_describe():
    assert describe(Iec104Info(True, "TESTFR con")) == "IEC 60870-5-104 (TESTFR con)"
    assert describe(None) is None
