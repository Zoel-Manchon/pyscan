"""The protocol codecs the detection engine and the scanner now share.

These are the functions that used to exist twice — once in the scanner, once in
the monitoring script. Testing them once is the point.
"""

from __future__ import annotations

import struct

import pytest

from pyscan.application.monitor_service import MonitorService
from pyscan.domain import iec104, modbus, ot_traffic, s7comm
from pyscan.domain.ot_detect import Baseline, Detector, Severity
from pyscan.domain.packet import decode


# --------------------------------------------------------------------------
# Modbus function codes
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (0x03, modbus.FunctionClass.READ),
        (0x05, modbus.FunctionClass.WRITE),
        (0x10, modbus.FunctionClass.WRITE),
        (0x2B, modbus.FunctionClass.RECON),
        (0x15, modbus.FunctionClass.PROGRAM),
        (0x77, modbus.FunctionClass.OTHER),
    ],
)
def test_function_codes_are_classified(code, expected):
    assert modbus.classify_function(code) is expected


def test_unknown_function_codes_still_get_a_name():
    assert modbus.function_name(0x77) == "Function 119"


def test_read_function_code_extracts_the_pdu_function():
    assert modbus.read_function_code(ot_traffic.modbus_write_coil(0, True)) == 0x05


def test_read_function_code_rejects_a_non_modbus_protocol_id():
    payload = struct.pack(">HHHB", 1, 0x0001, 6, 1) + b"\x06\x00\x09\x00\xfa"
    assert modbus.read_function_code(payload) is None


def test_read_function_code_rejects_an_impossible_length_field():
    payload = struct.pack(">HHHB", 1, 0x0000, 60000, 1) + b"\x06"
    assert modbus.read_function_code(payload) is None


def test_read_function_code_rejects_a_short_payload():
    assert modbus.read_function_code(b"\x00\x01\x00") is None


def test_exception_responses_report_the_underlying_function():
    payload = struct.pack(">HHHB", 1, 0, 2, 1) + bytes([0x83, 0x02])
    assert modbus.read_function_code(payload) == 0x03


# --------------------------------------------------------------------------
# IEC-104 APDUs
# --------------------------------------------------------------------------
def test_u_format_apdu_is_named():
    apdus = iec104.parse_apdus(ot_traffic.iec_u_frame(0x13))
    assert apdus[0].format is iec104.Format.U
    assert apdus[0].name == "STOPDT act"


def test_i_format_apdu_exposes_the_type_id():
    apdus = iec104.parse_apdus(ot_traffic.iec_i_frame(45))
    assert apdus[0].format is iec104.Format.I
    assert apdus[0].type_id == 45
    assert apdus[0].name == "C_SC_NA single command"


def test_s_format_apdu_is_recognised():
    apdus = iec104.parse_apdus(bytes([0x68, 0x04, 0x01, 0x00, 0x00, 0x00]))
    assert apdus[0].format is iec104.Format.S
    assert apdus[0].name == "S-frame"


def test_several_apdus_are_split_out_of_one_segment():
    payload = ot_traffic.iec_u_frame(0x07) + ot_traffic.iec_i_frame(100) + ot_traffic.iec_i_frame(45)
    assert [a.type_id for a in iec104.parse_apdus(payload)] == [None, 100, 45]


def test_parsing_stops_at_the_first_byte_that_is_not_a_start():
    assert iec104.parse_apdus(b"\xff\xff") == []


def test_a_truncated_apdu_is_dropped():
    assert iec104.parse_apdus(bytes([0x68, 0x04, 0x43])) == []


def test_the_apdu_limit_is_honoured():
    payload = ot_traffic.iec_u_frame(0x43) * 200
    assert len(iec104.parse_apdus(payload, limit=5)) == 5


@pytest.mark.parametrize(
    ("type_id", "expected"),
    [
        (1, iec104.TypeClass.MONITOR),
        (45, iec104.TypeClass.COMMAND),
        (100, iec104.TypeClass.SYSTEM),
        (200, iec104.TypeClass.COMMAND),  # unknown, in the control range
        (20, iec104.TypeClass.MONITOR),  # unknown, in the monitoring range
    ],
)
def test_type_ids_are_classified(type_id, expected):
    assert iec104.classify_type_id(type_id) is expected


def test_unknown_type_ids_still_get_a_name():
    assert iec104.type_name(200) == "TypeID 200"


def test_the_identification_probe_is_still_a_testfr():
    probe = iec104.build_testfr_act()
    assert iec104.parse_apdus(probe)[0].name == "TESTFR act"
    assert iec104.describe(iec104.parse_response(probe)) == "IEC 60870-5-104 (TESTFR act)"


# --------------------------------------------------------------------------
# S7comm jobs
# --------------------------------------------------------------------------
def s7_payload(rosctr: int, function: int) -> bytes:
    tpkt_and_cotp = bytes([0x03, 0x00, 0x00, 0x1F, 0x02, 0xF0, 0x80])
    return tpkt_and_cotp + bytes([0x32, rosctr, 0, 0, 0, 1, 0, 8, 0, 0, function]) + bytes(8)


def test_parse_job_reads_the_rosctr_and_function():
    job = s7comm.parse_job(s7_payload(0x01, 0x29))
    assert job is not None
    assert job.kind == "job" and job.name == "PLC Stop"
    assert job.job_class is s7comm.JobClass.CONTROL


def test_parse_job_rejects_payloads_that_are_not_s7():
    assert s7comm.parse_job(b"\x03\x00" + bytes(30)) is None
    assert s7comm.parse_job(b"") is None


def test_unknown_s7_functions_still_get_a_name():
    job = s7comm.parse_job(s7_payload(0x01, 0x99))
    assert job is not None and job.name == "Function 0x99"
    assert job.job_class is s7comm.JobClass.OTHER


def test_unknown_rosctr_is_named():
    job = s7comm.parse_job(s7_payload(0x09, 0x04))
    assert job is not None and job.kind == "rosctr 9"


# --------------------------------------------------------------------------
# the traffic generator, and the whole pipeline over it
# --------------------------------------------------------------------------
def test_the_scenario_is_deterministic():
    assert ot_traffic.build_frames() == ot_traffic.build_frames()


def test_generated_frames_decode_back_to_what_was_encoded():
    exchanges = ot_traffic.build_scenario()
    for exchange in exchanges:
        packet = decode(ot_traffic.encode_frame(exchange), 1, exchange.ts)
        assert packet.protocol == "TCP"
        assert packet.src == exchange.src and packet.dst == exchange.dst
        assert packet.dport == exchange.dport
        assert packet.payload == exchange.payload


def test_the_scenario_contains_the_shape_worth_recognising():
    detector = Detector(baseline=Baseline.of(ot_traffic.HMI, f"{ot_traffic.PLC},{ot_traffic.RTU}"))
    service = MonitorService(detector, min_severity=Severity.MEDIUM)
    frames = [(ts, 1, frame) for ts, frame in ot_traffic.build_frames()]
    alerts = list(service.run(frames))

    summaries = " | ".join(a.summary for a in alerts)
    assert "New connection (SYN)" in summaries
    assert "Reconnaissance" in summaries
    assert "WRITE to the process" in summaries
    assert "CONTROL COMMAND" in summaries
    assert "STOPDT" in summaries
    assert detector.hostile_sources == {ot_traffic.ATTACKER}


def test_the_baseline_polling_raises_nothing_on_its_own():
    detector = Detector(baseline=Baseline.of(ot_traffic.HMI, ot_traffic.PLC))
    service = MonitorService(detector)
    baseline_only = [
        (x.ts, 1, ot_traffic.encode_frame(x))
        for x in ot_traffic.build_scenario()
        if x.src == ot_traffic.HMI
    ]
    assert list(service.run(baseline_only)) == []


def test_monitor_service_ignores_heartbeats():
    service = MonitorService(Detector())
    assert list(service.run([None, None])) == []


def test_monitor_service_filters_below_the_severity_floor():
    detector = Detector(baseline=Baseline.of(ot_traffic.HMI, ot_traffic.PLC))
    service = MonitorService(detector, min_severity=Severity.CRITICAL)
    frames = [(ts, 1, frame) for ts, frame in ot_traffic.build_frames()]
    assert all(a.severity is Severity.CRITICAL for a in service.run(frames))


def test_monitor_service_exposes_its_detector():
    detector = Detector()
    assert MonitorService(detector).detector is detector
