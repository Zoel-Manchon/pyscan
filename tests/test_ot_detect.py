"""The OT detection rules: the highest-stakes pure logic in the project.

Every case here is a byte string and an assertion — no network, no PLC, no root.
That is exactly why the rules can be exhaustive.
"""

from __future__ import annotations

import pytest

from pyscan.domain import ot_traffic
from pyscan.domain.ot_detect import Baseline, Detector, Severity, at_least
from pyscan.domain.packet import Packet

HMI = ot_traffic.HMI
PLC = ot_traffic.PLC
RTU = ot_traffic.RTU
ATTACKER = ot_traffic.ATTACKER


def tcp(src: str, dst: str, dport: int, payload: bytes = b"", flags: str = "PA") -> Packet:
    return Packet(
        ts=1.0, length=60 + len(payload), protocol="TCP",
        src=src, dst=dst, sport=50000, dport=dport,
        flags=flags, payload=payload, version=4,
    )


def detector(hmi: str = HMI, plcs: str = f"{PLC},{RTU}") -> Detector:
    return Detector(baseline=Baseline.of(hmi, plcs))


# --------------------------------------------------------------------------
# baseline plumbing
# --------------------------------------------------------------------------
def test_baseline_parses_comma_separated_strings_and_drops_blanks():
    baseline = Baseline.of(" 10.0.0.1 , ,10.0.0.2 ", ["10.0.0.9", ""])
    assert baseline.hmi == frozenset({"10.0.0.1", "10.0.0.2"})
    assert baseline.plcs == frozenset({"10.0.0.9"})
    assert baseline.known


def test_baseline_without_hmi_is_not_known():
    assert not Baseline.of("", "10.0.0.9").known


def test_severity_ordering():
    assert at_least(Severity.CRITICAL, Severity.HIGH)
    assert at_least(Severity.MEDIUM, Severity.MEDIUM)
    assert not at_least(Severity.INFO, Severity.MEDIUM)


# --------------------------------------------------------------------------
# what is NOT an alert matters as much as what is
# --------------------------------------------------------------------------
def test_non_ot_traffic_is_ignored():
    assert detector().feed(tcp(ATTACKER, PLC, 443, b"GET / HTTP/1.1")) == []


def test_udp_is_ignored():
    packet = Packet(ts=1.0, length=60, protocol="UDP", src=ATTACKER, dst=PLC, dport=502)
    assert detector().feed(packet) == []


def test_traffic_to_an_unprotected_host_is_ignored():
    det = detector(plcs=PLC)  # the RTU is not in scope
    assert det.feed(tcp(ATTACKER, RTU, 2404, ot_traffic.iec_i_frame(45))) == []


def test_hmi_reads_raise_nothing():
    det = detector()
    assert det.feed(tcp(HMI, PLC, 502, ot_traffic.modbus_read_holding())) == []


def test_hmi_write_is_recorded_but_not_escalated():
    det = detector()
    alerts = det.feed(tcp(HMI, PLC, 502, ot_traffic.modbus_write_coil(0, closed=False)))
    assert [a.severity for a in alerts] == [Severity.INFO]
    assert det.hostile_sources == set()


def test_payload_that_is_not_modbus_raises_no_protocol_alert():
    det = detector()
    # Right port, wrong protocol: the MBAP protocol-id field does not say Modbus,
    # so byte 7 must NOT be read as "Write Single Register". The talker itself is
    # still worth reporting - it has no business here at all.
    alerts = det.feed(tcp(ATTACKER, PLC, 502, b"\x00\x01\x00\x09\x00\x06\x01\x06"))
    assert [a.summary for a in alerts] == [
        "Unauthorised talker sending OT traffic to a protected device"
    ]


# --------------------------------------------------------------------------
# Modbus
# --------------------------------------------------------------------------
def test_unauthorised_write_is_critical():
    det = detector()
    alerts = det.feed(tcp(ATTACKER, PLC, 502, ot_traffic.modbus_write_register(9, 250)))
    severities = [a.severity for a in alerts]
    assert Severity.CRITICAL in severities
    assert any("WRITE" in a.summary for a in alerts)
    assert any("T0855" in a.technique for a in alerts)
    assert ATTACKER in det.hostile_sources


def test_unauthorised_recon_is_medium():
    det = detector()
    alerts = det.feed(tcp(ATTACKER, PLC, 502, ot_traffic.modbus_read_device_id()))
    assert any(a.severity is Severity.MEDIUM and "Reconnaissance" in a.summary for a in alerts)


def test_new_talker_is_reported_once_per_pair():
    det = detector()
    first = det.feed(tcp(ATTACKER, PLC, 502, ot_traffic.modbus_read_holding()))
    second = det.feed(tcp(ATTACKER, PLC, 502, ot_traffic.modbus_read_holding()))
    assert any("Unauthorised talker" in a.summary for a in first)
    assert not any("Unauthorised talker" in a.summary for a in second)


def test_syn_to_an_ot_port_is_flagged():
    det = detector()
    alerts = det.feed(tcp(ATTACKER, PLC, 502, b"", flags="S"))
    assert [a.severity for a in alerts] == [Severity.MEDIUM]
    assert "SYN" in alerts[0].summary


def test_syn_ack_from_the_device_is_not_a_new_connection():
    det = detector()
    assert det.feed(tcp(ATTACKER, PLC, 502, b"", flags="SA")) == []


def test_file_record_write_is_a_program_download():
    det = detector()
    payload = ot_traffic.modbus_pdu(1, bytes([0x15, 0x00, 0x00]))
    alerts = det.feed(tcp(ATTACKER, PLC, 502, payload))
    assert any("T0843" in a.technique for a in alerts)


# --------------------------------------------------------------------------
# IEC 60870-5-104
# --------------------------------------------------------------------------
def test_control_command_is_critical():
    det = detector()
    alerts = det.feed(tcp(ATTACKER, RTU, 2404, ot_traffic.iec_i_frame(45)))
    assert any(a.severity is Severity.CRITICAL and "CONTROL COMMAND" in a.summary for a in alerts)


def test_interrogation_from_a_stranger_is_recon():
    det = detector()
    alerts = det.feed(tcp(ATTACKER, RTU, 2404, ot_traffic.iec_i_frame(100, ioa=0, payload=b"\x14")))
    assert any("Reconnaissance" in a.summary for a in alerts)


def test_stopdt_is_flagged_even_from_the_hmi():
    det = detector()
    alerts = det.feed(tcp(HMI, RTU, 2404, ot_traffic.iec_u_frame(0x13)))
    assert [a.summary.split(" -")[0] for a in alerts] == ["STOPDT act"]
    assert alerts[0].technique.startswith("T0804")


def test_startdt_is_not_an_alert():
    det = detector()
    assert det.feed(tcp(HMI, RTU, 2404, ot_traffic.iec_u_frame(0x07))) == []


def test_several_apdus_in_one_segment_are_all_seen():
    det = detector()
    payload = ot_traffic.iec_i_frame(100, ioa=0, payload=b"\x14") + ot_traffic.iec_i_frame(45)
    alerts = det.feed(tcp(ATTACKER, RTU, 2404, payload))
    summaries = " ".join(a.summary for a in alerts)
    assert "Reconnaissance" in summaries and "CONTROL COMMAND" in summaries


# --------------------------------------------------------------------------
# S7comm
# --------------------------------------------------------------------------
def _s7(rosctr: int, function: int) -> bytes:
    header = bytes([0x03, 0x00, 0x00, 0x1F]) + bytes([0x02, 0xF0, 0x80])
    return header + bytes([0x32, rosctr, 0, 0, 0, 1, 0, 8, 0, 0, function]) + bytes(8)


@pytest.mark.parametrize(
    ("function", "expected"),
    [(0x29, "CPU control"), (0x1A, "Block transfer"), (0x05, "WRITE to the process")],
)
def test_s7_jobs_are_classified(function, expected):
    det = detector(plcs=PLC)
    alerts = det.feed(tcp(ATTACKER, PLC, 102, _s7(0x01, function)))
    assert any(a.summary.startswith(expected) for a in alerts)


def test_s7_read_is_not_alerted():
    det = detector(plcs=PLC)
    alerts = det.feed(tcp(ATTACKER, PLC, 102, _s7(0x01, 0x04)))
    assert all("Unauthorised talker" in a.summary for a in alerts)


def test_s7_replies_from_the_plc_are_not_jobs():
    det = detector(plcs=PLC)
    alerts = det.feed(tcp(ATTACKER, PLC, 102, _s7(0x03, 0x05)))
    assert not any("WRITE" in a.summary for a in alerts)


# --------------------------------------------------------------------------
# behaviour with no baseline configured
# --------------------------------------------------------------------------
def test_without_a_baseline_a_write_is_high_not_critical():
    det = Detector()  # nothing configured at all
    alerts = det.feed(tcp(ATTACKER, PLC, 502, ot_traffic.modbus_write_coil(0, closed=True)))
    assert [a.severity for a in alerts] == [Severity.HIGH]
    assert det.hostile_sources == set()  # we cannot honestly name a source hostile


def test_without_a_plc_list_every_ot_destination_is_protected():
    det = Detector(baseline=Baseline.of(HMI, ""))
    alerts = det.feed(tcp(ATTACKER, "192.0.2.77", 502, ot_traffic.modbus_write_coil(0, True)))
    assert any(a.severity is Severity.CRITICAL for a in alerts)


def test_counters_track_what_was_observed():
    det = detector()
    det.feed(tcp(ATTACKER, PLC, 502, ot_traffic.modbus_write_register(9, 250)))
    det.feed(tcp(ATTACKER, RTU, 2404, ot_traffic.iec_i_frame(45)))
    assert det.packets == 2
    assert det.alerts >= 4
    assert "Modbus FC6" in det.observed_operations
    assert "IEC-104 T45" in det.observed_operations
