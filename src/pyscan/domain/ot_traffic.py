"""Synthetic OT traffic — a practice capture with an attack inside it. PURE.

Building frames byte by byte instead of reaching for a packet library is worth
the fifty lines: the OT lab now has no dependency beyond the standard library,
the scenario is deterministic (same bytes every run, so tests can assert on it),
and the protocol payloads are built by the same encoders the scanner uses.

The scenario is the one worth recognising on sight:

    legitimate baseline  ->  new talker  ->  reconnaissance  ->  write / command

which is the shape of nearly every published ICS intrusion. Fictional
addresses, real protocol bytes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

HMI = "10.10.30.10"  # the only source that legitimately drives the process
PLC = "10.10.30.21"  # Modbus feeder controller
RTU = "10.10.40.7"  # IEC-104 substation outstation
ATTACKER = "10.10.30.142"  # a station that has no business on the OT segment

_ETHERTYPE_IPV4 = 0x0800
_PROTO_TCP = 6
_FLAGS = {"S": 0x02, "SA": 0x12, "A": 0x10, "PA": 0x18, "FA": 0x11}


@dataclass(frozen=True, slots=True)
class Exchange:
    """One application message on the wire, at a point in time."""

    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes
    flags: str = "PA"


# ---------------------------------------------------------------------------
# protocol payloads
# ---------------------------------------------------------------------------
def modbus_pdu(unit: int, pdu: bytes, tid: int = 0) -> bytes:
    """Wrap a PDU in an MBAP header (length counts the unit id too)."""
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def modbus_read_holding(addr: int = 0, count: int = 125, unit: int = 1) -> bytes:
    return modbus_pdu(unit, struct.pack(">BHH", 0x03, addr, count))


def modbus_read_device_id(unit: int = 1) -> bytes:
    return modbus_pdu(unit, bytes([0x2B, 0x0E, 0x01, 0x00]))


def modbus_write_register(addr: int, value: int, unit: int = 1) -> bytes:
    return modbus_pdu(unit, struct.pack(">BHH", 0x06, addr, value))


def modbus_write_coil(addr: int, closed: bool, unit: int = 1) -> bytes:
    return modbus_pdu(unit, struct.pack(">BHH", 0x05, addr, 0xFF00 if closed else 0x0000))


def iec_u_frame(control: int) -> bytes:
    return bytes([0x68, 0x04, control, 0x00, 0x00, 0x00])


def iec_i_frame(type_id: int, cause: int = 6, common_address: int = 1, ioa: int = 1,
                payload: bytes = b"\x01") -> bytes:
    asdu = (
        struct.pack("<BBHH", type_id, 0x01, cause, common_address)
        + struct.pack("<I", ioa)[:3]
        + payload
    )
    body = b"\x00\x00\x00\x00" + asdu  # I-format control field (send/recv counters)
    return bytes([0x68, len(body)]) + body


# ---------------------------------------------------------------------------
# the scenario
# ---------------------------------------------------------------------------
def build_scenario(start: float = 1_700_000_000.0) -> list[Exchange]:
    """The four-act practice scenario, as application messages."""
    clock = _Clock(start)
    out: list[Exchange] = []

    # Act 1 - baseline: the HMI polls the PLC, reads only.
    for i in range(6):
        port = 50100 + i
        out.append(Exchange(clock.tick(0.9), HMI, PLC, port, 502,
                            modbus_read_holding(addr=i * 10)))
        out.append(Exchange(clock.tick(0.2), PLC, HMI, 502, port,
                            modbus_read_holding(addr=i * 10)))

    # Act 2 - a new talker appears and enumerates the device.
    out.append(Exchange(clock.tick(0.3), ATTACKER, PLC, 50412, 502, b"", flags="S"))
    out.append(Exchange(clock.tick(0.9), ATTACKER, PLC, 50412, 502, modbus_read_device_id()))
    out.append(Exchange(clock.tick(0.9), ATTACKER, PLC, 50412, 502,
                        modbus_read_holding(addr=0, count=125)))
    out.append(Exchange(clock.tick(0.9), ATTACKER, PLC, 50412, 502,
                        modbus_read_holding(addr=125, count=125)))

    # Act 3 - the write: a setpoint is moved, then a feeder is opened.
    out.append(Exchange(clock.tick(0.9), ATTACKER, PLC, 50412, 502,
                        modbus_write_register(addr=9, value=250)))
    out.append(Exchange(clock.tick(0.9), ATTACKER, PLC, 50412, 502,
                        modbus_write_coil(addr=0, closed=False)))
    out.append(Exchange(clock.tick(0.2), PLC, ATTACKER, 502, 50412,
                        modbus_write_coil(addr=0, closed=False)))

    # Act 4 - the substation: interrogate, command, then silence the reporting.
    out.append(Exchange(clock.tick(0.9), ATTACKER, RTU, 51020, 2404,
                        iec_i_frame(100, ioa=0, payload=b"\x14")))  # C_IC interrogation
    out.append(Exchange(clock.tick(0.9), ATTACKER, RTU, 51020, 2404,
                        iec_i_frame(45)))  # C_SC single command
    out.append(Exchange(clock.tick(0.9), ATTACKER, RTU, 51020, 2404,
                        iec_u_frame(0x13)))  # STOPDT act
    return out


def build_frames(start: float = 1_700_000_000.0) -> list[tuple[float, bytes]]:
    """The scenario as (timestamp, Ethernet frame) pairs, ready for pcap_writer."""
    return [(x.ts, encode_frame(x)) for x in build_scenario(start)]


# ---------------------------------------------------------------------------
# frame encoding
# ---------------------------------------------------------------------------
class _Clock:
    def __init__(self, start: float) -> None:
        self._now = start

    def tick(self, delta: float) -> float:
        self._now += delta
        return self._now


def encode_frame(exchange: Exchange) -> bytes:
    """Ethernet + IPv4 + TCP + payload, with both checksums filled in."""
    tcp = _tcp(exchange)
    ip = _ipv4(exchange.src, exchange.dst, tcp)
    ethernet = _mac(exchange.dst) + _mac(exchange.src) + struct.pack(">H", _ETHERTYPE_IPV4)
    return ethernet + ip + tcp


def _mac(address: str) -> bytes:
    """A stable, obviously-synthetic MAC derived from the IP address."""
    octets = [int(part) & 0xFF for part in address.split(".")]
    return bytes([0x02, 0x00, *octets[:4]])


def _tcp(exchange: Exchange) -> bytes:
    flags = _FLAGS.get(exchange.flags, 0x18)
    header = struct.pack(
        ">HHIIBBHHH",
        exchange.sport, exchange.dport,
        1000, 2000,  # fixed sequence/ack: this is a shape exercise, not a replay
        0x50, flags, 8192, 0, 0,
    )
    segment = header + exchange.payload
    checksum = _checksum(
        _pseudo_header(exchange.src, exchange.dst, len(segment)) + segment
    )
    return segment[:16] + struct.pack(">H", checksum) + segment[18:]


def _ipv4(src: str, dst: str, payload: bytes) -> bytes:
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + len(payload), 0, 0x4000, 64, _PROTO_TCP, 0,
        _address(src), _address(dst),
    )
    return header[:10] + struct.pack(">H", _checksum(header)) + header[12:]


def _pseudo_header(src: str, dst: str, length: int) -> bytes:
    return _address(src) + _address(dst) + struct.pack(">BBH", 0, _PROTO_TCP, length)


def _address(dotted: str) -> bytes:
    return bytes(int(part) for part in dotted.split("."))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = int(sum(struct.unpack(f">{len(data) // 2}H", data)))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF
