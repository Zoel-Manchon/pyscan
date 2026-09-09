"""Pure S7comm codec — read-only identification, no sockets.

S7-300/400 'classic' identification rides a small stack:
    TCP -> TPKT (RFC 1006) -> COTP (ISO-on-TCP) -> S7comm

Identifying a PLC is a three-step, read-only handshake:
    1. COTP Connection Request  -> Connection Confirm
    2. S7 Setup Communication    -> setup ack (negotiates PDU size)
    3. S7 Read SZL (module id)   -> SZL response with the order number (MLFB)

We never write to the PLC, never download blocks, never start/stop the CPU.
This module is bytes-in/bytes-out only; the socket handshake is in the adapter.

SAFETY: identification of real S7 PLCs should still target SIMULATORS only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import StrEnum

S7_PROTOCOL_ID = 0x32
COTP_CC = 0xD0  # Connection Confirm PDU type

_COTP_DT = bytes([0x02, 0xF0, 0x80])  # COTP Data header
_S7_OFFSET = 7  # TPKT(4) + COTP data header(3)
_FUNCTION_OFFSET = _S7_OFFSET + 10  # the S7 job/ack header is 10 bytes


class JobClass(StrEnum):
    """What an S7 job asks the CPU to do."""

    READ = "read"
    WRITE = "write"
    PROGRAM = "program"  # block up/download — logic is being changed
    CONTROL = "control"  # run/stop the CPU
    SETUP = "setup"
    OTHER = "other"


ROSCTR = {0x01: "job", 0x02: "ack", 0x03: "ack-data", 0x07: "userdata"}

FUNCTIONS: dict[int, tuple[str, JobClass]] = {
    0x00: ("CPU services", JobClass.OTHER),
    0x04: ("Read Var", JobClass.READ),
    0x05: ("Write Var", JobClass.WRITE),
    0x1A: ("Request download", JobClass.PROGRAM),
    0x1B: ("Download block", JobClass.PROGRAM),
    0x1C: ("Download ended", JobClass.PROGRAM),
    0x1D: ("Start upload", JobClass.PROGRAM),
    0x1E: ("Upload", JobClass.PROGRAM),
    0x1F: ("End upload", JobClass.PROGRAM),
    0x28: ("PLC Control", JobClass.CONTROL),
    0x29: ("PLC Stop", JobClass.CONTROL),
    0xF0: ("Setup communication", JobClass.SETUP),
}


@dataclass(frozen=True, slots=True)
class S7Info:
    is_s7: bool
    order_number: str | None = None


@dataclass(frozen=True, slots=True)
class S7Job:
    """A decoded S7 message header: who is asking for what."""

    rosctr: int
    function: int

    @property
    def kind(self) -> str:
        return ROSCTR.get(self.rosctr, f"rosctr {self.rosctr}")

    @property
    def name(self) -> str:
        entry = FUNCTIONS.get(self.function)
        return entry[0] if entry else f"Function 0x{self.function:02X}"

    @property
    def job_class(self) -> JobClass:
        entry = FUNCTIONS.get(self.function)
        return entry[1] if entry else JobClass.OTHER


def parse_job(payload: bytes) -> S7Job | None:
    """Read the S7 header out of a TCP payload, or None if it is not S7comm.

    The TPKT version byte and the S7 protocol id are both verified, so ordinary
    noise on port 102 does not get reported as PLC programming.
    """
    if len(payload) < _FUNCTION_OFFSET + 1:
        return None
    if payload[0] != 0x03 or payload[_S7_OFFSET] != S7_PROTOCOL_ID:
        return None
    return S7Job(rosctr=payload[_S7_OFFSET + 1], function=payload[_FUNCTION_OFFSET])


def _tpkt(payload: bytes) -> bytes:
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(payload)) + payload


def build_connection_request(rack: int = 0, slot: int = 2, conn_type: int = 0x01) -> bytes:
    """COTP Connection Request. dst TSAP encodes the rack/slot of the CPU."""
    dst_tsap = (conn_type << 8) | (rack * 0x20 + slot)
    src_tsap = 0x0100
    cotp = bytes([
        0x11, 0xE0,             # LI, CR
        0x00, 0x00,             # dst reference
        0x00, 0x01,             # src reference
        0x00,                   # class 0
        0xC0, 0x01, 0x0A,       # tpdu-size = 1024
        0xC1, 0x02, (src_tsap >> 8) & 0xFF, src_tsap & 0xFF,
        0xC2, 0x02, (dst_tsap >> 8) & 0xFF, dst_tsap & 0xFF,
    ])
    return _tpkt(cotp)


def build_setup_communication() -> bytes:
    s7 = bytes([
        0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00,  # S7 job header
        0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0,              # setup param
    ])
    return _tpkt(_COTP_DT + s7)


def build_read_szl(szl_id: int = 0x0011, index: int = 0x0000) -> bytes:
    param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])
    data = bytes([0xFF, 0x09, 0x00, 0x04]) + struct.pack(">HH", szl_id, index)
    s7_header = (
        bytes([0x32, 0x07, 0x00, 0x00, 0x00, 0x02])
        + struct.pack(">H", len(param))
        + struct.pack(">H", len(data))
    )
    return _tpkt(_COTP_DT + s7_header + param + data)


def is_connection_confirm(data: bytes) -> bool:
    return len(data) >= 6 and data[0] == 0x03 and data[5] == COTP_CC


def is_s7_response(data: bytes) -> bool:
    return len(data) >= 8 and data[0] == 0x03 and data[7] == S7_PROTOCOL_ID


def parse_szl(data: bytes) -> S7Info | None:
    """Best-effort extraction of the module order number from an SZL response.

    Returns is_s7=True whenever the framing is S7comm, with order_number filled
    in if the standard SZL-0x0011 layout is present. Defensive on purpose: a
    confirmed S7 handshake is the reliable signal; the MLFB is a bonus.
    """
    if not is_s7_response(data):
        return None
    try:
        parlen = struct.unpack(">H", data[13:15])[0]
        section = data[17 + parlen:]  # the data block, after the parameter
        if len(section) >= 12 and section[0] == 0xFF:
            record = section[12:]
            if len(record) >= 20:
                raw = record[:20].decode("latin-1", errors="replace")
                order = "".join(c for c in raw if c.isprintable()).strip()
                return S7Info(is_s7=True, order_number=order or None)
    except (IndexError, struct.error):
        pass
    return S7Info(is_s7=True)


def describe(info: S7Info | None) -> str | None:
    if not info or not info.is_s7:
        return None
    return "S7comm" + (f" {info.order_number}" if info.order_number else "")
