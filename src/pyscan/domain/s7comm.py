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

S7_PROTOCOL_ID = 0x32
COTP_CC = 0xD0  # Connection Confirm PDU type

_COTP_DT = bytes([0x02, 0xF0, 0x80])  # COTP Data header


@dataclass(frozen=True, slots=True)
class S7Info:
    is_s7: bool
    order_number: str | None = None


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
