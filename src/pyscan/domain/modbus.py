"""Pure Modbus/TCP codec — encode/decode only, no sockets.

Read-only identification: we build a single 'Read Device Identification'
request (function code 0x2B / MEI 0x0E) and parse whatever comes back. This is
the benign, asset-discovery side of OT recon — it never writes coils/registers
and never sends malformed frames. The socket I/O lives in the adapter; this
module is just bytes-in/bytes-out, so it's trivially unit-testable.

Modbus/TCP frame = MBAP header (7 bytes) + PDU:
    Transaction Id (2) | Protocol Id (2, =0) | Length (2) | Unit Id (1) | PDU
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_FC_READ_DEVICE_ID = 0x2B
_MEI_DEVICE_ID = 0x0E
_EXCEPTION_FLAG = 0x80  # FC | 0x80 in a response means "exception"


@dataclass(frozen=True, slots=True)
class ModbusInfo:
    is_modbus: bool
    is_exception: bool = False
    vendor: str | None = None
    product: str | None = None
    version: str | None = None


def build_device_id_request(unit: int = 1, tid: int = 1) -> bytes:
    """A 'Read Device Identification' (basic) request — read-only."""
    pdu = bytes([_FC_READ_DEVICE_ID, _MEI_DEVICE_ID, 0x01, 0x00])
    mbap = struct.pack(">HHHB", tid, 0x0000, len(pdu) + 1, unit)
    return mbap + pdu


def parse_response(data: bytes, tid: int) -> ModbusInfo | None:
    """Decode a response. Returns None if it isn't valid Modbus framing."""
    if len(data) < 8:  # MBAP(7) + at least one PDU byte
        return None
    rtid, proto, _length, _unit = struct.unpack(">HHHB", data[:7])
    if proto != 0x0000:
        return None  # protocol id must be 0 for Modbus

    fc = data[7]
    if fc == (_FC_READ_DEVICE_ID | _EXCEPTION_FLAG):
        # It spoke Modbus but doesn't support device identification.
        return ModbusInfo(is_modbus=True, is_exception=True)
    if fc != _FC_READ_DEVICE_ID:
        # Some other valid-looking function code — still Modbus framing.
        return ModbusInfo(is_modbus=True)

    return _parse_device_id_objects(data[7:])


def _parse_device_id_objects(body: bytes) -> ModbusInfo:
    # body: FC | MEI | ReadDevIdCode | Conformity | More | NextObjId | NumObjs | objects...
    if len(body) < 7:
        return ModbusInfo(is_modbus=True)
    num_objects = body[6]
    offset = 7
    fields: dict[int, str] = {}
    for _ in range(num_objects):
        if offset + 2 > len(body):
            break
        obj_id = body[offset]
        obj_len = body[offset + 1]
        value = body[offset + 2 : offset + 2 + obj_len]
        fields[obj_id] = value.decode("latin-1", errors="replace")
        offset += 2 + obj_len

    return ModbusInfo(
        is_modbus=True,
        vendor=fields.get(0x00),
        product=fields.get(0x01),
        version=fields.get(0x02),
    )


def describe(info: ModbusInfo | None) -> str | None:
    """Human/parseable banner string from a ModbusInfo."""
    if not info or not info.is_modbus:
        return None
    if info.is_exception:
        return "Modbus/TCP (no device id)"
    parts = [p for p in (info.vendor, info.product) if p]
    base = "Modbus/TCP" + (" " + " ".join(parts) if parts else "")
    if info.version:
        base += f" v{info.version}"
    return base
