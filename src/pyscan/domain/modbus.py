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
from enum import StrEnum

_FC_READ_DEVICE_ID = 0x2B
_MEI_DEVICE_ID = 0x0E
_EXCEPTION_FLAG = 0x80  # FC | 0x80 in a response means "exception"

MBAP_SIZE = 7  # Transaction(2) Protocol(2) Length(2) Unit(1)


class FunctionClass(StrEnum):
    """What a Modbus function code actually does to the device.

    This is the distinction the whole OT posture rests on: reading a holding
    register is an audit, writing a coil is an operation on the plant.
    """

    READ = "read"
    WRITE = "write"
    RECON = "recon"
    PROGRAM = "program"
    OTHER = "other"


FUNCTIONS: dict[int, tuple[str, FunctionClass]] = {
    0x01: ("Read Coils", FunctionClass.READ),
    0x02: ("Read Discrete Inputs", FunctionClass.READ),
    0x03: ("Read Holding Registers", FunctionClass.READ),
    0x04: ("Read Input Registers", FunctionClass.READ),
    0x05: ("Write Single Coil", FunctionClass.WRITE),
    0x06: ("Write Single Register", FunctionClass.WRITE),
    0x07: ("Read Exception Status", FunctionClass.READ),
    0x08: ("Diagnostics", FunctionClass.RECON),
    0x0B: ("Get Comm Event Counter", FunctionClass.READ),
    0x0C: ("Get Comm Event Log", FunctionClass.READ),
    0x0F: ("Write Multiple Coils", FunctionClass.WRITE),
    0x10: ("Write Multiple Registers", FunctionClass.WRITE),
    0x11: ("Report Server ID", FunctionClass.RECON),
    0x14: ("Read File Record", FunctionClass.READ),
    0x15: ("Write File Record", FunctionClass.PROGRAM),
    0x16: ("Mask Write Register", FunctionClass.WRITE),
    0x17: ("Read/Write Multiple Registers", FunctionClass.WRITE),
    0x18: ("Read FIFO Queue", FunctionClass.READ),
    0x2B: ("Read Device Identification", FunctionClass.RECON),
    0x5A: ("UMAS (Schneider vendor)", FunctionClass.PROGRAM),
}


def read_function_code(payload: bytes) -> int | None:
    """Pull the function code out of a Modbus/TCP payload, or None if it is not one.

    The protocol-id field is checked rather than assumed: on port 502 plenty of
    traffic is not Modbus, and reading byte 7 of whatever turns up is how a
    detector invents alerts out of noise.
    """
    if len(payload) < MBAP_SIZE + 1:
        return None
    protocol_id = struct.unpack(">H", payload[2:4])[0]
    if protocol_id != 0x0000:
        return None
    length = struct.unpack(">H", payload[4:6])[0]
    if not 1 <= length <= 253 + 2:
        return None
    return payload[MBAP_SIZE] & 0x7F  # strip the exception flag on responses


def classify_function(function_code: int) -> FunctionClass:
    name_and_class = FUNCTIONS.get(function_code)
    return name_and_class[1] if name_and_class else FunctionClass.OTHER


def function_name(function_code: int) -> str:
    name_and_class = FUNCTIONS.get(function_code)
    return name_and_class[0] if name_and_class else f"Function {function_code}"


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
