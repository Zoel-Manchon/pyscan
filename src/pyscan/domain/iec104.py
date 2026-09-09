"""Pure IEC 60870-5-104 codec — identification and traffic parsing, no sockets.

Two jobs, both pure:

  * Identification — send a TESTFR (test frame), the most benign OT probe that
    exists: a keepalive asking "are you an IEC-104 endpoint?" without touching
    the data-transfer state and without ever sending a process command.
  * Traffic parsing — split a TCP payload into APDUs and name what they carry,
    which is what the OT detection engine needs in order to tell an
    interrogation apart from a breaker command.

IEC-104 APCI = start(0x68) | length | 4 control octets, optionally followed by
an ASDU. The two low bits of the first control octet pick the frame format:
  ...0  I-format (numbered information transfer — carries an ASDU)
  ..01  S-format (supervisory, acknowledge only)
  ..11  U-format (unnumbered control: STARTDT / STOPDT / TESTFR)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

START = 0x68
APCI_SIZE = 6  # start + length + 4 control octets

# U-format control-octet-1 values (act = request, con = confirmation):
U_FRAMES = {
    0x07: "STARTDT act", 0x0B: "STARTDT con",
    0x13: "STOPDT act", 0x23: "STOPDT con",
    0x43: "TESTFR act", 0x83: "TESTFR con",
}


class Format(StrEnum):
    I = "I"  # noqa: E741 — the standard names these formats I, S and U
    S = "S"
    U = "U"


class TypeClass(StrEnum):
    """What an ASDU type id does. Commands are the ones that move the plant."""

    MONITOR = "monitor"
    COMMAND = "command"
    SYSTEM = "system"


# Only the type ids a detector cares about, named as in IEC 60870-5-101/104.
TYPE_IDS: dict[int, tuple[str, TypeClass]] = {
    1: ("M_SP_NA single point", TypeClass.MONITOR),
    3: ("M_DP_NA double point", TypeClass.MONITOR),
    9: ("M_ME_NA measured normalised", TypeClass.MONITOR),
    13: ("M_ME_NC measured short float", TypeClass.MONITOR),
    30: ("M_SP_TB single point w/ time", TypeClass.MONITOR),
    45: ("C_SC_NA single command", TypeClass.COMMAND),
    46: ("C_DC_NA double command", TypeClass.COMMAND),
    47: ("C_RC_NA regulating step command", TypeClass.COMMAND),
    48: ("C_SE_NA setpoint normalised", TypeClass.COMMAND),
    49: ("C_SE_NB setpoint scaled", TypeClass.COMMAND),
    50: ("C_SE_NC setpoint short float", TypeClass.COMMAND),
    51: ("C_BO_NA bitstring command", TypeClass.COMMAND),
    58: ("C_SC_TA single command w/ time", TypeClass.COMMAND),
    59: ("C_DC_TA double command w/ time", TypeClass.COMMAND),
    100: ("C_IC_NA interrogation", TypeClass.SYSTEM),
    101: ("C_CI_NA counter interrogation", TypeClass.SYSTEM),
    102: ("C_RD_NA read command", TypeClass.SYSTEM),
    103: ("C_CS_NA clock sync", TypeClass.SYSTEM),
    105: ("C_RP_NA reset process", TypeClass.COMMAND),
    107: ("C_TS_TA test command w/ time", TypeClass.SYSTEM),
}


@dataclass(frozen=True, slots=True)
class Iec104Info:
    is_iec104: bool
    frame: str | None = None


@dataclass(frozen=True, slots=True)
class Apdu:
    """One application protocol data unit lifted out of a TCP payload."""

    format: Format
    control: int
    type_id: int | None = None
    cause: int | None = None
    common_address: int | None = None

    @property
    def name(self) -> str:
        if self.format is Format.U:
            return U_FRAMES.get(self.control, "U-frame")
        if self.type_id is not None:
            return type_name(self.type_id)
        return f"{self.format.value}-frame"


def build_testfr_act() -> bytes:
    """TESTFR act — a keepalive liveness probe (read-only)."""
    return bytes([START, 0x04, 0x43, 0x00, 0x00, 0x00])


def parse_response(data: bytes) -> Iec104Info | None:
    """Return Iec104Info if this looks like IEC-104 U-format framing, else None."""
    if len(data) < APCI_SIZE or data[0] != START:
        return None
    control1 = data[2]
    if control1 & 0x03 != 0x03:  # must be U-format to confirm via our probe
        return None
    return Iec104Info(is_iec104=True, frame=U_FRAMES.get(control1, "U-frame"))


def parse_apdus(data: bytes, limit: int = 64) -> list[Apdu]:
    """Split a TCP payload into APDUs. Stops at the first byte that is not 0x68.

    Several APDUs routinely share one TCP segment, so a detector that only looks
    at the first one misses the command hiding behind the acknowledgement.
    """
    out: list[Apdu] = []
    offset = 0
    while len(out) < limit and offset + 2 <= len(data) and data[offset] == START:
        length = data[offset + 1]
        apdu = data[offset : offset + 2 + length]
        if len(apdu) < APCI_SIZE:
            break
        control1 = apdu[2]
        if control1 & 0x01 == 0:
            out.append(_parse_i_format(apdu, control1))
        elif control1 & 0x03 == 0x01:
            out.append(Apdu(Format.S, control1))
        else:
            out.append(Apdu(Format.U, control1))
        offset += 2 + length
    return out


def _parse_i_format(apdu: bytes, control1: int) -> Apdu:
    # ASDU starts right after the 6-byte APCI: TypeID | VSQ | CoT(2) | CA(2)
    if len(apdu) < APCI_SIZE + 1:
        return Apdu(Format.I, control1)
    type_id = apdu[APCI_SIZE]
    cause = apdu[APCI_SIZE + 2] if len(apdu) > APCI_SIZE + 2 else None
    address = (
        apdu[APCI_SIZE + 4] | (apdu[APCI_SIZE + 5] << 8)
        if len(apdu) > APCI_SIZE + 5
        else None
    )
    return Apdu(Format.I, control1, type_id=type_id, cause=cause, common_address=address)


def classify_type_id(type_id: int) -> TypeClass:
    entry = TYPE_IDS.get(type_id)
    if entry:
        return entry[1]
    # Anything in the monitoring range is telemetry; the rest is control-ish.
    return TypeClass.MONITOR if type_id < 45 else TypeClass.COMMAND


def type_name(type_id: int) -> str:
    entry = TYPE_IDS.get(type_id)
    return entry[0] if entry else f"TypeID {type_id}"


def describe(info: Iec104Info | None) -> str | None:
    if not info or not info.is_iec104:
        return None
    return "IEC 60870-5-104" + (f" ({info.frame})" if info.frame else "")
