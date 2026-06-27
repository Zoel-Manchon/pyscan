"""Pure IEC 60870-5-104 codec — liveness identification only, no sockets.

The most benign OT probe possible: we send a TESTFR (test frame) — a pure
keepalive that asks 'are you an IEC-104 endpoint?' without touching the
data-transfer state, and never sends any process command. A compliant station
answers TESTFR con. Encode/decode only here; the socket I/O is in the adapter.

IEC-104 APCI = start(0x68) | length | 4 control octets. The two low bits of the
first control octet pick the frame format; 0b11 = U-format (unnumbered control).
"""

from __future__ import annotations

from dataclasses import dataclass

_START = 0x68

# U-format control-octet-1 values (act = request, con = confirmation):
_U_FRAMES = {
    0x07: "STARTDT act", 0x0B: "STARTDT con",
    0x13: "STOPDT act", 0x23: "STOPDT con",
    0x43: "TESTFR act", 0x83: "TESTFR con",
}


@dataclass(frozen=True, slots=True)
class Iec104Info:
    is_iec104: bool
    frame: str | None = None


def build_testfr_act() -> bytes:
    """TESTFR act — a keepalive liveness probe (read-only)."""
    return bytes([_START, 0x04, 0x43, 0x00, 0x00, 0x00])


def parse_response(data: bytes) -> Iec104Info | None:
    """Return Iec104Info if this looks like IEC-104 U-format framing, else None."""
    if len(data) < 6 or data[0] != _START:
        return None
    control1 = data[2]
    if control1 & 0x03 != 0x03:  # must be U-format to confirm via our probe
        return None
    return Iec104Info(is_iec104=True, frame=_U_FRAMES.get(control1, "U-frame"))


def describe(info: Iec104Info | None) -> str | None:
    if not info or not info.is_iec104:
        return None
    return "IEC 60870-5-104" + (f" ({info.frame})" if info.frame else "")
