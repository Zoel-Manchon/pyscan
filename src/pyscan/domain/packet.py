"""Pure packet decoders — bytes in, structured Packet out. No sockets, no files.

The heart of the sniffer. Each layer is peeled in turn:
Ethernet -> IPv4/IPv6 (-> extension headers) -> TCP/UDP/ICMP. Because it is
pure, every decoder is unit-testable against a byte fixture — the same
probe/identify split that runs through the whole project, applied to capture
instead of scanning.

A decoded Packet carries its transport payload, which is what lets the OT
detection engine (`pyscan.domain.ot_detect`) work on decoded packets instead of
re-parsing raw frames for itself.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# pcap link-layer types
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101  # raw IPv4/IPv6, no link header
LINKTYPE_LINUX_SLL = 113  # Linux "any" cooked capture

_IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
_TCP_FLAGS = [(0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"), (0x20, "U")]

# IPv6 extension headers that are simply chained through on the way to the
# transport header. 44 (fragment) is a fixed 8 bytes; the rest carry a length.
_V6_EXT_VARIABLE = {0, 43, 60, 51}
_V6_EXT_FIXED8 = {44}
_V6_NO_NEXT = 59


@dataclass(frozen=True, slots=True)
class Packet:
    ts: float
    length: int
    protocol: str
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    info: str = ""
    flags: str = ""
    payload: bytes = field(default=b"", repr=False)
    version: int | None = None  # IP version, when the packet is IP at all


def decode(data: bytes, linktype: int = LINKTYPE_ETHERNET, ts: float = 0.0) -> Packet:
    length = len(data)
    try:
        if linktype == LINKTYPE_ETHERNET:
            return _decode_ethernet(data, ts, length)
        if linktype == LINKTYPE_LINUX_SLL:
            return _decode_linux_sll(data, ts, length)
        if linktype == LINKTYPE_RAW:
            return _decode_ip(data, ts, length)
    except (struct.error, IndexError, ValueError, OSError):
        pass
    return Packet(ts=ts, length=length, protocol="?")


def _decode_ethernet(data: bytes, ts: float, length: int) -> Packet:
    if len(data) < 14:
        return Packet(ts=ts, length=length, protocol="?")
    ethertype = struct.unpack(">H", data[12:14])[0]
    payload = data[14:]
    if ethertype == 0x8100 and len(data) >= 18:  # 802.1Q VLAN tag: step over it
        ethertype = struct.unpack(">H", data[16:18])[0]
        payload = data[18:]
    return _decode_ethertype(ethertype, payload, ts, length)


def _decode_linux_sll(data: bytes, ts: float, length: int) -> Packet:
    """Linux cooked capture (`-i any`): a 16-byte header, ethertype at the end."""
    if len(data) < 16:
        return Packet(ts=ts, length=length, protocol="?")
    ethertype = struct.unpack(">H", data[14:16])[0]
    return _decode_ethertype(ethertype, data[16:], ts, length)


def _decode_ethertype(ethertype: int, payload: bytes, ts: float, length: int) -> Packet:
    if ethertype in (0x0800, 0x86DD):
        return _decode_ip(payload, ts, length)
    if ethertype == 0x0806:
        return Packet(ts=ts, length=length, protocol="ARP", info="who-has / is-at")
    return Packet(ts=ts, length=length, protocol=f"0x{ethertype:04x}")


def _decode_ip(data: bytes, ts: float, length: int) -> Packet:
    """Dispatch on the IP version nibble, so RAW linktype handles both families."""
    if not data:
        return Packet(ts=ts, length=length, protocol="?")
    version = data[0] >> 4
    if version == 4:
        return _decode_ipv4(data, ts, length)
    if version == 6:
        return _decode_ipv6(data, ts, length)
    return Packet(ts=ts, length=length, protocol="?")


def _decode_ipv4(data: bytes, ts: float, length: int) -> Packet:
    if len(data) < 20:
        return Packet(ts=ts, length=length, protocol="IPv4", version=4)
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    total = struct.unpack(">H", data[2:4])[0]
    # Trust the header length when it is sane, so trailing Ethernet padding is
    # not mistaken for application payload.
    body = data[ihl:total] if 20 <= total <= len(data) else data[ihl:]
    return _decode_transport(proto, body, ts, length, src, dst, 4)


def _decode_ipv6(data: bytes, ts: float, length: int) -> Packet:
    if len(data) < 40:
        return Packet(ts=ts, length=length, protocol="IPv6", version=6)
    payload_len = struct.unpack(">H", data[4:6])[0]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    end = 40 + payload_len if 40 + payload_len <= len(data) else len(data)
    next_header, body = _skip_v6_extensions(data[6], data[40:end])
    return _decode_transport(next_header, body, ts, length, src, dst, 6)


def _skip_v6_extensions(next_header: int, body: bytes) -> tuple[int, bytes]:
    """Walk the extension-header chain until a transport (or unknown) header."""
    for _ in range(8):  # a bounded walk: no malformed packet can spin us
        if next_header in _V6_EXT_VARIABLE and len(body) >= 2:
            size = (body[1] + 1) * 8
        elif next_header in _V6_EXT_FIXED8 and len(body) >= 8:
            size = 8
        else:
            break
        next_header, body = body[0], body[size:]
    return next_header, body


def _decode_transport(
    proto: int, body: bytes, ts: float, length: int, src: str, dst: str, version: int
) -> Packet:
    name = _IP_PROTO.get(proto, f"IP/{proto}")
    if name == "TCP":
        return _decode_tcp(body, ts, length, src, dst, version)
    if name == "UDP":
        return _decode_udp(body, ts, length, src, dst, version)
    if name in ("ICMP", "ICMPv6"):
        return _decode_icmp(body, ts, length, src, dst, version, name)
    if proto == _V6_NO_NEXT:
        return Packet(ts=ts, length=length, protocol="IPv6", src=src, dst=dst, version=version)
    return Packet(ts=ts, length=length, protocol=name, src=src, dst=dst, version=version)


def _decode_tcp(data: bytes, ts: float, length: int, src: str, dst: str, version: int) -> Packet:
    if len(data) < 20:
        return Packet(ts=ts, length=length, protocol="TCP", src=src, dst=dst, version=version)
    sport, dport = struct.unpack(">HH", data[:4])
    data_offset = (data[12] >> 4) * 4
    flag_bits = data[13]
    flags = "".join(ch for bit, ch in _TCP_FLAGS if flag_bits & bit) or "."
    payload = data[data_offset:] if 20 <= data_offset <= len(data) else b""
    return Packet(
        ts, length, "TCP", src, dst, sport, dport,
        info=f"[{flags}]", flags=flags, payload=payload, version=version,
    )


def _decode_udp(data: bytes, ts: float, length: int, src: str, dst: str, version: int) -> Packet:
    if len(data) < 8:
        return Packet(ts=ts, length=length, protocol="UDP", src=src, dst=dst, version=version)
    sport, dport, ulen = struct.unpack(">HHH", data[:6])
    payload = data[8 : ulen if 8 <= ulen <= len(data) else len(data)]
    return Packet(
        ts, length, "UDP", src, dst, sport, dport,
        info=f"len={ulen}", payload=payload, version=version,
    )


def _decode_icmp(
    data: bytes, ts: float, length: int, src: str, dst: str, version: int, name: str
) -> Packet:
    if len(data) < 2:
        return Packet(ts=ts, length=length, protocol=name, src=src, dst=dst, version=version)
    icmp_type, code = data[0], data[1]
    kinds = (
        {128: "echo-request", 129: "echo-reply", 1: "unreachable", 3: "time-exceeded"}
        if name == "ICMPv6"
        else {0: "echo-reply", 8: "echo-request", 3: "unreachable", 11: "time-exceeded"}
    )
    info = kinds.get(icmp_type, f"type {icmp_type}") + (f"/{code}" if code else "")
    return Packet(ts, length, name, src, dst, info=info, payload=data[4:], version=version)
