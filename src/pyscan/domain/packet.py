"""Pure packet decoders — bytes in, structured Packet out. No sockets, no files.

The heart of the sniffer. Each layer is peeled in turn: Ethernet -> IPv4 ->
TCP/UDP/ICMP. Because it's pure, every decoder is unit-testable against a byte
fixture — the same probe/identify split that runs through the whole project,
applied to capture instead of scanning.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# pcap link-layer types
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101  # raw IPv4/IPv6, no link header

_IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP"}
_TCP_FLAGS = [(0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"), (0x20, "U")]


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


def decode(data: bytes, linktype: int = LINKTYPE_ETHERNET, ts: float = 0.0) -> Packet:
    length = len(data)
    try:
        if linktype == LINKTYPE_ETHERNET:
            return _decode_ethernet(data, ts, length)
        if linktype == LINKTYPE_RAW:
            return _decode_ipv4(data, ts, length)
    except (struct.error, IndexError):
        pass
    return Packet(ts=ts, length=length, protocol="?")


def _decode_ethernet(data: bytes, ts: float, length: int) -> Packet:
    if len(data) < 14:
        return Packet(ts=ts, length=length, protocol="?")
    ethertype = struct.unpack(">H", data[12:14])[0]
    payload = data[14:]
    if ethertype == 0x0800:
        return _decode_ipv4(payload, ts, length)
    if ethertype == 0x0806:
        return Packet(ts=ts, length=length, protocol="ARP", info="who-has / is-at")
    if ethertype == 0x86DD:
        return Packet(ts=ts, length=length, protocol="IPv6")
    return Packet(ts=ts, length=length, protocol=f"0x{ethertype:04x}")


def _decode_ipv4(data: bytes, ts: float, length: int) -> Packet:
    if len(data) < 20:
        return Packet(ts=ts, length=length, protocol="IPv4")
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    payload = data[ihl:]
    name = _IP_PROTO.get(proto, f"IP/{proto}")

    if name == "TCP":
        return _decode_tcp(payload, ts, length, src, dst)
    if name == "UDP":
        return _decode_udp(payload, ts, length, src, dst)
    if name == "ICMP":
        return _decode_icmp(payload, ts, length, src, dst)
    return Packet(ts=ts, length=length, protocol=name, src=src, dst=dst)


def _decode_tcp(data: bytes, ts: float, length: int, src: str, dst: str) -> Packet:
    if len(data) < 14:
        return Packet(ts=ts, length=length, protocol="TCP", src=src, dst=dst)
    sport, dport = struct.unpack(">HH", data[:4])
    flag_bits = data[13]
    flags = "".join(ch for bit, ch in _TCP_FLAGS if flag_bits & bit) or "."
    return Packet(ts, length, "TCP", src, dst, sport, dport, info=f"[{flags}]")


def _decode_udp(data: bytes, ts: float, length: int, src: str, dst: str) -> Packet:
    if len(data) < 8:
        return Packet(ts=ts, length=length, protocol="UDP", src=src, dst=dst)
    sport, dport, ulen = struct.unpack(">HHH", data[:6])
    return Packet(ts, length, "UDP", src, dst, sport, dport, info=f"len={ulen}")


def _decode_icmp(data: bytes, ts: float, length: int, src: str, dst: str) -> Packet:
    if len(data) < 2:
        return Packet(ts=ts, length=length, protocol="ICMP", src=src, dst=dst)
    icmp_type, code = data[0], data[1]
    kinds = {0: "echo-reply", 8: "echo-request", 3: "unreachable", 11: "time-exceeded"}
    info = kinds.get(icmp_type, f"type {icmp_type}") + (f"/{code}" if code else "")
    return Packet(ts, length, "ICMP", src, dst, info=info)
