"""UDP probe payloads — pure data, no sockets.

UDP has no handshake, so many services stay silent if you send an empty packet.
Sending a *protocol-correct* payload makes them answer, which is the difference
between a useless scan and a real one. Each entry is a minimal, read-only query
for a given service; OT protocols (DNP3, Modbus/UDP) are included for ICS recon.
"""

from __future__ import annotations

from pyscan.domain.modbus import build_device_id_request


def _dnp3_crc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def _dnp3_link_status() -> bytes:
    # Request Link Status: start(0x0564) | len | ctrl(0xC9) | dst | src | CRC
    header = bytes([0x05, 0x64, 0x05, 0xC9, 0x00, 0x00, 0x00, 0x00])
    crc = _dnp3_crc(header)
    return header + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


# NTP client request: mode 3, version 3 — 48 bytes, first byte 0x1B.
_NTP = bytes([0x1B]) + bytes(47)

# DNS query: version.bind CHAOS TXT — a classic that makes resolvers answer.
_DNS = (
    b"\x00\x00"                            # transaction id
    b"\x01\x00"                            # flags: standard query, RD
    b"\x00\x01\x00\x00\x00\x00\x00\x00"    # qdcount=1
    b"\x07version\x04bind\x00"             # qname: version.bind
    b"\x00\x10"                            # qtype TXT
    b"\x00\x03"                            # qclass CHAOS
)

# SNMPv1 GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0), community "public".
_SNMP = bytes.fromhex(
    "302902010004067075626c6963"          # SEQ, version v1, community "public"
    "a01c0204000000000201000201003"       # GetRequest PDU, request-id, err/idx
    "00e300c06082b06010201010100"         # varbind list -> OID sysDescr.0
    "0500"                                 # NULL value
)

_PROBES: dict[int, bytes] = {
    53: _DNS,
    123: _NTP,
    161: _SNMP,
    502: build_device_id_request(),       # Modbus/UDP
    20000: _dnp3_link_status(),            # DNP3
}

_DEFAULT = b"\x00"  # unknown ports: a single byte, enough to trigger ICMP if closed


def payload_for(port: int) -> bytes:
    return _PROBES.get(port, _DEFAULT)
