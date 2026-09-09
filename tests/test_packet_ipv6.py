"""Packet decoding beyond plain IPv4 Ethernet: IPv6 (with extension headers),
VLAN tags, Linux cooked capture, and the transport payload the OT rules need.
"""

from __future__ import annotations

import socket
import struct

from pyscan.domain.packet import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_RAW,
    decode,
)

V6_SRC = "2001:db8::1"
V6_DST = "2001:db8::2"


def _tcp(sport=1234, dport=502, flags=0x18, payload=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 0, 0, 0) + payload


def _udp(sport=5353, dport=53, payload=b""):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _ipv6(next_header, body, src=V6_SRC, dst=V6_DST):
    return (
        struct.pack(">IHBB", 0x60000000, len(body), next_header, 64)
        + socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
        + body
    )


def _ipv4(proto, body, src="1.2.3.4", dst="5.6.7.8"):
    return (
        struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0,
            socket.inet_aton(src), socket.inet_aton(dst),
        )
        + body
    )


# --------------------------------------------------------------------------
# IPv6
# --------------------------------------------------------------------------
def test_ipv6_tcp_carries_real_addresses_and_ports():
    packet = decode(_ipv6(6, _tcp(40000, 443, 0x02)), LINKTYPE_RAW)
    assert packet.protocol == "TCP"
    assert packet.src == V6_SRC and packet.dst == V6_DST
    assert packet.sport == 40000 and packet.dport == 443
    assert packet.flags == "S" and packet.version == 6


def test_ipv6_over_ethernet():
    frame = bytes(12) + b"\x86\xdd" + _ipv6(17, _udp(53, 5353))
    packet = decode(frame, LINKTYPE_ETHERNET)
    assert packet.protocol == "UDP" and packet.dst == V6_DST


def test_ipv6_extension_headers_are_walked_to_the_transport():
    inner = _tcp(1111, 502, payload=b"\xaa\xbb")
    # Hop-by-hop options (8 bytes) in front of the TCP header.
    hop_by_hop = bytes([6, 0]) + bytes(6)
    packet = decode(_ipv6(0, hop_by_hop + inner), LINKTYPE_RAW)
    assert packet.protocol == "TCP" and packet.dport == 502
    assert packet.payload == b"\xaa\xbb"


def test_ipv6_fragment_header_is_walked():
    inner = _tcp(2222, 80)
    fragment = bytes([6, 0]) + bytes(6)  # next=TCP, fixed 8 bytes
    assert decode(_ipv6(44, fragment + inner), LINKTYPE_RAW).sport == 2222


def test_icmpv6_is_named_and_decoded():
    packet = decode(_ipv6(58, bytes([128, 0, 0, 0])), LINKTYPE_RAW)
    assert packet.protocol == "ICMPv6" and "echo-request" in packet.info


def test_ipv6_with_no_next_header():
    assert decode(_ipv6(59, b""), LINKTYPE_RAW).protocol == "IPv6"


def test_truncated_ipv6_header_degrades_gracefully():
    assert decode(b"\x60" + bytes(10), LINKTYPE_RAW).protocol == "IPv6"


# --------------------------------------------------------------------------
# link layers
# --------------------------------------------------------------------------
def test_vlan_tag_is_stepped_over():
    frame = bytes(12) + b"\x81\x00" + b"\x00\x64" + b"\x08\x00" + _ipv4(6, _tcp(1, 2))
    assert decode(frame, LINKTYPE_ETHERNET).protocol == "TCP"


def test_linux_cooked_capture():
    frame = bytes(14) + b"\x08\x00" + _ipv4(6, _tcp(1, 502))
    packet = decode(frame, LINKTYPE_LINUX_SLL)
    assert packet.protocol == "TCP" and packet.dport == 502


def test_short_cooked_frame_is_unknown():
    assert decode(b"\x00" * 4, LINKTYPE_LINUX_SLL).protocol == "?"


def test_unknown_ethertype_is_reported_in_hex():
    assert decode(bytes(12) + b"\x88\xcc" + bytes(10), LINKTYPE_ETHERNET).protocol == "0x88cc"


def test_unknown_linktype_is_unknown():
    assert decode(b"\xff" * 40, 999).protocol == "?"


def test_non_ip_version_nibble_is_unknown():
    assert decode(b"\x70" + bytes(30), LINKTYPE_RAW).protocol == "?"


# --------------------------------------------------------------------------
# payload extraction — what the OT rules depend on
# --------------------------------------------------------------------------
def test_tcp_payload_is_extracted_past_the_options():
    body = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x7d"
    packet = decode(_ipv4(6, _tcp(1, 502, payload=body)), LINKTYPE_RAW)
    assert packet.payload == body


def test_ethernet_padding_is_not_mistaken_for_payload():
    # A 20-byte IPv4 + 20-byte TCP packet padded out to the 60-byte minimum.
    frame = bytes(12) + b"\x08\x00" + _ipv4(6, _tcp(1, 502)) + b"\x00" * 6
    assert decode(frame, LINKTYPE_ETHERNET).payload == b""


def test_udp_payload_respects_the_length_field():
    packet = decode(_ipv4(17, _udp(1, 161, b"\x30\x26")), LINKTYPE_RAW)
    assert packet.payload == b"\x30\x26"


def test_ipv4_protocol_without_a_decoder_is_named_by_number():
    assert decode(_ipv4(47, b"\x00" * 8), LINKTYPE_RAW).protocol == "IP/47"
