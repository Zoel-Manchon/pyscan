import socket
import struct

from pyscan.domain.packet import LINKTYPE_ETHERNET, LINKTYPE_RAW, decode


def _ipv4(proto, payload, src="1.2.3.4", dst="5.6.7.8"):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def _tcp(sport, dport, flags):
    return struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 0, 0, 0)


def _udp(sport, dport, payload=b""):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def test_decode_tcp_syn():
    p = decode(_ipv4(6, _tcp(51000, 443, 0x02)), LINKTYPE_RAW)
    assert p.protocol == "TCP" and p.sport == 51000 and p.dport == 443
    assert p.info == "[S]"
    assert p.src == "1.2.3.4" and p.dst == "5.6.7.8"


def test_decode_tcp_syn_ack():
    p = decode(_ipv4(6, _tcp(443, 51000, 0x12)), LINKTYPE_RAW)
    assert p.info == "[SA]"


def test_decode_udp():
    p = decode(_ipv4(17, _udp(5353, 53, b"\x00\x00")), LINKTYPE_RAW)
    assert p.protocol == "UDP" and p.sport == 5353 and p.dport == 53


def test_decode_icmp_echo():
    p = decode(_ipv4(1, struct.pack(">BBH", 8, 0, 0)), LINKTYPE_RAW)
    assert p.protocol == "ICMP" and "echo-request" in p.info


def test_decode_ethernet_wraps_ip():
    frame = bytes(12) + b"\x08\x00" + _ipv4(6, _tcp(1, 2, 0x02))
    p = decode(frame, LINKTYPE_ETHERNET)
    assert p.protocol == "TCP"


def test_decode_arp():
    frame = bytes(12) + b"\x08\x06" + bytes(28)
    p = decode(frame, LINKTYPE_ETHERNET)
    assert p.protocol == "ARP"


def test_garbage_is_unknown():
    assert decode(b"\x00\x01", LINKTYPE_ETHERNET).protocol == "?"
