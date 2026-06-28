"""Pure SYN-scan logic — classify a probe response, no sockets.

A SYN (half-open) scan sends a lone SYN and reads the reply:
  - SYN/ACK  -> port is OPEN   (we then send RST instead of completing)
  - RST/ACK  -> port is CLOSED
  - nothing  -> FILTERED       (firewall drop / host down)
  - ICMP unreachable -> FILTERED

This module just maps raw TCP flag bits to a PortState, so it's unit-testable
without raw sockets or privileges. The scapy I/O lives in the adapter.
"""

from __future__ import annotations

from pyscan.domain.models import PortState

# TCP control-flag bits
SYN = 0x02
RST = 0x04
ACK = 0x10
SYN_ACK = SYN | ACK  # 0x12
RST_ACK = RST | ACK  # 0x14


def classify(tcp_flags: int | None, icmp_unreachable: bool = False) -> PortState:
    if icmp_unreachable:
        return PortState.FILTERED
    if tcp_flags is None:
        return PortState.FILTERED
    if tcp_flags & SYN_ACK == SYN_ACK:
        return PortState.OPEN
    if tcp_flags & RST:
        return PortState.CLOSED
    return PortState.FILTERED
