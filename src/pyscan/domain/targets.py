"""Expand a target spec into concrete hosts — PURE, no DNS, no sockets.

Handles a single IP (v4 or v6), a hostname, or a CIDR range. A hostname cannot
be expanded without DNS (which is I/O), so it is passed straight through for
the scanner to resolve later. Keeping this pure means the fiddly CIDR maths is
trivially testable.
"""

from __future__ import annotations

import ipaddress
import socket

MAX_HOSTS = 65536  # guard: a /8 would be ~16M hosts — refuse rather than hang


def expand_targets(spec: str) -> list[str]:
    """Return the list of hosts a spec refers to.

    '192.168.1.5'      -> ['192.168.1.5']
    'scanme.nmap.org'  -> ['scanme.nmap.org']        (resolved later)
    '192.168.1.0/24'   -> ['192.168.1.1', ..., '192.168.1.254']
    '2001:db8::/126'   -> ['2001:db8::1', '2001:db8::2', '2001:db8::3']
    """
    spec = spec.strip()
    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return [spec]  # not an IP/CIDR -> treat as a hostname

    if net.num_addresses == 1:  # a bare IP parses as /32 or /128
        return [str(net.network_address)]

    # Check size BEFORE materialising — a /8 has ~16M addresses and building
    # that list just to reject it would hang for seconds. An IPv6 /64 is
    # unenumerable by construction, which this same guard catches.
    if net.num_addresses > MAX_HOSTS + 2:  # +2 for network/broadcast
        raise ValueError(
            f"Range too large ({net.num_addresses} addresses > {MAX_HOSTS}). "
            "Narrow the CIDR."
        )
    return [str(h) for h in net.hosts()]


def family_of(host: str) -> int:
    """The socket address family a literal host belongs to.

    Anything that is not an IPv6 literal is treated as AF_INET, which keeps the
    common path (v4 literals and already-resolved hostnames) free of surprises.
    """
    try:
        return socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    except ValueError:
        return socket.AF_INET


def is_ipv6(host: str) -> bool:
    return family_of(host) == socket.AF_INET6
