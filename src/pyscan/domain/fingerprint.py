"""Service/version fingerprinting — PURE logic, no sockets.

This is the 'identify' half of recon, deliberately separated from the 'probe'
half (the strategy that talks to sockets). Given a banner string and a port,
it returns a best guess of service + product + version by matching the banner
against a table of signatures. No I/O means it's trivial to unit-test: feed it
a string, assert the result.

Adding detection for a new product is one new row in _SIGNATURES.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pyscan.domain.well_known import service_for


@dataclass(frozen=True, slots=True)
class ServiceInfo:
    service: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class _Signature:
    service: str
    product: str | None
    regex: re.Pattern[str]


# Order matters: most specific first. A signature may capture a (?P<version>...)
# group and/or a (?P<product>...) group; product on the row is the fixed name.
_SIGNATURES: list[_Signature] = [
    _Signature("s7comm", None, re.compile(r"S7comm(?:\s+(?P<product>.+))?", re.I)),
    _Signature("iec-104", None, re.compile(r"IEC 60870-5-104", re.I)),
    _Signature("modbus", None, re.compile(r"Modbus/TCP(?:\s+(?P<product>.+?))?(?:\s+v(?P<version>[\d.]+))?\s*$", re.I)),
    _Signature("ssh", "OpenSSH", re.compile(r"SSH-[\d.]+-OpenSSH[_-](?P<version>[\w.]+)", re.I)),
    _Signature("ssh", "Dropbear", re.compile(r"SSH-[\d.]+-dropbear[_-]?(?P<version>[\w.]*)", re.I)),
    _Signature("ssh", None, re.compile(r"SSH-(?P<version>[\d.]+)-", re.I)),
    _Signature("ftp", "vsftpd", re.compile(r"vsftpd (?P<version>[\d.]+)", re.I)),
    _Signature("ftp", "ProFTPD", re.compile(r"ProFTPD (?P<version>[\d.]+)", re.I)),
    _Signature("ftp", "FileZilla", re.compile(r"FileZilla Server[ ]?(?P<version>[\d.]*)", re.I)),
    _Signature("http", "nginx", re.compile(r"Server:\s*nginx(?:/(?P<version>[\d.]+))?", re.I)),
    _Signature("http", "Apache", re.compile(r"Server:\s*Apache(?:/(?P<version>[\d.]+))?", re.I)),
    _Signature("http", "lighttpd", re.compile(r"Server:\s*lighttpd(?:/(?P<version>[\d.]+))?", re.I)),
    _Signature("http", "IIS", re.compile(r"Server:\s*Microsoft-IIS/(?P<version>[\d.]+)", re.I)),
    _Signature("http", None, re.compile(r"Server:\s*(?P<product>[^\r\n ;]+)", re.I)),
    _Signature("smtp", "Exim", re.compile(r"220[ -].*Exim (?P<version>[\d.]+)", re.I)),
    _Signature("smtp", "Postfix", re.compile(r"220[ -].*Postfix", re.I)),
    _Signature("smtp", None, re.compile(r"^220[ -]", re.I)),
    _Signature("pop3", None, re.compile(r"^\+OK", re.I)),
    _Signature("imap", None, re.compile(r"^\* OK", re.I)),
    _Signature("mysql", "MySQL", re.compile(r"(?P<version>\d+\.\d+\.\d+)\D*mysql", re.I)),
    _Signature("redis", "Redis", re.compile(r"redis_version:(?P<version>[\d.]+)", re.I)),
]


def identify(banner: str | None, port: int) -> ServiceInfo:
    """Best-effort service/product/version from a banner, with a port fallback."""
    if banner:
        for sig in _SIGNATURES:
            match = sig.regex.search(banner)
            if match:
                groups = match.groupdict()
                return ServiceInfo(
                    service=sig.service,
                    product=sig.product or groups.get("product"),
                    version=groups.get("version") or None,
                )
    # No banner, or nothing matched: fall back to the well-known port guess.
    return ServiceInfo(service=service_for(port))
