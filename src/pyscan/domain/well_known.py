"""Tiny well-known-port lookup so output reads like nmap ('22 open ssh').

Intentionally small and pure. Extend the table or swap it for an
/etc/services parser later without touching anything else.
"""

from __future__ import annotations

_WELL_KNOWN: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 80: "http", 110: "pop3", 123: "ntp",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1883: "mqtt", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5672: "amqp", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    # OT/ICS additions you'll want for the CIUDEN side later:
    502: "modbus", 2404: "iec-104", 20000: "dnp3", 102: "s7comm",
}


def service_for(port: int) -> str | None:
    return _WELL_KNOWN.get(port)
