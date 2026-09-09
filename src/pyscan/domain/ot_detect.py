"""OT intrusion detection rules — PURE logic, no sockets, no capture library.

This is the blue-team half of the project, and it is deliberately built on the
exact same protocol codecs the scanner uses: `modbus.read_function_code`,
`iec104.parse_apdus`, `s7comm.parse_job`. One decoder, two products. A rule
engine that re-implemented MBAP framing for itself would drift away from the
scanner the first time either was fixed.

The rules encode one idea, the same one that runs through the whole project:
    reading a device is an audit; writing to it is an operation on the plant.

So severity is a function of two things — what the message does, and whether
the source is the station that is supposed to be doing it. A `Write Single
Coil` from the HMI is a Tuesday. The identical frame from an engineering laptop
that has never spoken to that PLC before is an incident.

Everything here is bytes-and-dataclasses in, alerts out, which is why it can be
tested exhaustively without a network, a PLC, or root.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

from pyscan.domain import iec104, modbus, s7comm
from pyscan.domain.packet import Packet

# Addresses arrive either as a CLI string or as an already-split iterable.
Addresses = str | Iterable[str] | None

# The three OT protocols this engine understands, by their registered port.
OT_PORTS: dict[int, str] = {502: "Modbus", 2404: "IEC-104", 102: "S7comm"}


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


_ORDER = {Severity.CRITICAL: 3, Severity.HIGH: 2, Severity.MEDIUM: 1, Severity.INFO: 0}


def at_least(severity: Severity, floor: Severity) -> bool:
    """True when `severity` is as serious as `floor` or worse."""
    return _ORDER[severity] >= _ORDER[floor]


@dataclass(frozen=True, slots=True)
class Alert:
    """One finding, ready to print, log to a timeline, or write into a report."""

    ts: float
    severity: Severity
    src: str
    dst: str
    protocol: str
    summary: str
    technique: str  # MITRE ATT&CK for ICS
    action: str  # what a responder should actually do


@dataclass(frozen=True, slots=True)
class Baseline:
    """Who is allowed to talk to what.

    `hmi` is the set of stations that legitimately drive the process; `plcs` is
    the set of devices being protected. An empty `plcs` means "protect anything
    that is spoken to on an OT port", so the engine is useful before you have
    finished mapping the site.
    """

    hmi: frozenset[str] = frozenset()
    plcs: frozenset[str] = frozenset()

    @classmethod
    def of(cls, hmi: Addresses = (), plcs: Addresses = ()) -> Baseline:
        """Build from anything iterable or comma-separated, ignoring blanks."""
        return cls(hmi=_as_set(hmi), plcs=_as_set(plcs))

    @property
    def known(self) -> bool:
        return bool(self.hmi)


def _as_set(value: Addresses) -> frozenset[str]:
    if value is None:
        return frozenset()
    items = value.split(",") if isinstance(value, str) else list(value)
    return frozenset(item.strip() for item in items if item.strip())


@dataclass
class Detector:
    """Stateful only in what it has already reported — the rules stay pure.

    The state is one set: which (source, target) pairs have already produced a
    "new talker" alert, so a chatty attacker does not flood the console with the
    same finding a thousand times.
    """

    baseline: Baseline = field(default_factory=Baseline)
    packets: int = 0
    alerts: int = 0
    hostile_sources: set[str] = field(default_factory=set)
    observed_operations: set[str] = field(default_factory=set)
    _seen_talkers: set[tuple[str, str]] = field(default_factory=set, repr=False)

    # -- rule helpers -------------------------------------------------------
    def _protected(self, host: str | None) -> bool:
        if host is None:
            return False
        return host in self.baseline.plcs if self.baseline.plcs else True

    def _unauthorised(self, host: str | None) -> bool:
        """True when the source is definitely not the station in charge."""
        return host is not None and self.baseline.known and host not in self.baseline.hmi

    def _severity(self, src: str | None, when_hostile: Severity) -> Severity:
        if self._unauthorised(src):
            return when_hostile
        if not self.baseline.known:
            # No baseline given: a write is still worth surfacing, but we cannot
            # honestly call it unauthorised.
            return Severity.HIGH if when_hostile is Severity.CRITICAL else Severity.MEDIUM
        return Severity.INFO  # it came from the HMI: expected operation

    def _alert(
        self,
        pkt: Packet,
        severity: Severity,
        protocol: str,
        summary: str,
        technique: str,
        action: str,
    ) -> Alert:
        self.alerts += 1
        if self._unauthorised(pkt.src) and severity is not Severity.INFO:
            self.hostile_sources.add(str(pkt.src))
        return Alert(
            ts=pkt.ts,
            severity=severity,
            src=str(pkt.src),
            dst=str(pkt.dst),
            protocol=protocol,
            summary=summary,
            technique=technique,
            action=action,
        )

    # -- the entry point ----------------------------------------------------
    def feed(self, pkt: Packet) -> list[Alert]:
        """Return every alert this packet justifies (usually none)."""
        if pkt.protocol != "TCP" or pkt.dport is None:
            return []
        protocol = OT_PORTS.get(pkt.dport)
        if protocol is None or not self._protected(pkt.dst):
            return []

        self.packets += 1
        out: list[Alert] = []

        if "S" in pkt.flags and "A" not in pkt.flags and self._unauthorised(pkt.src):
            out.append(
                self._alert(
                    pkt, Severity.MEDIUM, protocol,
                    f"New connection (SYN) to OT port {pkt.dport}",
                    "T0846 Remote System Discovery",
                    "Unexpected talker reaching OT. Watch it: this is the prelude.",
                )
            )

        if not pkt.payload:
            return out

        out.extend(self._new_talker(pkt, protocol))
        if protocol == "Modbus":
            out.extend(self._modbus(pkt))
        elif protocol == "IEC-104":
            out.extend(self._iec104(pkt))
        else:
            out.extend(self._s7comm(pkt))
        return out

    # -- per-protocol rules -------------------------------------------------
    def _new_talker(self, pkt: Packet, protocol: str) -> list[Alert]:
        pair = (str(pkt.src), str(pkt.dst))
        if not self._unauthorised(pkt.src) or pair in self._seen_talkers:
            return []
        self._seen_talkers.add(pair)
        return [
            self._alert(
                pkt, Severity.HIGH, protocol,
                "Unauthorised talker sending OT traffic to a protected device",
                "T0846 Remote System Discovery",
                "Isolate the SOURCE with an ACL at the IDMZ. The HMI should be the only one here.",
            )
        ]

    def _modbus(self, pkt: Packet) -> list[Alert]:
        function = modbus.read_function_code(pkt.payload)
        if function is None:
            return []
        name = modbus.function_name(function)
        kind = modbus.classify_function(function)
        self.observed_operations.add(f"Modbus FC{function}")

        if kind is modbus.FunctionClass.WRITE:
            return [
                self._alert(
                    pkt, self._severity(pkt.src, Severity.CRITICAL), "Modbus",
                    f"WRITE to the process - FC{function} {name}",
                    "T0855 Unauthorized Command Message / T0836 Modify Parameter",
                    "Confirm the source is not the HMI, then isolate it. Do NOT reboot the PLC; "
                    "coordinate any restoration with operations.",
                )
            ]
        if kind is modbus.FunctionClass.PROGRAM:
            return [
                self._alert(
                    pkt, self._severity(pkt.src, Severity.CRITICAL), "Modbus",
                    f"Logic/file operation - FC{function} {name}",
                    "T0843 Program Download",
                    "Someone is changing what the device runs. Isolate the source and preserve evidence.",
                )
            ]
        if kind is modbus.FunctionClass.RECON and self._unauthorised(pkt.src):
            return [
                self._alert(
                    pkt, Severity.MEDIUM, "Modbus",
                    f"Reconnaissance - FC{function} {name}",
                    "T0888 Remote System Information Discovery",
                    "Enumeration usually precedes the write. Track this source now.",
                )
            ]
        return []

    def _iec104(self, pkt: Packet) -> list[Alert]:
        out: list[Alert] = []
        for apdu in iec104.parse_apdus(pkt.payload):
            if apdu.format is iec104.Format.U:
                if apdu.control == 0x13:  # STOPDT act
                    self.observed_operations.add("IEC-104 STOPDT")
                    out.append(
                        self._alert(
                            pkt, Severity.MEDIUM, "IEC-104",
                            "STOPDT act - an attempt to stop the outstation reporting",
                            "T0804 Block Reporting Message",
                            "Telemetry is being silenced. Correlate with any commands just before it; "
                            "do not trust a quiet HMI.",
                        )
                    )
                continue
            if apdu.type_id is None:
                continue

            kind = iec104.classify_type_id(apdu.type_id)
            self.observed_operations.add(f"IEC-104 T{apdu.type_id}")
            if kind is iec104.TypeClass.COMMAND:
                out.append(
                    self._alert(
                        pkt, self._severity(pkt.src, Severity.CRITICAL), "IEC-104",
                        f"CONTROL COMMAND - {apdu.name}",
                        "T0855 Unauthorized Command Message",
                        "A legitimate command from an illegitimate source is the Industroyer signature. "
                        "Isolate the source; do not cut the process.",
                    )
                )
            elif kind is iec104.TypeClass.SYSTEM and self._unauthorised(pkt.src):
                out.append(
                    self._alert(
                        pkt, Severity.MEDIUM, "IEC-104",
                        f"Reconnaissance - {apdu.name}",
                        "T0888 Remote System Information Discovery",
                        "An interrogation from a non-HMI source usually precedes the command.",
                    )
                )
        return out

    def _s7comm(self, pkt: Packet) -> list[Alert]:
        job = s7comm.parse_job(pkt.payload)
        if job is None or job.rosctr != 0x01:  # only requests, not the PLC replies
            return []
        self.observed_operations.add(f"S7 {job.name}")

        if job.job_class is s7comm.JobClass.PROGRAM:
            return [
                self._alert(
                    pkt, self._severity(pkt.src, Severity.CRITICAL), "S7comm",
                    f"Block transfer - {job.name}",
                    "T0843 Program Download",
                    "Control logic is being read or replaced. Isolate the source and preserve the capture.",
                )
            ]
        if job.job_class is s7comm.JobClass.CONTROL:
            return [
                self._alert(
                    pkt, self._severity(pkt.src, Severity.CRITICAL), "S7comm",
                    f"CPU control - {job.name}",
                    "T0858 Change Operating Mode / T0813 Denial of Control",
                    "Someone is starting or stopping the CPU. Alert operations before anything else.",
                )
            ]
        if job.job_class is s7comm.JobClass.WRITE:
            return [
                self._alert(
                    pkt, self._severity(pkt.src, Severity.CRITICAL), "S7comm",
                    f"WRITE to the process - {job.name}",
                    "T0855 Unauthorized Command Message",
                    "Confirm the source, then isolate it. Do not stop the CPU yourself.",
                )
            ]
        return []
