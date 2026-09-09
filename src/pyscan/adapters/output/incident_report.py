"""Markdown incident report — the artefact you hand over when the shift ends.

Pure enough to test: given a detector's state and a timeline of events, it
returns the report as a string. Writing it to disk is one line on top, so the
formatting can be asserted without touching a filesystem.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from pyscan.domain.ot_detect import Detector

TimelineEntry = tuple[str, str, str]  # (UTC time, kind, detail)


def build_report(
    detector: Detector,
    timeline: Sequence[TimelineEntry] = (),
    now: datetime | None = None,
) -> str:
    stamp = now or datetime.now(UTC)
    sources = ", ".join(sorted(detector.hostile_sources)) or "-"
    operations = ", ".join(sorted(detector.observed_operations)) or "-"

    lines = [
        f"# INC-{stamp.strftime('%Y%m%d')}-01 - OT incident",
        "",
        f"Generated: {stamp.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Traffic reviewed: {detector.packets} OT packets, {detector.alerts} alerts raised.",
        "",
        "## 1. Executive summary",
        "",
        "_[fill in: what happened, over what window, current status]_",
        "",
        "## 2. Indicators of compromise",
        "",
        f"- Hostile source(s): `{sources}`",
        f"- Operations observed: `{operations}`",
        "- OT ports in scope: 502 (Modbus) / 2404 (IEC-104) / 102 (S7comm)",
        "",
        "## 3. Timeline (UTC)",
        "",
    ]
    if timeline:
        lines += [f"- **{when}** - {kind} - {detail}" for when, kind, detail in timeline]
    else:
        lines.append("_(no events recorded)_")

    lines += [
        "",
        "## 4. ATT&CK for ICS mapping",
        "",
        "Discovery (T0846 / T0888) -> Collection -> Impair Process Control "
        "(T0855 Unauthorized Command Message) -> Impact.",
        "",
        "## 5. Containment and recommendations",
        "",
        "- Source isolated by ACL at the IDMZ - the source, not the PLC.",
        "- Setpoint and breaker restoration coordinated with operations.",
        "- Allow-list of sources permitted to reach the PLC; IDS rule on any write "
        "from a source other than the HMI.",
        "",
        "---",
        "",
        "Availability > Integrity > Confidentiality. Detect, map, document, "
        "isolate the source, report.",
    ]
    return "\n".join(lines) + "\n"


def write_report(
    path: str | Path,
    detector: Detector,
    timeline: Sequence[TimelineEntry] = (),
    now: datetime | None = None,
) -> Path:
    target = Path(path)
    target.write_text(build_report(detector, timeline, now), encoding="utf-8")
    return target
