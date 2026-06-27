"""Parse human port specs like '22,80,443', '1-1024', '1-100,8080' into ints.

Pure function, no I/O — the easiest possible thing to unit-test, and the kind
of fiddly parsing logic that benefits most from being isolated.
"""

from __future__ import annotations

MIN_PORT = 1
MAX_PORT = 65535


def parse_port_spec(spec: str) -> list[int]:
    """Return a sorted, de-duplicated list of ports.

    Raises ValueError on anything malformed or out of range.
    """
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, _, hi_s = chunk.partition("-")
            lo, hi = _to_port(lo_s), _to_port(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(_to_port(chunk))

    if not ports:
        raise ValueError("No ports parsed from spec.")
    return sorted(ports)


def _to_port(raw: str) -> int:
    raw = raw.strip()
    try:
        n = int(raw)
    except ValueError:
        raise ValueError(f"Invalid port: {raw!r}") from None
    if not (MIN_PORT <= n <= MAX_PORT):
        raise ValueError(f"Port out of range (1-65535): {n}")
    return n
