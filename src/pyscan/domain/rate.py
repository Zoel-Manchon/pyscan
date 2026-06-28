"""Pure rate pacer — evenly spaces probe 'slots' at N per second.

Rate limiting matters for OT: fragile ICS devices can fall over under a flood,
so capping probes/second is a safety feature, not just politeness. The math
(when does the next slot open?) is pure and clock-injected, so it's testable
without touching real time. The async glue lives in the application layer.
"""

from __future__ import annotations


class Pacer:
    def __init__(self, rate: float, start: float = 0.0) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self._interval = 1.0 / rate
        self._next = start

    def reserve(self, now: float) -> float:
        """Reserve the next slot; return seconds to wait from `now` until it fires.

        Back-to-back reservations are spaced one interval apart. If the caller is
        already past the next slot (an idle gap), the slot resets to `now` — so a
        lull never banks up into a burst.
        """
        slot = self._next if self._next > now else now
        self._next = slot + self._interval
        return slot - now
