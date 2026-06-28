"""Async gate around the pure Pacer — throttles probe launches to a max rate.

A lock serialises the slot reservations; the actual wait happens outside the
lock so paced probes sleep concurrently rather than blocking each other.
"""

from __future__ import annotations

import asyncio
import time

from pyscan.domain.rate import Pacer


class AsyncRateLimiter:
    def __init__(self, rate: float) -> None:
        self._pacer = Pacer(rate, time.monotonic())
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            wait = self._pacer.reserve(time.monotonic())
        if wait > 0:
            await asyncio.sleep(wait)
