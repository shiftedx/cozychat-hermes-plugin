"""Bounded admission before doing Noise work; no unauthenticated peer gets a reply."""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Callable


class HandshakeLimiter:
    """Per-source and global token buckets, with bounded source bookkeeping."""

    def __init__(self, *, per_minute: float = 20, burst: int = 20,
                 global_per_minute: float = 120, global_burst: int = 32,
                 max_sources: int = 1024, clock: Callable[[], float] = time.monotonic) -> None:
        self._rate = per_minute / 60
        self._burst = burst
        self._global_rate = global_per_minute / 60
        self._global_burst = global_burst
        self._global = (float(global_burst), clock())
        self._sources = OrderedDict()
        self._max_sources = max_sources
        self._clock = clock

    def admits(self, source: str) -> bool:
        now = self._clock()
        tokens, last = self._global
        tokens = min(self._global_burst, tokens + max(0, now - last) * self._global_rate)
        self._global = (tokens, now)
        if tokens < 1:
            return False
        available, last = self._sources.pop(source, (float(self._burst), now))
        available = min(self._burst, available + max(0, now - last) * self._rate)
        allowed = available >= 1
        self._sources[source] = (available - 1 if allowed else available, now)
        while len(self._sources) > self._max_sources:
            self._sources.popitem(last=False)
        # Rejected attempts consume global credit too, preventing rotation through many IPs
        # from doing unlimited admission/bookkeeping work.
        self._global = (tokens - 1, now)
        return allowed
