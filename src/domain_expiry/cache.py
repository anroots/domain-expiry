"""Bounded in-memory cache of LookupResults (see ADR-0001)."""

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from .lookup import LookupResult


@dataclass(frozen=True)
class CachedResult:
    result: LookupResult
    fetched_at: float
    expires_at: float


class ResultCache:
    """Successes live for success_ttl, failures for failure_ttl.

    The least recently probed Domain is evicted once max_entries is reached.
    Safe to use from several threads.
    """

    def __init__(
        self,
        success_ttl: float,
        failure_ttl: float,
        max_entries: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._success_ttl = success_ttl
        self._failure_ttl = failure_ttl
        self._max_entries = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, CachedResult] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, domain: str) -> CachedResult | None:
        with self._lock:
            return self._get(domain)

    def _get(self, domain: str) -> CachedResult | None:
        entry = self._entries.get(domain)
        if entry is None:
            return None
        if self._clock() >= entry.expires_at:
            del self._entries[domain]
            return None
        self._entries.move_to_end(domain)
        return entry

    def put(self, result: LookupResult) -> CachedResult:
        now = self._clock()
        ttl = self._success_ttl if result.success else self._failure_ttl
        entry = CachedResult(result, fetched_at=now, expires_at=now + ttl)
        with self._lock:
            self._entries[result.domain] = entry
            self._entries.move_to_end(result.domain)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
        return entry

    def __len__(self) -> int:
        return len(self._entries)
