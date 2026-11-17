"""Turning a (possibly cached) LookupResult into a Probe's metrics."""

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest

from .cache import ResultCache
from .lookup import LookupResult, Outcome, lookup

log = logging.getLogger(__name__)

Lookup = Callable[[str, float], LookupResult]

# Lookups waiting for the WHOIS worker beyond this are refused, so a flood of
# Probes for random Domains can't queue work without bound.
MAX_PENDING_LOOKUPS = 1000


class SelfMetrics:
    """The exporter's own operational metrics, served on /metrics."""

    def __init__(self, registry: CollectorRegistry) -> None:
        self.lookups = Counter(
            "domain_expiry_exporter_lookups",
            "WHOIS lookups performed, by outcome.",
            ["outcome"],
            registry=registry,
        )
        self.cache_requests = Counter(
            "domain_expiry_exporter_cache_requests",
            "Probe cache lookups, by result.",
            ["result"],
            registry=registry,
        )
        self.cache_entries = Gauge(
            "domain_expiry_exporter_cache_entries",
            "Domains currently held in the result cache.",
            registry=registry,
        )
        for outcome in Outcome:
            self.lookups.labels(outcome.value)
        for result in ("hit", "miss"):
            self.cache_requests.labels(result)


class Prober:
    """Answers Probes from the cache, running WHOIS lookups on one background worker.

    Lookups run one at a time, in order (ADR-0003). A Probe waits for its lookup
    only as long as its own budget allows; a lookup that outlives the Probe keeps
    going and its result is cached for the next scrape.
    """

    def __init__(
        self,
        cache: ResultCache,
        metrics: SelfMetrics,
        lookup_fn: Lookup = lookup,
        lookup_timeout: float = 20.0,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._cache = cache
        self._metrics = metrics
        self._lookup = lookup_fn
        self._lookup_timeout = lookup_timeout
        self._clock = clock
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="whois")
        self._pending: dict[str, Future[LookupResult]] = {}
        self._lock = threading.Lock()

    def result_for(self, domain: str, timeout: float) -> LookupResult:
        with self._lock:
            cached = self._cache.get(domain)
            if cached is not None:
                self._metrics.cache_requests.labels("hit").inc()
                return cached.result
            self._metrics.cache_requests.labels("miss").inc()
            future = self._pending.get(domain)
            if future is None:
                if len(self._pending) >= MAX_PENDING_LOOKUPS:
                    return LookupResult(domain, Outcome.TIMEOUT, detail="lookup queue is full")
                future = self._executor.submit(self._run, domain)
                self._pending[domain] = future
        try:
            return future.result(timeout=timeout)
        except FutureTimeout:
            return LookupResult(
                domain,
                Outcome.TIMEOUT,
                detail=f"no result within {timeout:g}s, lookup continues in the background",
            )

    def _run(self, domain: str) -> LookupResult:
        try:
            result = self._lookup(domain, self._lookup_timeout)
        except Exception as e:  # a bug in parsing must not wedge the Probe
            log.exception("lookup crashed domain=%s", domain)
            result = LookupResult(domain, Outcome.ERROR, detail=f"internal error: {e!r}")
        self._metrics.lookups.labels(result.outcome.value).inc()
        if not result.success:
            log.warning(
                "lookup failed domain=%s outcome=%s detail=%s",
                domain,
                result.outcome,
                printable(result.detail),
            )
        with self._lock:
            self._cache.put(result)
            self._pending.pop(domain, None)
        self._metrics.cache_entries.set(len(self._cache))
        return result

    def probe(self, domain: str, timeout: float) -> bytes:
        """Run a Probe and render its metrics in the Prometheus text format."""
        start = self._clock()
        result = self.result_for(domain, timeout)
        return render(result, self._clock() - start)

    def close(self) -> None:
        """Drop queued lookups; one already running finishes within its deadline."""
        self._executor.shutdown(wait=False, cancel_futures=True)


def printable(text: str) -> str:
    """WHOIS text with control characters (terminal escapes, newlines) replaced."""
    return "".join(c if c.isprintable() else "?" for c in text)


def render(result: LookupResult, duration: float) -> bytes:
    registry = CollectorRegistry(auto_describe=True)
    labels = {"domain": result.domain}

    Gauge(
        "probe_success",
        "Whether the WHOIS lookup succeeded (a Domain that is not Registered still counts).",
        labels.keys(),
        registry=registry,
    ).labels(**labels).set(1 if result.success else 0)
    Gauge(
        "probe_duration_seconds",
        "How long the Probe took, including cache hits.",
        labels.keys(),
        registry=registry,
    ).labels(**labels).set(duration)

    if result.success:
        Gauge(
            "domain_registered",
            "Whether the registry holds a record for the Domain.",
            labels.keys(),
            registry=registry,
        ).labels(**labels).set(1 if result.registered else 0)

    if result.success and result.expiry is not None:
        Gauge(
            "domain_expiry_timestamp_seconds",
            "When the Domain's registration expires, as a Unix timestamp.",
            labels.keys(),
            registry=registry,
        ).labels(**labels).set(result.expiry.timestamp())

    if result.success and result.statuses:
        status = Gauge(
            "domain_status",
            "Registry Status codes currently on the Domain (one series per Status).",
            ["domain", "status"],
            registry=registry,
        )
        for code in sorted(result.statuses):
            status.labels(domain=result.domain, status=code).set(1)

    return generate_latest(registry)
