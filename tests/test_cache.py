from domain_expiry.cache import ResultCache
from domain_expiry.lookup import LookupResult, Outcome


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def ok(domain):
    return LookupResult(domain, Outcome.OK, registered=True)


def failed(domain):
    return LookupResult(domain, Outcome.TIMEOUT)


def test_success_is_kept_for_success_ttl():
    clock = Clock()
    cache = ResultCache(success_ttl=100, failure_ttl=10, max_entries=10, clock=clock)
    cache.put(ok("a.com"))
    clock.now += 99
    assert cache.get("a.com").result.outcome is Outcome.OK
    clock.now += 1
    assert cache.get("a.com") is None


def test_failure_is_kept_for_failure_ttl():
    clock = Clock()
    cache = ResultCache(success_ttl=100, failure_ttl=10, max_entries=10, clock=clock)
    cache.put(failed("a.com"))
    clock.now += 9
    assert cache.get("a.com") is not None
    clock.now += 1
    assert cache.get("a.com") is None


def test_not_found_counts_as_success():
    clock = Clock()
    cache = ResultCache(success_ttl=100, failure_ttl=10, max_entries=10, clock=clock)
    cache.put(LookupResult("gone.com", Outcome.NOT_FOUND))
    clock.now += 50
    assert cache.get("gone.com") is not None


def test_least_recently_probed_is_evicted():
    cache = ResultCache(success_ttl=100, failure_ttl=10, max_entries=2, clock=Clock())
    cache.put(ok("a.com"))
    cache.put(ok("b.com"))
    cache.get("a.com")  # a.com is now the most recently probed
    cache.put(ok("c.com"))
    assert cache.get("b.com") is None
    assert cache.get("a.com") is not None
    assert cache.get("c.com") is not None
    assert len(cache) == 2


def test_new_result_replaces_old():
    clock = Clock()
    cache = ResultCache(success_ttl=100, failure_ttl=10, max_entries=10, clock=clock)
    cache.put(failed("a.com"))
    cache.put(ok("a.com"))
    clock.now += 50
    assert cache.get("a.com").result.outcome is Outcome.OK
