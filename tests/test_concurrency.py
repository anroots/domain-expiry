"""The server stays responsive while WHOIS is slow, and lookups stay serialised."""

import socket
import threading
import time
import urllib.request

import pytest
from prometheus_client import CollectorRegistry

from domain_expiry.app import make_app, make_http_server
from domain_expiry.cache import ResultCache
from domain_expiry.config import Config
from domain_expiry.lookup import LookupResult, Outcome
from domain_expiry.probe import Prober, SelfMetrics, printable


class SlowLookup:
    """A lookup that blocks until released, recording how many ran at once."""

    def __init__(self):
        self.release = threading.Event()
        self.running = 0
        self.max_running = 0
        self.calls = []
        self._lock = threading.Lock()

    def __call__(self, domain, timeout):
        with self._lock:
            self.calls.append(domain)
            self.running += 1
            self.max_running = max(self.max_running, self.running)
        self.release.wait(5)
        with self._lock:
            self.running -= 1
        return LookupResult(domain, Outcome.OK, registered=True)


def make_prober(lookup_fn):
    cache = ResultCache(success_ttl=3600, failure_ttl=60, max_entries=100)
    return Prober(cache, SelfMetrics(CollectorRegistry()), lookup_fn=lookup_fn)


@pytest.fixture
def server():
    slow = SlowLookup()
    prober = make_prober(slow)
    config = Config(listen_address="127.0.0.1", port=0)
    httpd = make_http_server(make_app(prober, config, registry=CollectorRegistry()), config)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield slow, f"http://127.0.0.1:{httpd.server_address[1]}"
    slow.release.set()
    httpd.shutdown()
    httpd.server_close()
    prober.close()


def get(url, timeout=2):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read().decode()


def test_health_and_metrics_answer_during_a_slow_lookup(server):
    slow, base = server
    probe = threading.Thread(target=get, args=(f"{base}/probe?target=example.com", 10))
    probe.start()
    time.sleep(0.2)
    assert slow.running == 1
    assert get(f"{base}/-/healthy")[0] == 200
    assert get(f"{base}/metrics")[0] == 200
    slow.release.set()
    probe.join()


def test_idle_connection_does_not_block_others(server):
    _, base = server
    port = int(base.rsplit(":", 1)[1])
    with socket.create_connection(("127.0.0.1", port)):
        assert get(f"{base}/-/healthy")[0] == 200


def test_lookups_run_one_at_a_time(server):
    slow, base = server
    probes = [
        threading.Thread(target=get, args=(f"{base}/probe?target=d{i}.com", 10)) for i in range(3)
    ]
    for t in probes:
        t.start()
    time.sleep(0.3)
    slow.release.set()
    for t in probes:
        t.join()
    assert slow.max_running == 1
    assert sorted(slow.calls) == ["d0.com", "d1.com", "d2.com"]


def test_probe_times_out_but_lookup_result_is_cached_for_next_probe():
    slow = SlowLookup()
    prober = make_prober(slow)
    try:
        first = prober.result_for("example.com", timeout=0.1)
        assert first.outcome is Outcome.TIMEOUT
        slow.release.set()
        deadline = time.monotonic() + 2
        while prober.result_for("example.com", 0.1).outcome is not Outcome.OK:
            assert time.monotonic() < deadline
        assert slow.calls == ["example.com"]
    finally:
        prober.close()


def test_concurrent_probes_for_one_domain_share_a_lookup():
    slow = SlowLookup()
    prober = make_prober(slow)
    try:
        results = []
        threads = [
            threading.Thread(target=lambda: results.append(prober.result_for("a.com", 5)))
            for _ in range(3)
        ]
        for t in threads:
            t.start()
        time.sleep(0.2)
        slow.release.set()
        for t in threads:
            t.join()
        assert slow.calls == ["a.com"]
        assert all(r.outcome is Outcome.OK for r in results)
    finally:
        prober.close()


def test_crashing_lookup_becomes_an_error_result():
    def boom(domain, timeout):
        raise RuntimeError("parser bug")

    prober = make_prober(boom)
    try:
        assert prober.result_for("a.com", 1).outcome is Outcome.ERROR
    finally:
        prober.close()


def test_printable_strips_control_characters():
    assert printable("bad\x1b[31mred\nline\x00") == "bad?[31mred?line?"
