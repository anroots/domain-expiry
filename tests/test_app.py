from datetime import UTC, datetime
from io import BytesIO

import pytest
from prometheus_client import CollectorRegistry
from prometheus_client.parser import text_string_to_metric_families

from domain_expiry.app import make_app, probe_timeout
from domain_expiry.cache import ResultCache
from domain_expiry.config import Config
from domain_expiry.lookup import LookupResult, Outcome
from domain_expiry.probe import Prober, SelfMetrics

EXPIRY = datetime(2027, 8, 13, 4, 0, tzinfo=UTC)

RESULTS = {
    "example.com": LookupResult(
        "example.com",
        Outcome.OK,
        registered=True,
        expiry=EXPIRY,
        statuses=frozenset({"client_hold", "client_transfer_prohibited"}),
    ),
    "eurid.eu": LookupResult("eurid.eu", Outcome.OK, registered=True),
    "gone.com": LookupResult("gone.com", Outcome.NOT_FOUND),
    "slow.com": LookupResult("slow.com", Outcome.TIMEOUT, detail="timed out"),
}


class Harness:
    def __init__(self):
        self.calls = []
        self.registry = CollectorRegistry()
        self.config = Config()

        def fake_lookup(domain, timeout):
            self.calls.append((domain, timeout))
            return RESULTS[domain]

        cache = ResultCache(success_ttl=3600, failure_ttl=60, max_entries=100)
        prober = Prober(
            cache,
            SelfMetrics(self.registry),
            lookup_fn=fake_lookup,
            lookup_timeout=self.config.lookup_timeout_seconds,
        )
        self.app = make_app(prober, self.config, registry=self.registry)

    def get(self, path, query="", headers=None):
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "wsgi.input": BytesIO(),
            **(headers or {}),
        }
        status = {}

        def start_response(s, h):
            status["code"] = int(s.split()[0])

        body = b"".join(self.app(environ, start_response)).decode()
        return status["code"], body


def samples(body):
    out = {}
    for family in text_string_to_metric_families(body):
        for s in family.samples:
            out[(s.name, tuple(sorted(s.labels.items())))] = s.value
    return out


@pytest.fixture
def h():
    return Harness()


def test_registered_domain(h):
    code, body = h.get("/probe", "target=example.com")
    assert code == 200
    m = samples(body)
    d = (("domain", "example.com"),)
    assert m[("probe_success", d)] == 1
    assert m[("domain_registered", d)] == 1
    assert m[("domain_expiry_timestamp_seconds", d)] == EXPIRY.timestamp()
    assert m[("domain_status", (("domain", "example.com"), ("status", "client_hold")))] == 1
    assert ("probe_duration_seconds", d) in m


def test_eu_domain_has_registration_but_no_expiry(h):
    m = samples(h.get("/probe", "target=eurid.eu")[1])
    d = (("domain", "eurid.eu"),)
    assert m[("probe_success", d)] == 1
    assert m[("domain_registered", d)] == 1
    assert ("domain_expiry_timestamp_seconds", d) not in m
    assert not any(name == "domain_status" for name, _ in m)


def test_unregistered_domain(h):
    m = samples(h.get("/probe", "target=gone.com")[1])
    d = (("domain", "gone.com"),)
    assert m[("probe_success", d)] == 1
    assert m[("domain_registered", d)] == 0
    assert ("domain_expiry_timestamp_seconds", d) not in m


def test_failed_lookup_omits_domain_metrics(h):
    m = samples(h.get("/probe", "target=slow.com")[1])
    d = (("domain", "slow.com"),)
    assert m[("probe_success", d)] == 0
    assert ("domain_registered", d) not in m
    assert ("domain_expiry_timestamp_seconds", d) not in m


@pytest.mark.parametrize("query", ["", "target=", "target=www.example.com", "target=com"])
def test_invalid_target_is_400(h, query):
    code, _ = h.get("/probe", query)
    assert code == 400
    assert h.calls == []


def test_target_is_canonicalised(h):
    h.get("/probe", "target=Example.COM.")
    assert h.calls[0][0] == "example.com"


def test_second_probe_is_served_from_cache(h):
    h.get("/probe", "target=example.com")
    h.get("/probe", "target=example.com")
    assert len(h.calls) == 1
    m = samples(h.get("/metrics")[1])
    assert m[("domain_expiry_exporter_cache_requests_total", (("result", "hit"),))] == 1
    assert m[("domain_expiry_exporter_cache_requests_total", (("result", "miss"),))] == 1
    assert m[("domain_expiry_exporter_lookups_total", (("outcome", "ok"),))] == 1
    assert m[("domain_expiry_exporter_cache_entries", ())] == 1


def test_failures_are_cached_too(h):
    h.get("/probe", "target=slow.com")
    h.get("/probe", "target=slow.com")
    assert len(h.calls) == 1


def test_whois_gets_the_configured_timeout_whatever_the_scrape_timeout(h):
    h.get(
        "/probe",
        "target=example.com",
        headers={"HTTP_X_PROMETHEUS_SCRAPE_TIMEOUT_SECONDS": "5"},
    )
    assert h.calls[0][1] == pytest.approx(20.0)


def test_responses_forbid_content_sniffing(h):
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/probe", "QUERY_STRING": "target=<b>"}
    headers = {}
    h.app(environ, lambda s, hs: headers.update(hs))
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Type"] == "text/plain; charset=utf-8"


@pytest.mark.parametrize(
    "header, expected",
    [(None, 20.0), ("30", 20.0), ("5", 4.5), ("0.5", 1.0), ("junk", 20.0)],
)
def test_probe_timeout(header, expected):
    environ = {"HTTP_X_PROMETHEUS_SCRAPE_TIMEOUT_SECONDS": header} if header else {}
    assert probe_timeout(environ, Config()) == pytest.approx(expected)


def test_health_and_unknown_paths(h):
    assert h.get("/-/healthy")[0] == 200
    assert h.get("/")[0] == 200
    assert h.get("/nope")[0] == 404
