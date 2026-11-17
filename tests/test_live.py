"""Real WHOIS lookups, run weekly in CI to catch registry format changes.

Run locally with: pytest -m live
"""

from datetime import UTC, datetime

import pytest

from domain_expiry.lookup import Outcome, lookup

pytestmark = pytest.mark.live

NOW = datetime.now(UTC)


@pytest.mark.parametrize("domain", ["example.com", "internet.ee"])
def test_expiry_is_published(domain):
    r = lookup(domain, timeout=20)
    assert r.outcome is Outcome.OK, r.detail
    assert r.registered
    assert r.expiry is not None and r.expiry > NOW
    assert r.statuses


def test_eu_is_registered_without_expiry():
    r = lookup("eurid.eu", timeout=20)
    assert r.outcome is Outcome.OK, r.detail
    assert r.registered
    assert r.expiry is None


@pytest.mark.parametrize("tld", ["com", "ee", "eu"])
def test_unregistered_domain_is_not_found(tld):
    r = lookup(f"this-domain-should-not-exist-7f3k2q9.{tld}", timeout=20)
    assert r.outcome is Outcome.NOT_FOUND, r.detail
