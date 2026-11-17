from datetime import UTC, datetime

import pytest

from domain_expiry.lookup import (
    Outcome,
    lookup,
    normalize_status,
    parse,
)


def test_com_registered(whois_text):
    r = parse("example.com", whois_text("com_registered"))
    assert r.outcome is Outcome.OK
    assert r.registered
    assert r.expiry == datetime(2027, 8, 13, 4, 0, tzinfo=UTC)
    assert r.statuses == {
        "client_delete_prohibited",
        "client_transfer_prohibited",
        "client_update_prohibited",
    }


def test_com_held(whois_text):
    r = parse("example.com", whois_text("com_held"))
    assert r.outcome is Outcome.OK
    assert {"client_hold", "redemption_period"} <= r.statuses


def test_com_not_found(whois_text):
    r = parse("this-domain-should-not-exist-7f3k2q9.com", whois_text("com_not_found"))
    assert r.outcome is Outcome.NOT_FOUND
    assert r.success and not r.registered
    assert r.expiry is None


def test_ee_registered(whois_text):
    r = parse("internet.ee", whois_text("ee_registered"))
    assert r.outcome is Outcome.OK
    assert r.registered
    assert r.expiry == datetime(2030, 2, 5, tzinfo=UTC)
    assert r.statuses == {"ok"}


def test_ee_not_found_despite_python_whois_missing_it(whois_text):
    # python-whois 0.9.6 only recognises a reply that is exactly "Domain not found".
    r = parse("this-domain-should-not-exist-7f3k2q9.ee", whois_text("ee_not_found"))
    assert r.outcome is Outcome.NOT_FOUND
    assert not r.registered


def test_eu_registered_has_no_expiry_by_design(whois_text):
    r = parse("eurid.eu", whois_text("eu_registered"))
    assert r.outcome is Outcome.OK
    assert r.registered
    assert r.expiry is None
    assert r.statuses == frozenset()


def test_eu_not_found(whois_text):
    r = parse("this-domain-should-not-exist-7f3k2q9.eu", whois_text("eu_not_found"))
    assert r.outcome is Outcome.NOT_FOUND


def test_missing_expiry_outside_no_expiry_tlds_fails(whois_text):
    text = "\n".join(
        line for line in whois_text("com_registered").splitlines() if "Expir" not in line
    )
    r = parse("example.com", text)
    assert r.outcome is Outcome.NO_EXPIRY
    assert not r.success


@pytest.mark.parametrize(
    "text",
    [
        "Query rate limit exceeded. Try again later.\n",
        "%% Server busy\n",
        "Some unexpected banner\nwithout any useful fields\n",
    ],
)
def test_unrecognised_replies_never_mean_not_registered(text):
    for domain in ("example.com", "internet.ee", "eurid.eu"):
        r = parse(domain, text)
        assert not r.success, domain
        assert r.outcome is not Outcome.NOT_FOUND


def test_empty_reply_is_an_error():
    assert parse("example.com", "").outcome is Outcome.ERROR


def test_timeout_is_reported():
    def slow(domain, timeout):
        raise TimeoutError("timed out")

    assert lookup("example.com", 1, fetch=slow).outcome is Outcome.TIMEOUT


def test_network_error_is_reported():
    def broken(domain, timeout):
        raise ConnectionRefusedError("refused")

    r = lookup("example.com", 1, fetch=broken)
    assert r.outcome is Outcome.ERROR
    assert "refused" in r.detail


def test_lookup_passes_domain_and_timeout(whois_text):
    seen = {}

    def fake(domain, timeout):
        seen.update(domain=domain, timeout=timeout)
        return whois_text("com_registered")

    assert lookup("example.com", 4.5, fetch=fake).outcome is Outcome.OK
    assert seen == {"domain": "example.com", "timeout": 4.5}


@pytest.mark.parametrize(
    "raw, code",
    [
        (
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "client_transfer_prohibited",
        ),
        ("ok (paid and in zone)", "ok"),
        ("client hold", "client_hold"),
        ("serverHold", "server_hold"),
        ("pendingDelete", "pending_delete"),
        ("OK", "ok"),
        ("https://icann.org/epp", None),
    ],
)
def test_normalize_status(raw, code):
    assert normalize_status(raw) == code


def test_whois_deadline_covers_the_whole_lookup(monkeypatch):
    """A server that drips bytes can't stretch a lookup past its budget."""
    import socket
    import threading
    import time

    from domain_expiry import lookup as lookup_mod

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    stop = threading.Event()

    def drip():
        conn, _ = listener.accept()
        with conn:
            while not stop.is_set():
                conn.sendall(b"x")
                time.sleep(0.1)

    threading.Thread(target=drip, daemon=True).start()
    real_connect = lookup_mod._DeadlineSocket.connect
    monkeypatch.setattr(
        lookup_mod._DeadlineSocket, "connect", lambda s, addr: real_connect(s, ("127.0.0.1", port))
    )
    monkeypatch.setattr(lookup_mod._DeadlineClient, "choose_server", lambda s, d: "whois.test")
    try:
        start = time.monotonic()
        result = lookup_mod.lookup("example.com", 0.5)
        assert result.outcome is Outcome.TIMEOUT
        assert time.monotonic() - start < 1.5
    finally:
        stop.set()
        listener.close()
