"""WHOIS lookups via python-whois, turned into a LookupResult (see ADR-0003)."""

import enum
import logging
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from whois.exceptions import (
    WhoisDomainNotFoundError,
    WhoisError,
    WhoisQuotaExceededError,
)
from whois.parser import WhoisEntry
from whois.whois import NICClient

from .domains import tld_of

log = logging.getLogger(__name__)

# TLDs whose registry does not publish an Expiry over public WHOIS. For these a
# missing expiration date is expected; for every other TLD it is a failure.
NO_EXPIRY_TLDS: frozenset[str] = frozenset({"eu"})

# Registries whose "not found" reply python-whois does not recognise.
# python-whois 0.9.6 only matches .ee when the whole reply is exactly
# "Domain not found", but whois.tld.ee adds a banner around it.
_NOT_FOUND_PATTERNS: dict[str, re.Pattern[str]] = {
    "ee": re.compile(r"^Domain not found\s*$", re.M),
}


class Outcome(enum.StrEnum):
    OK = "ok"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    NO_EXPIRY = "no_expiry"
    PARSE_ERROR = "parse_error"
    ERROR = "error"


@dataclass(frozen=True)
class LookupResult:
    """What a single WHOIS lookup established about a Domain."""

    domain: str
    outcome: Outcome
    registered: bool = False
    expiry: datetime | None = None
    statuses: frozenset[str] = field(default_factory=frozenset)
    detail: str = ""

    @property
    def success(self) -> bool:
        return self.outcome in (Outcome.OK, Outcome.NOT_FOUND)


WhoisFetcher = Callable[[str, float], str]


class _DeadlineSocket(socket.socket):
    """A TCP socket whose every operation is bounded by one shared deadline.

    python-whois applies its timeout to each recv, and gives each server it
    contacts (IANA, registry, registrar referral) a fresh one. This caps the
    whole lookup instead, so a slow or dripping server can't stretch it.
    """

    def __init__(self, deadline: float) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self._deadline = deadline

    def _remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("WHOIS lookup exceeded its deadline")
        return remaining

    def settimeout(self, value: float | None) -> None:
        super().settimeout(self._remaining() if value is None else min(value, self._remaining()))

    def connect(self, address) -> None:
        super().settimeout(self._remaining())
        super().connect(address)

    def send(self, data, flags: int = 0) -> int:
        super().settimeout(self._remaining())
        return super().send(data, flags)

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        super().settimeout(self._remaining())
        return super().recv(bufsize, flags)


class _DeadlineClient(NICClient):
    def __init__(self, deadline: float) -> None:
        super().__init__()
        self._deadline = deadline

    def get_socket(self) -> socket.socket:  # replaces a staticmethod; SOCKS proxies unsupported
        return _DeadlineSocket(self._deadline)


def fetch_whois(domain: str, timeout: float) -> str:
    """Raw WHOIS text for a Domain, using python-whois's port-43 client.

    `timeout` is the budget for the whole lookup, referrals included.
    """
    client = _DeadlineClient(time.monotonic() + timeout)
    return client.whois_lookup(
        None, domain, 0, quiet=True, ignore_socket_errors=False, timeout=timeout
    )


def lookup(domain: str, timeout: float, fetch: WhoisFetcher = fetch_whois) -> LookupResult:
    try:
        text = fetch(domain, timeout)
    except TimeoutError as e:
        return LookupResult(domain, Outcome.TIMEOUT, detail=str(e) or "timed out")
    except OSError as e:
        return LookupResult(domain, Outcome.ERROR, detail=f"network error: {e}")
    return parse(domain, text)


def parse(domain: str, text: str) -> LookupResult:
    """Interpret raw WHOIS text for a Domain."""
    tld = tld_of(domain)
    if not text or not text.strip():
        return LookupResult(domain, Outcome.ERROR, detail="empty WHOIS response")

    pattern = _NOT_FOUND_PATTERNS.get(tld)
    if pattern and pattern.search(text):
        return LookupResult(domain, Outcome.NOT_FOUND)

    try:
        entry = WhoisEntry.load(domain, text)
    except WhoisDomainNotFoundError:
        return LookupResult(domain, Outcome.NOT_FOUND)
    except WhoisQuotaExceededError as e:
        return LookupResult(domain, Outcome.RATE_LIMITED, detail=_first_line(str(e)))
    except WhoisError as e:
        return LookupResult(domain, Outcome.PARSE_ERROR, detail=_first_line(str(e)))

    # A reply that names no domain is not proof that the Domain is gone: it may be
    # a rate-limit page or a format change. Never report "not Registered" from it.
    if not entry.get("domain_name"):
        return LookupResult(domain, Outcome.PARSE_ERROR, detail="WHOIS reply has no domain name")

    statuses = normalize_statuses(entry.get("status"))
    expiry = _earliest(entry.get("expiration_date"))
    if expiry is None and tld not in NO_EXPIRY_TLDS:
        return LookupResult(
            domain,
            Outcome.NO_EXPIRY,
            registered=True,
            statuses=statuses,
            detail="WHOIS reply has no expiration date",
        )

    return LookupResult(domain, Outcome.OK, registered=True, expiry=expiry, statuses=statuses)


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_WORD = re.compile(r"[^a-z0-9]+")


def normalize_status(raw: str) -> str | None:
    """The leading EPP code of a WHOIS status, in snake_case.

    'clientTransferProhibited https://icann.org/epp#...' -> 'client_transfer_prohibited'
    'ok (paid and in zone)' -> 'ok'
    'client hold' -> 'client_hold'
    """
    text = raw.split("(", 1)[0]
    text = re.sub(r"\S+://\S+", "", text).strip()
    if not text:
        return None
    text = _CAMEL_BOUNDARY.sub("_", text).lower()
    code = _NON_WORD.sub("_", text).strip("_")
    return code or None


def normalize_statuses(raw: str | list[str] | None) -> frozenset[str]:
    if not raw:
        return frozenset()
    values = [raw] if isinstance(raw, str) else raw
    return frozenset(code for v in values if (code := normalize_status(str(v))))


def _earliest(value: datetime | str | list | None) -> datetime | None:
    """python-whois yields a datetime, a list of them, or unparsed strings."""
    if value is None:
        return None
    values = value if isinstance(value, list) else [value]
    dates = [v if v.tzinfo else v.replace(tzinfo=UTC) for v in values if isinstance(v, datetime)]
    # Registry and registrar dates can disagree; the earliest is the safe one to alert on.
    return min(dates) if dates else None


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""
