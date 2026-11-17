"""Validation of probe targets: only registrable Domains are accepted."""

from publicsuffixlist import PublicSuffixList

# ICANN section only: private suffixes such as github.io are not registries,
# so foo.github.io has no registration of its own to expire.
_PSL = PublicSuffixList(only_icann=True)


class InvalidTarget(ValueError):
    """The probe target is not a registrable Domain."""


def parse_domain(target: str | None) -> str:
    """Return the canonical (lowercase, IDNA-encoded) Domain, or raise InvalidTarget."""
    if not target or not target.strip():
        raise InvalidTarget("missing 'target' parameter")

    name = target.strip().rstrip(".").lower()
    if "://" in name or "/" in name or ":" in name or " " in name:
        raise InvalidTarget(f"{target!r} is not a domain name (no scheme, path or port allowed)")

    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise InvalidTarget(f"{target!r} is not a valid domain name: {e}") from None

    labels = name.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        raise InvalidTarget(f"{target!r} is not a registrable domain")
    if all(label.isdigit() for label in labels):
        raise InvalidTarget(f"{target!r} looks like an IP address, not a domain")

    registrable = _PSL.privatesuffix(name)
    if registrable is None:
        raise InvalidTarget(f"{target!r} is a public suffix, not a registrable domain")
    if registrable != name:
        raise InvalidTarget(
            f"{target!r} is a subdomain; probe its registrable domain {registrable!r} instead"
        )
    return name


def tld_of(domain: str) -> str:
    """The top-level label of a Domain, e.g. 'eu' for 'eurid.eu'."""
    return domain.rsplit(".", 1)[-1]
