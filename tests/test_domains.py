import pytest

from domain_expiry.domains import InvalidTarget, parse_domain


@pytest.mark.parametrize(
    "target, expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.com.", "example.com"),
        (" internet.ee ", "internet.ee"),
        ("eurid.eu", "eurid.eu"),
        ("example.co.uk", "example.co.uk"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_accepts_registrable_domains(target, expected):
    assert parse_domain(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        None,
        "",
        "   ",
        "www.example.com",  # subdomain
        "api.internet.ee",  # subdomain
        "com",  # public suffix
        "co.uk",  # public suffix
        "localhost",
        "1.2.3.4",
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "exa mple.com",
        "example..com",
    ],
)
def test_rejects_everything_else(target):
    with pytest.raises(InvalidTarget):
        parse_domain(target)


def test_private_suffixes_are_not_registries():
    # github.io is a private PSL entry; foo.github.io has no registration of its own.
    with pytest.raises(InvalidTarget, match="subdomain"):
        parse_domain("foo.github.io")


def test_subdomain_error_names_the_registrable_domain():
    with pytest.raises(InvalidTarget, match="'example.com'"):
        parse_domain("www.example.com")
