import pytest

from domain_expiry.config import Config


def test_defaults():
    c = Config.from_env({})
    assert c.port == 9019
    assert c.cache_ttl_seconds == 43200
    assert c.failure_ttl_seconds == 900
    assert c.cache_max_entries == 10_000


def test_overrides():
    c = Config.from_env(
        {
            "DOMAIN_EXPIRY_PORT": "9999",
            "DOMAIN_EXPIRY_CACHE_TTL_SECONDS": "60",
            "DOMAIN_EXPIRY_LOG_LEVEL": "debug",
        }
    )
    assert (c.port, c.cache_ttl_seconds, c.log_level) == (9999, 60.0, "DEBUG")


@pytest.mark.parametrize(
    "env",
    [
        {"DOMAIN_EXPIRY_PORT": "abc"},
        {"DOMAIN_EXPIRY_CACHE_MAX_ENTRIES": "0"},
        {"DOMAIN_EXPIRY_LOOKUP_TIMEOUT_SECONDS": "-1"},
    ],
)
def test_invalid_values_are_rejected(env):
    with pytest.raises(ValueError, match="DOMAIN_EXPIRY_"):
        Config.from_env(env)
