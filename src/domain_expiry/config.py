"""Settings, read from DOMAIN_EXPIRY_* environment variables."""

import os
from collections.abc import Mapping
from dataclasses import dataclass

PREFIX = "DOMAIN_EXPIRY_"


@dataclass(frozen=True)
class Config:
    listen_address: str = "0.0.0.0"
    port: int = 9019
    cache_ttl_seconds: float = 12 * 3600
    failure_ttl_seconds: float = 15 * 60
    cache_max_entries: int = 10_000
    lookup_timeout_seconds: float = 20.0
    timeout_offset_seconds: float = 0.5
    log_level: str = "INFO"

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Config":
        def get(name: str, cast, default):
            raw = env.get(PREFIX + name)
            if raw is None or raw == "":
                return default
            try:
                return cast(raw)
            except ValueError:
                raise ValueError(f"{PREFIX}{name}={raw!r} is not a valid {cast.__name__}") from None

        d = cls()
        cfg = cls(
            listen_address=get("LISTEN_ADDRESS", str, d.listen_address),
            port=get("PORT", int, d.port),
            cache_ttl_seconds=get("CACHE_TTL_SECONDS", float, d.cache_ttl_seconds),
            failure_ttl_seconds=get("FAILURE_TTL_SECONDS", float, d.failure_ttl_seconds),
            cache_max_entries=get("CACHE_MAX_ENTRIES", int, d.cache_max_entries),
            lookup_timeout_seconds=get("LOOKUP_TIMEOUT_SECONDS", float, d.lookup_timeout_seconds),
            timeout_offset_seconds=get("TIMEOUT_OFFSET_SECONDS", float, d.timeout_offset_seconds),
            log_level=get("LOG_LEVEL", str, d.log_level).upper(),
        )
        if cfg.cache_max_entries < 1:
            raise ValueError(f"{PREFIX}CACHE_MAX_ENTRIES must be at least 1")
        if cfg.lookup_timeout_seconds <= 0:
            raise ValueError(f"{PREFIX}LOOKUP_TIMEOUT_SECONDS must be positive")
        return cfg
