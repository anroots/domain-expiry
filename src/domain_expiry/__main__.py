import contextlib
import logging
import signal
import sys

from prometheus_client import REGISTRY, disable_created_metrics

from .app import make_app, serve
from .cache import ResultCache
from .config import Config
from .probe import Prober, SelfMetrics


def main() -> None:
    try:
        config = Config.from_env()
    except ValueError as e:
        sys.exit(f"configuration error: {e}")

    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    disable_created_metrics()
    cache = ResultCache(
        success_ttl=config.cache_ttl_seconds,
        failure_ttl=config.failure_ttl_seconds,
        max_entries=config.cache_max_entries,
    )
    prober = Prober(cache, SelfMetrics(REGISTRY), lookup_timeout=config.lookup_timeout_seconds)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        with contextlib.suppress(KeyboardInterrupt):
            serve(make_app(prober, config), config)
    finally:
        prober.close()


if __name__ == "__main__":
    main()
