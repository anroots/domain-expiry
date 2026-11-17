"""WSGI app and threaded HTTP server: /probe, /metrics and health endpoints."""

import logging
from html import escape
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, CollectorRegistry, generate_latest

from . import __version__
from .config import Config
from .domains import InvalidTarget, parse_domain
from .probe import Prober

log = logging.getLogger(__name__)

TIMEOUT_HEADER = "HTTP_X_PROMETHEUS_SCRAPE_TIMEOUT_SECONDS"
MIN_TIMEOUT_SECONDS = 1.0
CLIENT_TIMEOUT_SECONDS = 10

LANDING_PAGE = """<!doctype html>
<html><head><title>Domain Expiry Exporter</title></head>
<body>
<h1>Domain Expiry Exporter {version}</h1>
<form action="/probe"><label>Domain <input name="target" placeholder="eesti.ee"></label>
<button>Probe</button></form>
<p><a href="/metrics">Exporter metrics</a></p>
</body></html>
"""


def probe_timeout(environ: dict, config: Config) -> float:
    """The lookup budget: Prometheus's scrape timeout minus an offset, capped by config."""
    timeout = config.lookup_timeout_seconds
    raw = environ.get(TIMEOUT_HEADER)
    if raw:
        try:
            timeout = min(timeout, float(raw) - config.timeout_offset_seconds)
        except ValueError:
            log.debug("ignoring invalid scrape timeout header %r", raw)
    return max(timeout, MIN_TIMEOUT_SECONDS)


def make_app(prober: Prober, config: Config, registry: CollectorRegistry = REGISTRY):
    def app(environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET")
        if method not in ("GET", "HEAD"):
            return _respond(start_response, "405 Method Not Allowed", b"method not allowed\n")

        if path == "/probe":
            query = parse_qs(environ.get("QUERY_STRING", ""))
            try:
                domain = parse_domain((query.get("target") or [None])[0])
            except InvalidTarget as e:
                return _respond(start_response, "400 Bad Request", f"{e}\n".encode())
            body = prober.probe(domain, probe_timeout(environ, config))
            return _respond(start_response, "200 OK", body, CONTENT_TYPE_LATEST)

        if path == "/metrics":
            return _respond(
                start_response, "200 OK", generate_latest(registry), CONTENT_TYPE_LATEST
            )

        if path in ("/-/healthy", "/-/ready"):
            return _respond(start_response, "200 OK", b"OK\n")

        if path == "/":
            page = LANDING_PAGE.format(version=escape(__version__)).encode()
            return _respond(start_response, "200 OK", page, "text/html; charset=utf-8")

        return _respond(start_response, "404 Not Found", b"not found\n")

    return app


def _respond(
    start_response, status: str, body: bytes, content_type: str = "text/plain; charset=utf-8"
):
    start_response(
        status,
        [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("X-Content-Type-Options", "nosniff"),
        ],
    )
    return [body]


class _QuietHandler(WSGIRequestHandler):
    # Socket timeout per connection: a client that connects and goes quiet is
    # dropped instead of holding its thread forever.
    timeout = CLIENT_TIMEOUT_SECONDS

    def log_message(self, format, *args):  # noqa: A002 - signature from BaseHTTPRequestHandler
        log.debug("%s %s", self.address_string(), format % args)


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """One thread per connection, so health checks and /metrics answer while a
    Probe waits on WHOIS. Lookups themselves still run one at a time (Prober)."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        # Clients that time out or hang up are routine; don't dump tracebacks.
        log.debug("connection from %s dropped", client_address[0], exc_info=True)


def make_http_server(app, config: Config) -> WSGIServer:
    return make_server(
        config.listen_address,
        config.port,
        app,
        server_class=_ThreadingWSGIServer,
        handler_class=_QuietHandler,
    )


def serve(app, config: Config) -> None:
    with make_http_server(app, config) as server:
        log.info("listening on %s:%d", config.listen_address, config.port)
        server.serve_forever()
