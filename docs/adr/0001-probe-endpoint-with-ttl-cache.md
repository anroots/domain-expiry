# Probe endpoint with a TTL cache, not a configured domain list

The exporter exposes a blackbox-style `/probe?target=<domain>` endpoint instead of reading a list of Domains from its own config file. The list of Domains lives in Prometheus (scrape config or a Prometheus Operator `Probe` resource), so adding a Domain never means redeploying the exporter. Registries rate-limit lookups hard and an Expiry rarely changes, so each Domain's lookup result is cached in memory (12h by default). A probe is therefore usually served from cache, not from a live lookup.

## Considered Options

- **Configured list with background refresh**: rejected because it duplicates target management that Prometheus already does.
- **Probe without a cache**: rejected because a short `scrape_interval` would hammer registries and get the exporter rate-limited.
