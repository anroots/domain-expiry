# WHOIS via python-whois, not RDAP

Expiry data comes from WHOIS (port 43), parsed by the `python-whois` library, for every TLD. RDAP would give structured data, but the required TLDs `.ee` and `.eu` have no RDAP service, and running two lookup paths isn't worth it for three TLDs. We accept that WHOIS output is free text and differs per registry: each supported TLD depends on a python-whois parser, and a TLD without one is unsupported.

## Consequences

- EURid's public WHOIS publishes neither an Expiry nor a Status (confirmed against whois.eurid.eu on 2026-11-16), so `.eu` Probes report only whether the Domain is Registered, with no Status and no Expiry. Getting a real `.eu` Expiry would need a separate source, such as a registrar API.
- python-whois is blocking. Cache misses are looked up one at a time on a single background worker, so a slow registry delays the lookups queued behind it. HTTP requests are served on their own threads, so health checks and `/metrics` still answer meanwhile (an earlier fully single-threaded server could be frozen by one idle connection). Each lookup has one overall deadline (20s by default) covering every WHOIS server it contacts.
