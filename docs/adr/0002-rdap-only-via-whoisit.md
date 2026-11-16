---
status: superseded by ADR-0003
---

# RDAP only, via whoisit, with no WHOIS fallback

Expiry data was to come only from RDAP, using the `whoisit` library, with no WHOIS fallback because WHOIS output is free text that differs by registry and breaks easily.

Superseded: `.ee` and `.eu` are required TLDs, and neither has an RDAP service (both are missing from the IANA bootstrap and from whoisit's overrides as of 2026-11). See ADR-0003.
