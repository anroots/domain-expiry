# WHOIS via python-whois, not RDAP

Expiry data comes from WHOIS (port 43), parsed by the `python-whois` library, for every TLD. RDAP would give structured data, but the required TLDs `.ee` and `.eu` have no RDAP service, and running two lookup paths isn't worth it for three TLDs. We accept that WHOIS output is free text and differs per registry: each supported TLD depends on a python-whois parser, and a TLD without one is unsupported.

## Consequences

- EURid's public WHOIS appears not to publish an Expiry (python-whois's `.eu` parser has no expiration field). python-whois's `.eu` parser has no status field either, so `.eu` Probes report only whether the Domain is Registered, with no Status and no Expiry. Getting a real `.eu` Expiry would need a separate source, such as a registrar API.
- python-whois is blocking, so lookups must run off the request path.
