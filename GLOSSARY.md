# Domain Expiry

A Prometheus exporter that reports when domain registrations expire, so renewals are never missed.

## Language

**Domain**:
A registrable domain name (e.g. `example.com`, `example.co.uk`): the unit a registrant holds at a registry. Hostnames below it (`www.example.com`) are not Domains.
_Avoid_: Hostname, subdomain, site, zone

**Registered**:
A Domain is Registered when its registry holds a record for it. A Domain that lapsed and was deleted is not Registered and has no Expiry.
_Avoid_: Active, exists, live

**Expiry**:
The moment a Domain's registration lapses at its registry unless renewed, as published by the registry.
_Avoid_: Expiration, expiry date, renewal date, TLS/certificate expiry

**Status**:
A registry-assigned status code on a Domain (e.g. client hold, redemption period, pending delete). A Domain can carry several at once.
_Avoid_: State, flag, EPP code

**Probe**:
A single on-demand lookup of one Domain's Expiry, requested by Prometheus for that Domain.
_Avoid_: Check, scan, query
