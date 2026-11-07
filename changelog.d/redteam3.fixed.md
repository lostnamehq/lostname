- Fixes from the third adversarial review (watch, lint and mail, parity):
  - `watch`: a new `LostnameWatchAbsent` alert fires when watch stops; an interception episode ends only on a clean
    probe; exit readiness uses parity under the exit's own model, and T0 is never ready on a signed zone; deliveries
    follow no redirects and never print an endpoint's password; OTLP log records carry `traceId` and `spanId`; the
    standby alert fires after two runs; the config refuses duplicate provider names and addresses without a port.
  - `mail` and `lint`: SPF accepts any unknown modifier, refuses a repeated `redirect` or `exp` and malformed
    `ip4`/`ip6`; DMARC follows RFC 9989 (a missing or invalid `p` is `p=none`; an invalid `sp` is reported); DKIM
    needs `v=DKIM1` first when present, reads tag names case-sensitively and skips names that are not selectors;
    findings never quote record text; SMTP TLSA (L-22, M-11) counts only at the MX hosts; the zone's own registered
    domain is never "the provider" (L-11, L-12); DNSControl record types must be plain type names.
  - `parity`: CDS and CDNSKEY are compared between every pair of providers, over UDP and TCP, with signatures
    checked, and must describe the same keys (`cds-cdnskey-differ`); a server that does not answer them is a gap;
    NSEC3 records count only in the zone's own chain; the interception probe counts any reply; shared fate also
    compares host names.
