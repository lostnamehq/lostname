# References

Every standard Lostname implements or relies on, and every project it builds on. Rules cite the section where they use it.

## Normative: DNS
- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034): Domain names, concepts and facilities (CNAME rules, 3.6.2; zone cuts and glue, 4.2.1).
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035): Domain names, implementation and specification (zone file format).
- [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181): Clarifications to the DNS specification (10.1 CNAME with other data; 10.3 MX and NS must not point to an alias).
- [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308): Negative caching (the negative TTL is the minimum of SOA MINIMUM and the SOA TTL, section 5).
- [RFC 4343](https://www.rfc-editor.org/rfc/rfc4343): Case insensitivity of ASCII letters in DNS labels.
- [RFC 8020](https://www.rfc-editor.org/rfc/rfc8020): NXDOMAIN means nothing underneath (empty non-terminals answer NODATA, 3.1).
- [RFC 8482](https://www.rfc-editor.org/rfc/rfc8482): Minimal responses to ANY (why Lostname never queries ANY).
- [RFC 8767](https://www.rfc-editor.org/rfc/rfc8767): Serving stale data (resolver behaviour the simulator models).
- [RFC 9471](https://www.rfc-editor.org/rfc/rfc9471): Glue records in referral responses (3.1).
- [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460): SVCB and HTTPS records (AliasMode, 2.4.1).
- [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505): Null MX (the `retire` profile).

## Normative: DNSSEC
- [RFC 6781](https://www.rfc-editor.org/rfc/rfc6781): DNSSEC operational practices v2 (4.3.5 changing DNS operators, cooperating 4.3.5.1 and non-cooperating 4.3.5.2).
- [RFC 7583](https://www.rfc-editor.org/rfc/rfc7583): DNSSEC key rollover timing (waiting logic only; it covers one operator).
- [RFC 7344](https://www.rfc-editor.org/rfc/rfc7344) and [RFC 8078](https://www.rfc-editor.org/rfc/rfc8078): CDS and CDNSKEY, and the delete signal `CDS 0 0 0 0` (RFC 8078 section 4).
- [RFC 7477](https://www.rfc-editor.org/rfc/rfc7477): CSYNC, child-to-parent synchronisation.
- [RFC 8624](https://www.rfc-editor.org/rfc/rfc8624): DNSSEC algorithm implementation requirements and usage guidance (lint rule L-21).
- [RFC 8198](https://www.rfc-editor.org/rfc/rfc8198): Aggressive use of DNSSEC-validated cache (modelled by the simulator).
- [RFC 8901](https://www.rfc-editor.org/rfc/rfc8901): Multi-signer DNSSEC models (model 2: 2.1.2 and 3; common algorithm: 4; NSEC and NSEC3: 5; CDS: 8-9).
- [RFC 9975](https://www.rfc-editor.org/rfc/rfc9975): Clarifications on CDS, CDNSKEY and CSYNC consistency.
- [draft-ietf-dnsop-dnssec-automation](https://datatracker.ietf.org/doc/draft-ietf-dnsop-dnssec-automation/): Multi-signer DNSSEC automation (the procedure behind transition model T2).

## Normative: mail and certificates
- [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989): DMARC, which obsoletes RFC 7489; [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990) aggregate reporting, [RFC 9991](https://www.rfc-editor.org/rfc/rfc9991) failure reporting.
- [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208): SPF.
- [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376): DKIM.
- [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461): MTA-STS. [RFC 8460](https://www.rfc-editor.org/rfc/rfc8460): TLS-RPT.
- [RFC 7672](https://www.rfc-editor.org/rfc/rfc7672): DANE for SMTP.
- [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659): CAA (critical flag, 4.1). [RFC 8657](https://www.rfc-editor.org/rfc/rfc8657): CAA `accounturi` and `validationmethods`.
- [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) and [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761): reserved names (the only names allowed in test fixtures).

## Informative
- [draft-johani-dnsop-multi-provider-requirements](https://github.com/johanix/draft-johani-dnsop-multi-provider-requirements): baseline requirements for multi-provider DNS.
- V. Ramasubramanian and E. G. Sirer, "Perils of Transitive Trust in the Domain Name System" (the dependency-graph idea behind the shared-fate check).

## Software Lostname stands on
| Project | Licence | How Lostname uses it |
|---|---|---|
| [DNSControl](https://github.com/DNSControl/dnscontrol) | MIT | export (`get-zones`), configuration as JSON (`print-ir`), preview and push; called as the official binary |
| [miekg/dns](https://github.com/miekg/dns) | BSD-3 | DNS queries and DNSSEC validation in Go |
| [OctoDNS](https://github.com/octodns/octodns) | MIT | an independent second comparison in tests |
| [GRoot and Ferret](https://github.com/dns-groot) | MIT | formal zone verification and differential testing: the foundation of full-coverage parity |
| [IANA DNSSEC Rollercoaster](https://github.com/iana-org/dnssec-rollercoaster) | BSD-3 | test bed for the rehearsal |
| [DNSViz](https://github.com/dnsviz/dnsviz) | GPL-2.0 | pre-deployment validation per plan step, run as a separate program |
| [ANSSI transdep](https://github.com/ANSSI-FR/transdep) | BSD-2 | DNS dependency-graph single points of failure, the base for the shared-fate check |
| [acme-dns](https://github.com/acme-dns/acme-dns) | MIT | what certificate continuity recommends for provider-independent DNS-01 |
| [dnsglobe](https://github.com/514-labs/dnsglobe) | MIT | neighbour for the cutover observer |
| [Shadow](https://github.com/shadow/shadow) | BSD-3 (various) | candidate for running real resolvers in virtual time during rehearsal |
| [JetBrains Mono](https://github.com/JetBrains/JetBrainsMono) | OFL-1.1 | the wordmark typeface (`brand/Fonts/OFL.txt`) |
