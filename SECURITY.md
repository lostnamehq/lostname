# Security

Lostname is pre-release: the model, the lab and the first commands work, and there is no release yet.

## Reporting a weakness
Report privately, never in a public issue or pull request, through a private security advisory on this repository:
https://github.com/lostnamehq/lostname/security/advisories/new

Include what you found, how to reproduce it, and the impact as you see it. We will agree a disclosure timeline with you before anything is made public, and credit you if you want it.

### Response targets
- We acknowledge a report within 5 working days.
- For a confirmed issue we give you a fix or a plan with dates within 30 days.

These are targets for a small project, not guarantees; if we need longer we say so and why.

## Supported versions
| Version | Supported |
|---|---|
| none released | the `main` branch only, until 0.1.0 |

## What Lostname is designed to guarantee
These are the properties a vulnerability report would most likely concern:
- **No false all-clear.** Comparisons and checks report "no verdict" (exit code 2) when an answer is not authoritative or the path is intercepted.
- **No credential access.** Lostname never reads the credentials file; it passes its path to DNSControl.
- **No writes without consent.** Read-only by default. The only write path (`drill --apply`, a later release) requires a typed confirmation and a fresh lint without blockers.
- **No contact beyond the owner's zone.** Network traffic goes only to DNSControl's provider APIs and to the authoritative servers of the zone being checked and its parent.
- **A verified dependency.** DNSControl is pinned and checksum-verified on every call.
