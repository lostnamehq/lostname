# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]
The first release: it tells you, before you need it, what would break if you moved your DNS today.
- `lint` checks a zone file or DNSControl config offline, and with `--to` what will not survive a move to a provider.
- `parity` compares what two providers serve, authoritative and fail-closed, DNSSEC included: signatures, the chain
  from the parent's DS, NSEC and NSEC3 denial (opt-out included), CDS across providers, wildcards, shared fate.
- `mail` reads the zone's mail records (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, TLSA) offline.
- `watch` runs the checks on a schedule into your own stack: OpenMetrics and OTLP metrics, CloudEvents, traces, a
  modelled exit-readiness SLO, catalog zones and a keyed-hash zone label for shared stacks.
- `--evidence` bundles, JSON Schemas for every output, SARIF, CI templates, reproducible and signed releases.

### Added
- Model drafts 1 to 4a (`docs/model.md`) and prior art (`docs/prior-art.md`).
- M0 falsifier lab and findings (`m0/`).
- Roadmap, contributing guide, security policy, references.
- Brand: mark, badge, wordmark, palette and icons (`brand/`).
- Formal model of DNSSEC transitions (`internal/sim/`): plans as data, an explorer of reachable resolver states, and the minimal safe waits.
- `lostname lint` (first slice):
  - reads RFC 1035 zone files into a neutral zone model (`internal/zone/`);
  - zone-only rules: L-00 (is it a zone at all), L-07, L-08, L-09, L-13, L-14, L-15, L-18, L-21;
  - deterministic JSON (`--json`, schema `lostname.lint/v0`), `--strict`, exit codes 0/1/2/3;
  - no network use, enforced by a test.
- `lostname fetch` (AXFR, fail-closed):
  - transfers a zone and writes it as a zone file, so `lint` stays offline;
  - TSIG from a key file, never on the command line;
  - the transfer must begin and end with the same SOA;
  - without TSIG, an interception probe runs first, and an intercepted path gives "no verdict" (exit 2).
- `lostname parity` (core, fail-closed):
  - asks every address of each provider over UDP (EDNS 1232, DO) and TCP, and requires authority (AA) or a referral at a zone cut;
  - covers every record, a name that must not exist and every empty non-terminal;
  - compares RRsets and TTLs, with SOA timers as notes, SOA MINIMUM as a risk, and apex NS by transition model;
  - compares each provider with the zone file too, so providers that agree on wrong data fail;
  - a difference fails, a missing authoritative answer gives no verdict, and an intercepted path gives no verdict before any question.

- `lint` rule L-21 (RFC 8624): DNSKEY algorithms that must not, or should not, be used for signing, and SHA-1 DS digests.
- `parity` reports serial drift between a provider's own servers (a secondary that is behind) as a risk.
- Configuration as code (`internal/config`, `lostname config`):
  - embedded defaults with a versioned schema;
  - a strict override file (`--config`): unknown keys and invalid values are errors;
  - no deployment setting is hardcoded any more.
- Red-team fixes in `parity`:
  - providers without addresses or with duplicate names are refused;
  - RRSIGs are no longer compared as data;
  - a wildcard zone no longer fails the NX probe;
  - an unknown verdict fails closed.
- `tools/check.py`: one check for people and CI (gofmt, vet on four targets, staticcheck, tests, fuzzing, govulncheck, the publication gate).
- `authtest`: an in-process authoritative server for tests, with faults (lame, not authoritative, RFC 8020 violation).
