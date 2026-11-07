# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-07

The first release: it tells you, before you need it, what would break if you moved your DNS today.
- `lint` checks a zone file or DNSControl config offline, and with `--to` what will not survive a move to a provider.
- `parity` compares what two providers serve, authoritative and fail-closed, DNSSEC included: signatures, the chain
  from the parent's DS, NSEC and NSEC3 denial (opt-out included), CDS across providers, wildcards, shared fate.
- `mail` reads the zone's mail records (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, TLSA) offline.
- `watch` runs the checks on a schedule into your own stack: OpenMetrics and OTLP metrics, CloudEvents, traces, a
  modelled exit-readiness SLO, catalog zones and a keyed-hash zone label for shared stacks.
- `--evidence` bundles, JSON Schemas for every output, SARIF, CI templates, reproducible and signed releases.

### Upgrading
- First release. From v0.1.0 the command-line flags, exit codes, JSON report schemas (`lostname.*/v0`), configuration
  keys, metric names and labels, event types and trace attributes follow semantic versioning: a rename or removal
  is a breaking change and waits for a new major version (or, before 1.0, a new minor version with an entry here).
- The evidence behind this release is the test suite, a lab conformance run (OpenTelemetry Collector with Prometheus
  and with VictoriaMetrics) and in-process test servers. A parity run against real providers comes in v0.1.1. The
  exit-readiness SLO is modelled (`basis="modelled"`), not measured.

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
- `lint --baseline REPORT` compares with an earlier `lint --json` report of the same zone and reports, and judges, only
  what got worse: new findings and raised severities. The summary counts what was fixed. A report of another zone,
  or one that was itself made against a baseline, is refused.
- CI templates in `deploy/ci/` run `lostname parity` against a standby provider on a schedule: a GitLab CI job
  and a GitHub Actions workflow (findings to code scanning). Both run the release image pinned by digest, keep the
  SARIF report and the evidence bundle, and fail on findings and on a missing verdict.
- The observability conformance fixture (`tools/conformance/`) and its first run: the OpenTelemetry Collector with
  Prometheus and with VictoriaMetrics answered all 18 queries alike, the blind zone's result series absent.
- `lint --evidence DIR` and `parity --evidence DIR` write an evidence bundle: the inputs, the report, for parity every
  DNS exchange per server and transport (what was asked, of whom, over which path, with which answer and when),
  `versions.json`, and a `MANIFEST.sha256` over all of it. The bundle appears whole or not at all, never overwrites
  an earlier one, and holds no credentials; it does show the zone's internal names.
- The interception probe also covers IPv6 (`probe.canary_v6`, by default `[2001:db8::53]:53`): `parity` and `fetch`
  probe every address family their servers use, so a middlebox on the IPv6 path gives no verdict too.
- IPv6 is now tested, not only accepted: parity over the IPv6 loopback (alone, next to IPv4, with a difference, and a
  signed zone with its DS chain), a TSIG transfer over IPv6, and address parsing for IPv6 with and without a port.
- L-04: with `--dnscontrol-ir`, lint checks the config's DNSSEC intent. A zone that is signed now (`--current FILE`,
  the zone as served, for example from `fetch`) without `AUTODNSSEC_ON` in the config is a blocker; so is
  `AUTODNSSEC_ON` for a target that cannot sign through DNSControl (HETZNER_V2, SCALEWAY and OVH, per the matrix).
- `lint` rule L-10: provider metadata on a record (DNSControl's `meta`, such as `CF_PROXY_ON` or a geo key) is a risk:
  a zone transfer or another provider does not carry it. The DNSControl reader keeps the metadata key names
  (`meta` in the zone) and refuses a key that is not a plain name.
- `lint` rules L-11 (a sub-delegation to the current provider's servers is lame after the exit; blocker), L-12
  (a CNAME, MX, SRV, DNAME, SVCB or HTTPS target under the current provider's own domain; risk), L-16 (an answer
  larger than 1232 bytes with its signatures truncates over UDP; note) and L-20 (apex nameservers that share an
  address, a /24 or a /48 prefix; risk). Provider domains use the public suffix list.
- `parity` reports shared fate between providers (`shared-fate`, risk): servers of two providers that share an
  address, a /24 or a /48 prefix. IPv4 and IPv6 alike; AS numbers are not checked yet.
- `lint --to PROVIDER` says what will not survive a move to that provider: record types it does not serve (L-02),
  ALIAS records (L-03), and a missing SOA where the target needs one (L-01). The capabilities are DNSControl's provider
  matrix, pinned at v5.7.0. `lint --dnscontrol-ir FILE` reads the output of `dnscontrol print-ir` instead of a zone
  file; Lostname never runs DNSControl itself, because print-ir reads the credentials file.
- `lostname mail` reads the zone's mail records offline: SPF, DMARC, DKIM (only the selectors the zone publishes),
  MTA-STS, TLS-RPT, BIMI and DANE TLSA. It prints the posture and findings M-01 to M-11 (multiple or unparsable SPF
  and DMARC records, `+all`, `ptr`, `p=none`, broken DKIM keys, malformed MTA-STS and TLS-RPT records, TLSA usages not
  meant for SMTP), as JSON with a schema. Findings never quote record data.
- `lint` rule L-22: DANE TLSA on a mail host ties mail delivery to the DNSSEC handover (a note in a signed zone; a
  risk in an unsigned one, where the records do nothing).
- `parity` checks L-19 at the providers: different CDS or CDNSKEY sets between two providers, or between one
  provider's servers, fail (`cds-differs`): a parent that scans CDS installs one of them, and the zone is bogus at
  the other. A set at one provider only is a risk (`cds-one-sided`). Whether the parent scans is not known, so the
  check judges as if it does.
- `parity --parent ADDR[,ADDR]` checks the chain from the parent's DS RRset to every server's DNSKEY RRset: a served
  key must match a DS and sign the DNSKEY RRset validly. A parent without DS is a note (insecure delegation); a signed
  zone checked without `--parent` gives no verdict.
- `parity` checks authenticated denial: NSEC and NSEC3 records in a negative answer must be signed by the server's
  keys and prove the NODATA or NXDOMAIN answer, wildcard included. A signed zone answering without them fails. A
  provider denying with NSEC next to one with NSEC3 is a risk.
- `parity` runs within limits for real providers: `parity.deadline_seconds` (900) for the whole run,
  `parity.max_queries_per_server` (5000) and `parity.pace_milliseconds` (0). A question a limit stops is a gap, so the
  run ends without a verdict, never with a partial pass. A server that answered and then stops answering or refuses is
  labelled "possibly rate limited". The report counts the queries per server (`queries`).
- `parity` checks the no-DS proof in referrals to insecure delegations of a signed zone (RFC 4035 3.1.4.1,
  RFC 5155 7.2.7): an NSEC at the cut with NS and without DS and SOA, a matching NSEC3, or under NSEC3 opt-out the
  closest provable encloser and an opt-out NSEC3 covering the next closer name. A referral without it fails
  (`referral-denial-missing`); one whose records prove nothing fails as `denial-invalid`.
- `parity` validates DNSSEC signatures: every RRSIG a server returns must be inside its validity window, made by a key
  in that server's own DNSKEY RRset, and cryptographically valid. Where the zone file is signed, every answer must
  carry one. A valid signature that expires sooner than `parity.min_signature_life_seconds` (default 6 hours) is a
  risk. Not yet: the chain to the parent's DS and authenticated denial.
- `parity` checks answers expanded from a wildcard: they must carry a signed NSEC or NSEC3 proof that the queried name
  itself does not exist (`wildcard-proof-missing` otherwise). The test server now synthesises wildcard answers.
- `lostname doctor` checks that the machine, network path and configuration can give verdicts: the configuration,
  the IPv4 and IPv6 interception probes, the watched zone files and catalogs, the salt and state files.
- `watch` logs its loop with structured messages (slog, text on stderr): failed deliveries, the state file, rounds.
- Golden files pin the exact output of `config`, `lint` and `mail`; a mutation suite (`tools/mutate.py`) checks that
  the tests catch a broken rule, and runs before every release.
- The simulator advises on pre-staging the DNSKEY TTL: per exit model and registry lock, the exit time before and
  after lowering it, the wait the lowering costs, and whether the plan stays safe at the lower TTL.
- The release workflow can be run by hand as a dry run: tests, mutations, both builds, OpenVEX and the image build,
  without the tag check, signing, pushing or a release.
- `lostname.allowed_signers` holds the public key that signs release tags (SSH, ed25519). Verify a tag with
  `git -c gpg.ssh.allowedSignersFile=lostname.allowed_signers tag -v vX.Y.Z`.
- Release candidates: a tag `vX.Y.Z-rc.N` publishes a prerelease through the same workflow, with the coming
  release's notes.
- Release supply chain: `tools/build.py` builds every binary reproducibly (checked in CI and in the push gate), with
  a CycloneDX SBOM per binary and `SHA256SUMS`; the release workflow verifies the signed tag, builds twice and
  compares, adds an OpenVEX statement, signs the checksums with Sigstore (keyless), attests SLSA provenance, and
  publishes a multi-arch image (`ghcr.io/lostnamehq/lostname`, non-root, nothing written inside) signed and attested
  the same way. `docs/publishing.md` describes the release process.
- `lint --sarif` and `parity --sarif` print SARIF 2.1.0 for the code-scanning views of GitHub and GitLab. A parity
  run without a verdict is an unsuccessful invocation, with the gaps as notices. Results point at the zone file;
  line numbers follow when records carry them.
- JSON Schemas for `lint --json`, `parity --json` and the configuration, in `docs/schemas/`. Tests validate real
  output against them, and every parity finding kind is listed.
- The exit simulator reports how long after the last step caches can still hold an earlier step's NS, DS or DNSKEY
  (the drain time), and lists the resolver assumptions behind every verdict.
- The project site on lostname.be (GitHub Pages from `site/`): a one-page introduction, the `go-import` page for the
  module path, and `security.txt`; no cookies, nothing loaded from third parties.
- `lostname version` (also `--version`) prints the release and commit the binary was built from, read from Go's
  build information; `--json` follows `docs/schemas/version.schema.json`. `lostname help` (also `-h`, `--help`)
  prints the usage text and exits 0.
- The release workflow refuses a binary whose `version` does not name the tag being released.
- `lostname watch` runs `lint` and `parity` on the zones in the config's `watch` section every
  `watch.interval_seconds` and serves the results on `/metrics` (OpenMetrics, `watch.listen`, loopback by default).
  A check that ends without a verdict leaves its result series out: absent, never zero. `--once` runs one round,
  prints the metrics and exits with the worst verdict's code.
- `watch.catalogs` checks the members of catalog zones (RFC 9432), each like a listed zone with the catalog's
  providers, parent and exit objective; the catalog is read every round and has its own `catalog` check. A member
  without a verdict does not stop the others, and a listed zone keeps its own settings.
- `lostname watch` sends events (CloudEvents 1.0, JSON) when `watch.events` names a transport: `http` posts each
  event in structured mode to `watch.events_endpoint`, `otlp` sends them as OTLP logs. Events say when a verdict
  changes, when a finding opens or closes and when the network path is intercepted; they carry no record data, and
  a check without a verdict closes no finding. The source is `lostname/<watch.instance>`.
- The parity report names the probe address that answered and the protocols it answered over (`interception`).
- Exit readiness as an SLO: a watch zone with an `exit` block (`model`, `lock`, `target_seconds`) gets an `exit`
  check each round. The exit time is the simulator's (safe plan, registry-lock schedule, cache drain), with the
  zone's own DNSKEY TTL. New metrics `lostname_exit_time_seconds`, `lostname_exit_target_seconds` and the SLI
  `lostname_exit_ready`; alert rules on multi-window burn rates (`LostnameExitBudgetBurnFast`, `...Slow`).
- `watch` pushes the same metrics over OTLP/HTTP (JSON) when `watch.otlp_endpoint` is set, with the optional
  correlation attributes from `watch.resource`; a blind run sends no result data points.
- `watch` adds `lostname_dnssec_status` (secure, insecure, bogus, indeterminate, per provider) and
  `lostname_dnssec_signature_expiry_seconds`; `parity --json` reports each provider's earliest signature expiry.
- The alert rules ship as code in `deploy/alerts/lostname.rules.yaml`, each with severity, suggested autonomy, owner
  role and action.
- `watch.state_file` keeps the event tracker's state across restarts, so findings fixed while watch was down are
  closed; after its first round watch sends `be.lostname.watch.resync.v0` with every verdict and open finding.
- `lostname watch` sends each check run as an OpenTelemetry trace when `watch.traces` is on: a root span for the
  check and a span per DNS query (question, server, transport, response code; no answer data), to
  `watch.otlp_endpoint` at `/v1/traces`. Events carry the check's `traceparent`.
- `watch.zone_id.salt_file` switches on the keyed-hash zone label: labels, event subjects and spans carry
  HMAC-SHA-256(salt, zone) instead of the zone's name, and owner names become relative to the zone.

### Changed
- The exit-readiness series carry `basis="modelled"` and the contract says what the number rests on and leaves
  out: it comes from the simulator, not from a measured exit.
- `lint --to` names the provider matrix and its release date in every verdict (`target` in the JSON report, and
  in the text summary), so a pass from an old matrix is visible. The capability data records the release date.
- The README's status lists what works today, including DNSSEC validation in `parity`, `watch` and `--evidence`.
- Domain Guard's "answers within 2 working days" is now planned as 4 calendar days, the upper bound across a
  weekend (was 48 hours). Exit times under Guard in `docs/model.md` grow accordingly.
- L-21 also checks CDNSKEY algorithms and CDS digests, and flags the GOST R 34.11-94 digest next to SHA-1 (RFC 8624
  section 3.3): a CDS or CDNSKEY asks the parent to publish exactly that.
- The model, the observability contract, the README and the roadmap match the code: the lint rule table says where
  each rule runs (L-00, L-20, L-21 and L-22 added; L-05, L-06 and L-17 marked v0.2; L-19 in parity), the mail rules
  M-01 to M-11 have a table, the command table lists every command with its real flags, the threat model covers
  `watch`'s network paths, the series budget is recomputed (28 per zone, 36 with an exit objective), and the keyed-hash
  zone label is marked as planned, not built. Guard tests keep them in line.
- Roadmap v0.2 adds a readable per-zone report, a `watch` digest for users without a metrics stack, bulk zone
  input from DNSControl `get-zones` for portfolio mode, and a thin, reviewed mapping to audit frameworks.
- Roadmap v0.1 names exactly the lint rules it ships; L-05, L-06 and L-17 move to v0.2 with provider capability
  profiles. v0.1 adds the referral no-DS proof (NSEC3 opt-out included), CI templates for GitLab and GitHub, and the
  release supply chain with a container image; published CI components stay in v0.2.

### Fixed
- Dependencies: `golang.org/x/net` 0.62.0 (fixes GO-2026-6610, 6611, 6612, 6617, 6860, 6866 in code Lostname does
  not reach; govulncheck found none reachable), pytest 9.0.3 for the tests (PYSEC-2026-1845), the SARIF upload
  action 4.39.2.
- The public text check reports, without failing, the flags in a Dependabot pull request's own title and body (they
  quote upstream release notes); hard failures and the diff check are unchanged.
- Text output can no longer carry terminal control characters from zone data or server answers.
- `fetch` refuses a transfer that runs past `fetch.deadline_seconds` or grows past `fetch.max_records` (no verdict),
  one framed by another zone's SOA, or one with an SOA inside it.
- A zone file with `$GENERATE` is refused with the line number; expand it first.
- `parity` reports a provider's servers that serve the same data with different TTLs as `inconsistent-servers`.
- Inputs fail closed on holes the second red team found: `$GENERATE` hidden behind a carriage return or parentheses
  is refused; records outside class IN are refused; crafted `print-ir` input (a type number that disagrees with the
  type, a domain listed twice, trailing data, a line break in data, a record spliced into a name) is refused; the
  transfer's closing SOA must equal the opening one in full.
- The config refuses disabling or downgrading L-00, unknown rule ids, probe ports that are not 1-65535, and keys
  that match only when case is ignored. A baseline never hides an L-00 finding.
- Evidence bundles store inputs by role (`inputs/zone-...`, `inputs/baseline-...`), refuse two files for one path,
  include the origin in their name and take a numeric suffix rather than fail when a bundle of the same second
  exists; `Verify` refuses paths outside the bundle and needs `versions.json`. SARIF points at the input as a path
  relative to the working directory.
- `parity` fails closed on eleven cases the second red team found: the DS at a delegation and its glue are compared;
  a provider serving its own copy of a delegated child fails; TXT text keeps its spaces when compared; data at an
  empty non-terminal fails; a class other than IN never compares equal; a parent DS over a provider without keys
  fails (a stale DS, or an unsigned provider of several); the DNSKEY RRset must be the same over UDP and TCP;
  colliding key tags are all tried; a revoked key may only sign the DNSKEY RRset.
- The publication tooling fails closed on five holes the second red team found: `export.py` refuses a target that
  contains the repository or is a non-empty directory that is not the public clone (a wrong target once deleted the
  repository), never touches any `.git`, and refuses symbolic links; private passages are removed whole or the build
  stops; a missing client-names file is an error and an export needs it; a denied term split across a line break is
  caught.
- `watch` fixes from the second red team: the interception gauge is raised when any zone's path is caught; a provider
  pair is only counted when both sides answered (a silent reference no longer reads as 0 mismatches); a zone listed
  twice is refused; a second `LostnameChecksSilent` rule covers checks without any success since `watch` started;
  label values use OpenMetrics escaping and provider names must be plain; `/metrics` answers GET and HEAD only, with
  read, write and idle timeouts; the OTLP push repeats the latest snapshot every 30 seconds so stacks with a short
  lookback keep seeing it.
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

### Security
- The release notes' `cosign` commands check the exact signer, the release workflow at that tag
  (`--certificate-identity .../release.yml@refs/tags/vX.Y.Z`); the release candidates' notes accepted a signature
  from any workflow in the repository.

