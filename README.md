<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/final/wordmark-dark.svg">
    <img src="brand/final/wordmark.svg" alt="lostname" height="72">
  </picture>
</p>
<p align="center"><strong>Last name standing.</strong> Prove you can leave your DNS provider without losing your name.</p>
<p align="center">
  <a href="https://github.com/lostnamehq/lostname/actions/workflows/ci.yml"><img src="https://github.com/lostnamehq/lostname/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/lostnamehq/lostname/releases"><img src="https://img.shields.io/github/v/release/lostnamehq/lostname?include_prereleases&amp;sort=semver" alt="Latest release"></a>
  <a href="https://pkg.go.dev/lostname.be/lostname"><img src="https://pkg.go.dev/badge/lostname.be/lostname.svg" alt="Go Reference"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/lostnamehq/lostname" alt="Go version"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/lostnamehq/lostname"><img src="https://api.scorecard.dev/projects/github.com/lostnamehq/lostname/badge" alt="OpenSSF Scorecard"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-EUPL--1.2-blue" alt="Licence: EUPL-1.2"></a>
</p>

Lostname is a command-line tool for domain owners and the IT partners who run domains for them. It answers one
question before you need it: *if we had to move our DNS today, what would break, how long would it take, and can we
prove it went right?*

> **Status: v0.1 release candidates.** `lint`, `parity`, `mail`, `watch`, `fetch`, `doctor` and `config` work and are
> tested; `plan`, `simulate`, `drill` and `report` are the plan (`ROADMAP.md`). Output formats and the observability
> contract are stable from v0.1.0; until then they may still change.

## Quick start

```sh
go install lostname.be/lostname/cmd/lostname@latest   # or a signed binary from Releases, or the container image

lostname lint --zone example.test.zone --origin example.test --to HETZNER_V2
```

```text
L-07  note    example.test. CAA: CAA issue "letsencrypt.org" has no accounturi: any account at that CA may issue (RFC 8657)
L-11  blocker shop.example.test. NS: the delegation names ns1.dns-host.example., a server of the current DNS provider: after the exit it is lame unless shop.example.test. moves too (Lostname model section 3)
L-12  risk    www.example.test. CNAME: CNAME points at proxy.dns-host.example., under dns-host.example, the current DNS provider's own domain: check that it keeps working after the exit (Lostname model section 3)
lint fail: example.test., 12 record(s), 1 blocker(s), 1 risk(s), 1 note(s)
```

Then check that a standby provider serves the same zone as the current one, DNSSEC included:

```sh
lostname parity --zone example.test.zone --origin example.test \
  --provider current=192.0.2.53 --provider standby=198.51.100.53
```

`lint`, `parity` and `mail` also write `--json` (JSON Schemas in `docs/schemas/`); `lint` and `parity` write `--sarif`
for code scanning. The container image is `ghcr.io/lostnamehq/lostname`, and `deploy/ci/` has ready-made jobs for
GitLab CI and GitHub Actions that run `parity` against a standby provider on a schedule.

## Why
Number portability lets you keep your phone number when you switch operators. Domains have no such guarantee in
practice. A move between DNS providers silently breaks things:
- an export that drops the SOA, so the zone stops being served;
- DNSSEC keys that don't move, so validating resolvers fail;
- provider-specific records that don't exist anywhere else;
- mail and certificate renewals tied to the old provider's API.

Most owners find out during the move. Lostname finds out before it.

## What it does
| Command | Answers | Release |
|---|---|---|
| `lint [--to PROVIDER]` | what is wrong with the zone, and what will not survive a move to that provider (DNSControl's provider matrix, pinned); reads zone files and `dnscontrol print-ir` | v0.1 |
| `parity --provider A=ADDR --provider B=ADDR` | do both providers answer every query the same, authoritatively; validates DNSSEC against each provider's own keys, the parent's DS, and NSEC/NSEC3 denial | v0.1 |
| `mail` | what the zone publishes for mail (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, TLSA) and what is wrong with it, offline | v0.1 |
| `watch` | `lint` and `parity` on a schedule: Prometheus metrics, OTLP, optional events and traces, and an exit-readiness SLO | v0.1 |
| `fetch` | the zone itself, by zone transfer (AXFR, TSIG) | v0.1 |
| `doctor`, `config` | can this machine and network path give verdicts at all; the effective configuration | v0.1 |
| `plan --from A --to B` | the safe order of steps, DNSSEC included, with the waits computed from your real TTLs, and the **exit time** | v0.2 |
| `simulate` | what any resolver would see at every step of that plan, including what goes wrong if a step fails | v0.2 |
| `drill`, `report` | the yearly exit exercise, and the evidence to show for it | v0.3 |

`--evidence DIR` on `lint` and `parity` writes the inputs, the report and every DNS exchange with a SHA-256 manifest.

## Principles
- **No verdict without authority.** A check that didn't get an authoritative answer from every server it compares
  says "no verdict", never "all clear". Exit codes: 0 pass, 1 findings, 2 no verdict, 3 usage or input error.
- **Build on, never replace.** [DNSControl](https://github.com/DNSControl/dnscontrol) does export, import and push.
  Lostname calls the official, pinned binary and adds what it lacks.
- **The owner acts.** Read-only by default. Lostname never opens your credentials file and never operates DNS for
  anyone.
- **Facts with provenance.** Every finding says what was seen, where, when, and by which version of which tool.
- **Evidence as a by-product.** Every check can leave a bundle with a checksum manifest.

## Verify what you install
Releases are built reproducibly (built twice and compared), signed keylessly with Sigstore, and carry SLSA build
provenance, a CycloneDX SBOM per binary and an OpenVEX statement. Tags are signed with the release key in
`lostname.allowed_signers`. Each release's notes give the exact commands; `docs/publishing.md` describes the path.

## Documentation
- `docs/model.md`: the exit model the checks come from, including the exit codes.
- `docs/observability.md`: metrics, events, traces and alert rules for `watch`.
- `docs/references.md` and `docs/prior-art.md`: the RFCs, and what exists already.
- `CHANGELOG.md`, `ROADMAP.md`, `SECURITY.md`, `CONTRIBUTING.md`, `SUPPORT.md`.

## Standing on shoulders
DNSControl; GRoot and Ferret (formal DNS verification); the IANA DNSSEC Rollercoaster test bed; DNSViz; the IETF
multi-signer automation work.

## Licence
[EUPL-1.2](LICENSE). Contributions come in under the same licence with a Developer Certificate of Origin sign-off
(`CONTRIBUTING.md`).

## Name and mark
`lostname` is the name everywhere technical. `l*stname.` is the wordmark only: the asterisk is the DNS wildcard, the
period the DNS root. Brand assets are in `brand/final/`; see `TRADEMARK.md`.
