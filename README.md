# l*stname.

<p>
  <a href="https://github.com/lostnamehq/lostname/actions/workflows/ci.yml"><img src="https://github.com/lostnamehq/lostname/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/lostnamehq/lostname"><img src="https://api.scorecard.dev/projects/github.com/lostnamehq/lostname/badge" alt="OpenSSF Scorecard"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-EUPL--1.2-blue" alt="Licence: EUPL-1.2"></a>
</p>

**Last name standing.** Prove you can leave your DNS provider without losing your name.

Lostname is a command-line tool for domain owners and the IT partners who run domains for them. It answers one question before you need it: *if we had to move our DNS today, what would break, how long would it take, and can we prove it went right?*

> **Status: pre-release, published early.**
> - **Done:** the model is written (`docs/model.md`), the falsifier lab has run (`m0/`), and the formal model of DNSSEC transitions can be explored with `go test ./internal/sim` (`internal/sim/`).
> - **Works today** (`go run ./cmd/lostname`, pre-release):
>   - `lint` checks a zone file, or the output of `dnscontrol print-ir`, offline; with `--to PROVIDER` it also says what
>     will not survive a move to that provider (DNSControl's provider matrix, pinned; every verdict names its version);
>   - `fetch` transfers a zone (AXFR, TSIG);
>   - `parity` compares what two providers serve, fail-closed, and validates DNSSEC: signatures against each
>     provider's own keys, the chain from the parent's DS, NSEC and NSEC3 denial, and the no-DS proof in referrals
>     (NSEC3 opt-out included);
>   - `watch` runs `lint` and `parity` on a schedule and exports metrics (`/metrics`, OTLP), optional events and
>     traces, and a modelled exit-readiness SLO;
>   - `--evidence DIR` on `lint` and `parity` writes the inputs, the report and every DNS exchange with a checksum
>     manifest.
>   - `mail` reads the zone's mail records (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, TLSA) offline;
>   - `config` prints the effective configuration, and `doctor` checks that this machine, network path and
>     configuration can give verdicts (interception probes, watch files);
>   - CI templates in `deploy/ci/` run `parity` against a standby provider on a schedule (GitLab CI, GitHub Actions).
> - **Next:** the rest of v0.1 (`ROADMAP.md`). Of the commands below, `plan`, `simulate`, `drill` and `report` are the plan, not working code.
> - **Install path once released:** `lostname.be/lostname`.

## Why
Number portability lets you keep your phone number when you switch operators. Domains have no such guarantee in practice. A move between DNS providers silently breaks things:
- an export that drops the SOA, so the zone stops being served;
- DNSSEC keys that don't move, so validating resolvers fail;
- provider-specific records that don't exist anywhere else;
- mail and certificate renewals tied to the old provider's API.

Most owners find out during the move. Lostname finds out before it.

## What it does (planned)
| Command | Answers | Release |
|---|---|---|
| `lostname lint --to <provider>` | what will not survive a move to that provider | v0.1 |
| `lostname parity --provider A=ADDR --provider B=ADDR` | do both providers answer every query the same, authoritatively | v0.1 |
| `lostname mail` | what the zone publishes for mail (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, TLSA), and what is wrong with it, offline | v0.1 |
| `lostname plan --from A --to B` | the safe order of steps, DNSSEC included, with the waits computed from your real TTLs, and the **exit time** | v0.2 |
| `lostname simulate` | what any resolver would see at every step of that plan, including what goes wrong if a step fails | v0.2 |
| `lostname drill`, `lostname report` | the yearly exit exercise, and the evidence to show for it | v0.3 |

## Principles
- **No verdict without authority.** A check that didn't get an authoritative answer from every server it compares says "no verdict", never "all clear".
- **Build on, never replace.** [DNSControl](https://github.com/DNSControl/dnscontrol) does export, import and push. Lostname calls the official, pinned binary and adds what it lacks.
- **The owner acts.** Read-only by default. Lostname never opens your credentials file and never operates DNS for anyone.
- **Facts with provenance.** Every finding says what was seen, where, when, and by which version of which tool.
- **Evidence as a by-product.** Every check can leave a bundle (`--evidence`) with a checksum manifest.

## Standing on shoulders
Lostname builds on:
- DNSControl;
- GRoot and Ferret (formal DNS verification);
- the IANA DNSSEC Rollercoaster test bed;
- DNSViz;
- the IETF multi-signer automation work.

See `docs/references.md` and `docs/prior-art.md`.

## Licence
[EUPL-1.2](LICENSE). Contributions come in under the same licence with a Developer Certificate of Origin sign-off (`CONTRIBUTING.md`).

## Name and mark
`lostname` is the name everywhere technical. `l*stname.` is the wordmark only: the asterisk is the DNS wildcard, the period the DNS root. Brand assets are in `brand/final/`.
