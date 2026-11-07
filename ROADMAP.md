# Roadmap

The order of work and its direction. Dates are targets, not promises; versions after the next one may move. Details per feature are in `docs/model.md` (section numbers in brackets).

## Done
- **Model, drafts 1 to 4a:**
  - principles, entities, lint rules, parity semantics and DNSSEC transition models T0-T6;
  - threats and controls;
  - differentiators D1-D21 with priorities;
  - red-teamed and checked against the cited RFCs.
- **M0 falsifier, lab part** (`m0/FINDINGS.md`): a scripted exit between two signing PowerDNS servers. It showed what export and import already cover and what nothing covers: silent breakage, the DNSSEC handover, provider-to-provider parity and evidence.
- **Prior art:** a wide search on GitHub, GitLab and Codeberg and in the DNS software itself (`docs/prior-art.md`).
- **Brand:** mark, badge, wordmark, palette and icons (`brand/`).
- **Formal model, first version** (`internal/sim/`, model section 5b): plans T0, T1, T2 and T4 as data, and an explorer that checks every reachable resolver state.
  - It refuses T4.
  - It found a missing DNSKEY wait in the drafted T1 and T2.
  - It computes the minimal safe waits.

## Next: M0 real-provider part (November 2026)
- The same drill between two real EU providers with a real parent zone, over UDP and TCP.
- First capability observations (DNSKEY and CDS import, dual-host).

## v0.1: lint and parity (target December 2026)
- **Inputs:** RFC 1035 zone files, AXFR (TSIG) and live queries, besides DNSControl. `lint` makes no network calls.
- **Output:** deterministic JSON with a published schema. Exit codes: 0 pass, 1 findings, 2 no verdict, 3 input error.
- **`lint`** for portability to a target provider [3]: rules L-00 to L-04, L-07 to L-16, L-18 and L-20 to L-22, with L-19 (CDS across providers) and L-20 between providers in `parity`. The shared-fate check L-20 [13] covers shared nameserver addresses and prefixes; AS numbers come with the diversity score in v0.2.
- **`parity`**, authority-aware and fail-closed [4]:
  - per address, over UDP and TCP;
  - DNSSEC signatures validated;
  - wildcard and denial probes, and the no-DS proof in referrals (NSEC3 opt-out included);
  - interception detection.
- **DNS and mail record engine** (`lostname mail`, offline): SPF, DMARC (RFC 9989), DKIM, MTA-STS, TLS-RPT, BIMI and DANE TLSA, the base for mail continuity (D13). CAA and DNSSEC stay in `lint` and `parity`.
- **Evidence bundle,** unsigned [6].
- **A CI template** that runs `parity` against a standby provider on a schedule: copy-paste files for GitLab CI and GitHub Actions, using the container image by digest.
- **Release supply chain:** reproducible builds, signed tags, cosign keyless signatures, SLSA provenance, a CycloneDX SBOM per binary, an OpenVEX from govulncheck, SHA256SUMS, and a non-root, read-only-root container image.
- **Reliability and automation extras:**
  - serial drift between a provider's servers;
  - weak DNSSEC algorithm checks (RFC 8624);
  - a TTL pre-staging advisor;
  - SARIF output and a baseline diff for CI;
  - traces of every run;
  - exit readiness as an SLO.
- **`watch`, minimal** (self-hosted): parity and DNSSEC expiry as metrics, exposed as OpenMetrics and sent over OTLP, into the user's own stack. Conformance fixtures for the OpenTelemetry Collector with Prometheus and with VictoriaMetrics.

## v0.2: plan and simulate (target Q1 2027)
- **OpenTofu/Terraform input** (read only).
- **Key changes in place:** KSK rolls and DS changes for a zone that doesn't move, planned and simulated like an exit.
- **`plan`:** transition models T0, T0s and T1 with a timing calculator; T2 (multi-signer) only for providers proven to support it, following the IETF dnssec-automation draft [5].
- **The exit simulator** (D11): resolver cache states per step. With it, **exit time** (D1) as a range (technical floor plus organisational part) and the **scenario library** (D20).
- **Continuity checks:**
  - mail (D13);
  - certificates (D12);
  - provider-injected and hidden records (D15);
  - verification tokens, local output only (D14).
- **`retire` mode** (D5) for names being given up.
- **Provider capability profiles:** what each provider needs and allows, with sources, for the lint rules that need it: required metadata (L-05), TTL limits (L-06) and signing algorithms (L-17).
- **Packs and modes:**
  - `.be` parent facts (D7);
  - break-glass exit kit (D17) with the account-loss tabletop drill (D21) and its manifest, the domain bill of materials (D16);
  - portfolio mode for agencies (D9), reading zones in bulk from DNSControl `get-zones` output for providers without zone transfer (credentials stay in DNSControl).
- **A report a person can read:** a static HTML page per zone, in English and Dutch, built from the JSON reports: lint, parity, the plan and its exit time, labelled modelled until rehearsals measure it.
- **A digest without a metrics stack:** `watch --once --digest FILE` writes a short summary of every zone (verdicts, what changed, exit time) for any scheduler and mailer to deliver. Lostname does not send mail itself.
- **A thin mapping to audit frameworks:** what each check shows, under "evidence, not compliance", reviewed by a qualified person before it ships.

- **Sovereignty and automation:**
  - a jurisdiction map per zone, and an EU-only resolution check;
  - a key custody check;
  - a network diversity score;
  - an encrypted second measurement path (DoH and DoT);
  - policy as code (Rego);
  - executable plans with human gates;
  - published CI components (a GitHub Action, a GitLab CI catalog component) and a stable Go API;
  - dashboards as code.

## v0.3: rehearse and prove (target Q2-Q3 2027)
- **Rehearsal** (D3): the plan replayed on real DNS software in a lab, to validate the simulator.
- **Evidence:** signed evidence and offline `verify` (D4).
- **Data:** the open EU provider portability dataset (D6) and ownership facts with sources (D2).
- **Live:** the validation-aware cutover observer (D19) and provider-independent zone history (D18).
- **Commands:** read-only `drill` and `report`.
- **Proof at scale:** RIPE Atlas multi-vantage measurements and a fully offline mode.

## Later
- **Full DNS observability** (`watch` beyond v0.1): one view over delegation, parity, DNSSEC state and expiry, record drift and mail records. It emits OpenTelemetry, Prometheus/OpenMetrics and versioned JSON events into the user's own stack, with optional dashboards and alert rules as code. It has no database or UI of its own.
- `drill --apply`, only with the controls of model section 8.
- A post-move guard that reuses existing takeover checkers.

## Not planned
- Hosting or operating DNS.
- Signing zones.
- Storing credentials.
- Hosted monitoring as a service: continuous checking is self-hosted by the user.
- Paid-only features.

## References
The full list, with what each standard is used for, is in [docs/references.md](docs/references.md).

### Normative
- RFC 1035, Domain names: implementation and specification (the zone file format): <https://www.rfc-editor.org/rfc/rfc1035>
- RFC 8624, Algorithm implementation requirements and usage guidance for DNSSEC: <https://www.rfc-editor.org/rfc/rfc8624>
- RFC 9989, Domain-based Message Authentication, Reporting, and Conformance (DMARC): <https://www.rfc-editor.org/rfc/rfc9989>

### Informative
- DNSControl, the provider layer Lostname calls: <https://docs.dnscontrol.org/>
