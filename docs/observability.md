# Observability contract (draft)

> **Status: draft v0.1 for review** (v0 reviewed by a first tester on 2026-11-05). Names, labels and units may change until v0.1.0. After that they follow semantic versioning: a rename is a breaking change.

`lostname watch` runs the checks on a schedule, in the user's own environment, and emits the results into the user's own observability stack. Lostname has no database and no user interface of its own.

## Rules
- **Two ways out, same data:**
  - an OpenMetrics endpoint (`/metrics`, Prometheus-compatible);
  - OTLP push (metrics and logs) to any OpenTelemetry Collector.
- **State changes are events:** a finding opened or closed, or a verdict changed, is sent as a CloudEvent (section "Events"), so it can be routed without polling metrics.
- **Base units in names** (`_seconds`, `_bytes`); no milliseconds, no percentages.
- **Bounded labels.** Every label has a known, small set of values per monitored zone:
  - no record data in labels;
  - no free text;
  - no addresses beyond the zone's own nameserver addresses.
  
  The series budget per zone is stated below, so a stack can plan for it.
- **Names in OTLP use dots** (`lostname.parity.mismatches`). The OpenMetrics names are the usual translation (`lostname_parity_mismatches`).
- **Attributes follow OpenTelemetry's semantic conventions** where they exist:
  - `dns.question.name` for record names in logs;
  - `server.address` for a nameserver address.

  Lostname's own attributes carry the `lostname.` prefix.
- **Optional correlation attributes,** never required: `site`, `tenant`, `entity_id`, `risk_id`. Set them as resource attributes, so a host stack can join Lostname data to its own inventory.
- **Silence is a signal.** `lostname_check_last_success_timestamp_seconds` lets an alert fire when checks stop arriving.
- **A missing measurement is never zero.** When a check ends in `no_verdict`, its result series are not emitted for that run:
  - over OpenMetrics they are left out;
  - over OTLP no data point is sent.

  This applies to `lostname_lint_findings`, `lostname_parity_mismatches`, `lostname_parity_servers_answering` and the DNSSEC series. A dashboard can then never read "0 mismatches" while the check was blind. Only `lostname_check_verdict` (state `no_verdict`) and the duration are emitted.

## Metrics (v0)
| Name (OpenMetrics) | Type | Unit | Labels | Meaning |
|---|---|---|---|---|
| `lostname_check_verdict` | stateset | | `zone`, `check`, `lostname_check_verdict` = pass, fail, no_verdict | the last verdict of each check (`lint`, `parity`, `dnssec`) |
| `lostname_check_last_success_timestamp_seconds` | gauge | seconds (Unix time) | `zone`, `check` | when the check last finished with a verdict |
| `lostname_check_duration_seconds` | gauge | seconds | `zone`, `check` | duration of the last run |
| `lostname_lint_findings` | gauge | | `zone`, `severity` = blocker, risk, note | findings of the last lint run |
| `lostname_parity_mismatches` | gauge | | `zone`, `provider_a`, `provider_b` | RRsets that differ between two providers in the last parity run |
| `lostname_parity_servers_answering` | gauge | | `zone`, `provider` | nameserver addresses that answered authoritatively (AA), over UDP and TCP |
| `lostname_parity_servers_expected` | gauge | | `zone`, `provider` | nameserver addresses the delegation names |
| `lostname_dnssec_status` | stateset | | `zone`, `provider`, `lostname_dnssec_status` = secure, insecure, bogus, indeterminate | validation result of the zone's chain, per provider |
| `lostname_dnssec_signature_expiry_seconds` | gauge | seconds | `zone`, `provider` | time until the earliest RRSIG expiration seen at that provider |
| `lostname_probe_intercepted` | gauge | 0 or 1 | | 1 when the interception probe got an answer; every verdict over that path is then `no_verdict` |

**Series budget per zone,** with two providers and the three checks: about 25 series (3 x 3 verdict states, 3 timestamps, 3 durations, 3 severities, 1 pair, 2 x 2 server counts, 2 x 4 DNSSEC states, 2 expiries). With n providers it grows with n squared through the provider pairs, so `parity` compares each provider with one reference by default.

**Zone names as labels.** A zone name is public DNS data, but in a multi-tenant stack the set of monitored zones is that tenant's data:
- **By default,** `zone` carries the raw zone name, for use inside one tenant's scope.
- **For data that crosses a tenant boundary** (for example, aggregates forwarded to a parent stack), the deployer can switch on `lostname.zone.id`. It replaces the raw name with a keyed hash (HMAC-SHA-256 with a salt the deployer supplies), stable per deployment and not reversible without the salt.
- **`tenant` stays optional.** A host stack can set it itself from its own inventory.

## Events (CloudEvents 1.0, JSON)
| `type` | When | `data` |
|---|---|---|
| `be.lostname.check.verdict.changed.v0` | a check's verdict changes | zone, check, from, to, run id |
| `be.lostname.finding.opened.v0` | a lint or parity finding appears | zone, rule, severity, name, type, message, ref |
| `be.lostname.finding.closed.v0` | a finding is gone in a later run | zone, rule, name, type |
| `be.lostname.probe.intercepted.v0` | the interception probe gets an answer | probe address, protocols that answered |

- **`source` and `subject`:** `source` is `lostname/<instance id>`; `subject` is the zone, or `lostname.zone.id` when that is switched on.
- **No record data:** events carry no record data beyond the owner name and type.
- **Transport:** Lostname sends events as OTLP logs or as CloudEvents over HTTP (structured mode). It never publishes to a message bus itself. Mapping event types to bus subjects (for example `events.dns.<tenant>.<type>` on NATS) is the deployer's choice, made in their collector or bridge.
- **Correlation extensions:** optional, in CloudEvents' lower-case extension names: `entityid`, `site`, `tenant`, `riskids`, `severity` and `traceparent`.

## Alerts as code
Every shipped alert rule names an **owner role**, an **action**, a **severity** and a suggested **autonomy** level. No alert ships without an action.
- **Severity** is one of `info`, `warning`, `critical`, `compromise`.
- **Autonomy** says how far automation may act on the alert:
  - `autonomous`: may act alone;
  - `notify`: tell a person;
  - `gated`: act only after a named approval;
  - `human`: a person acts.

  Lostname only suggests autonomy levels; the deployer sets them.

| Alert | Fires when | Severity | Autonomy | Action |
|---|---|---|---|---|
| `LostnameStandbyNotInParity` | `lostname_parity_mismatches > 0` for 2 runs | warning | notify | fix the standby provider before relying on it for an exit |
| `LostnameSignatureExpirySoon` | `lostname_dnssec_signature_expiry_seconds < 3 * 86400` | warning | gated | check the signer at that provider; expiry makes the zone bogus |
| `LostnameDNSSECBogus` | `lostname_dnssec_status{lostname_dnssec_status="bogus"} == 1` | critical | human | incident: validating resolvers reject the zone |
| `LostnameChecksSilent` | no success for 3 intervals | warning | notify | check that `watch` is running and can reach the servers |
| `LostnamePathIntercepted` | `lostname_probe_intercepted == 1` | warning | notify | run `watch` from a network path without DNS interception |

## Component profile
For stacks that register each component's signals:
- **Signals:** metrics and events, acquired by OTLP push or by scraping `/metrics`.
- **Audit stream:** none, because Lostname is read-only: it queries DNS and changes nothing.

A future write path (`drill --apply`) will need its own audit stream before it ships.

## Conformance
For each supported stack, a recorded fixture holds the expected output: a fixed set of results, emitted, ingested and queried back. The fixture includes a `no_verdict` run, whose result queries must return *absent*, not zero. CI runs the same fixture against:
- the OpenTelemetry Collector with Prometheus;
- the OpenTelemetry Collector with VictoriaMetrics.

A difference between the stacks is a bug in our contract, not in the stack.
