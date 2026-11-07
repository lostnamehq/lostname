# Observability contract

> **Status: stable from v0.1.0.** Names, labels, units, event types and trace attributes follow semantic versioning: a rename or removal is a breaking change (see `CHANGELOG.md`, "Upgrading").

`lostname watch` runs the checks on a schedule, in the user's own environment, and emits the results into the user's own observability stack. Lostname has no database and no user interface of its own.

**Implemented (2026-11-06):** `lostname watch` serves every metric below on `/metrics` and pushes the same data over OTLP/HTTP (JSON) when `watch.otlp_endpoint` is set, with the no-verdict rule on both; `--once` runs one round. The alert rules are in `deploy/alerts/lostname.rules.yaml`. Events (section "Events") and traces (section "Traces") are implemented and off by default. Exit readiness is an SLO (section "Exit readiness as an SLO").

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
| `lostname_check_verdict` | stateset | | `zone`, `check`, `lostname_check_verdict` = pass, fail, no_verdict | the last verdict of each check (`lint`, `parity`, `exit` for a zone with an exit objective, and `catalog` for a catalog zone; the DNSSEC series come with `parity`) |
| `lostname_check_last_success_timestamp_seconds` | gauge | seconds (Unix time) | `zone`, `check` | when the check last finished with a verdict |
| `lostname_check_duration_seconds` | gauge | seconds | `zone`, `check` | duration of the last run |
| `lostname_lint_findings` | gauge | | `zone`, `severity` = blocker, risk, note | findings of the last lint run |
| `lostname_parity_mismatches` | gauge | | `zone`, `provider_a`, `provider_b` | RRsets that differ between two providers in the last parity run |
| `lostname_parity_servers_answering` | gauge | | `zone`, `provider` | nameserver addresses that answered authoritatively (AA), over UDP and TCP |
| `lostname_parity_servers_expected` | gauge | | `zone`, `provider` | nameserver addresses configured for the provider (`watch.zones[].providers[].addrs`) |
| `lostname_dnssec_status` | stateset | | `zone`, `provider`, `lostname_dnssec_status` = secure, insecure, bogus, indeterminate | validation result of the zone's chain, per provider |
| `lostname_dnssec_signature_expiry_seconds` | gauge | seconds | `zone`, `provider` | time until the earliest RRSIG expiration seen at that provider |
| `lostname_exit_time_seconds` | gauge | seconds | `zone`, `model`, `basis` = modelled | exit time under the zone's exit model and registry lock, caches drained (absent without a verdict) |
| `lostname_exit_target_seconds` | gauge | seconds | `zone` | the zone's exit-time objective (config, always emitted) |
| `lostname_exit_ready` | gauge | 0 or 1 | `zone`, `basis` = modelled | the SLI: 1 when the exit fits the objective and the standby is in parity (absent without a verdict) |
| `lostname_probe_intercepted` | gauge | 0 or 1 | | 1 when the interception probe got an answer; every verdict over that path is then `no_verdict` |

**Series budget per zone,** with two providers and the two checks `lint` and `parity`: 28 series (2 x 3 verdict states, 2 timestamps, 2 durations, 3 severities, 1 pair, 2 x 2 server counts, 2 x 4 DNSSEC states, 2 expiries). A zone with an `exit` objective adds 8 (3 verdict states, a timestamp, a duration, the time, the target, ready), so 36. A catalog zone (`watch.catalogs`, RFC 9432) adds 5 for its own `catalog` check, and each member counts as a zone. One series, `lostname_probe_intercepted`, is global. With n providers it grows with n squared through the provider pairs, so `parity` compares each provider with one reference by default.

**Zone names as labels.** A zone name is public DNS data, but in a multi-tenant stack the set of monitored zones is that tenant's data:
- **By default,** `zone` carries the raw zone name, for use inside one tenant's scope.
- **For data that crosses a tenant boundary** (for example, aggregates forwarded to a parent stack), switch on the keyed-hash zone label: `watch.zone_id.salt_file` names a file of at least 16 bytes of secret salt. Every label, event subject and span then carries `z` plus 32 hex digits of HMAC-SHA-256(salt, zone) instead of the name, stable per deployment and not reversible without the salt. Owner names in events and spans become relative to the zone (`www`, `@`), because a full owner name contains the zone's name. It applies where results enter `watch`'s snapshot, so every way out carries the id.
- **`tenant` stays optional.** A host stack can set it itself from its own inventory.

## Events (CloudEvents 1.0, JSON)
| `type` | When | `data` |
|---|---|---|
| `be.lostname.check.verdict.changed.v0` | a check's verdict changes (on the first round, `from` is empty) | zone, check, from, to, run id |
| `be.lostname.finding.opened.v0` | a lint or parity finding appears (on the first round, every finding opens) | zone, check, rule, severity, name, type, ref, provider (parity), run id |
| `be.lostname.finding.closed.v0` | a finding is gone in a later run with a verdict | zone, check, rule, name, type, provider (parity), run id |
| `be.lostname.watch.resync.v0` | after watch's first round (a start or a restart) | every verdict (zone, check, verdict) and every open finding, whether the path is intercepted, run id |
| `be.lostname.probe.intercepted.v0` | the interception probe gets an answer, once until the path is clean again | probe address, protocols that answered, run id |

- **`source` and `subject`:** `source` is `lostname/<instance id>`; `subject` is the zone, or its keyed-hash id when `watch.zone_id` is on.
- **No record data:** events carry no record data beyond the owner name and type. A finding's message can quote record data, so events leave it out; the rule and its reference say what the finding is.
- **Across restarts:** with `watch.state_file`, watch keeps its event state on disk (written atomically after each round; owner names, rule ids and verdicts only) and closes, after a restart, the findings that were fixed while it was down. After its first round it always sends a resync event, so any consumer can replace its state. Zones that leave the config leave the state, without events.
- **A missing measurement closes nothing:** a check that ends without a verdict changes its verdict, but neither opens nor closes findings.
- **Configuration:** `watch.events` lists the transports (`http`, `otlp`; none by default), `watch.events_endpoint` is the CloudEvents URL, `watch.instance` names the source (the host name when empty). A failed delivery is reported on stderr and not retried: the metrics carry the current state.
- **Transport:** Lostname sends events as OTLP logs (to `/v1/logs`, the CloudEvents attributes as `cloudevents.*` attributes, the data as the body) or as CloudEvents over HTTP (structured mode, one POST per event). It never publishes to a message bus itself. Mapping event types to bus subjects (for example `events.dns.<tenant>.<type>` on NATS) is the deployer's choice, made in their collector or bridge.
- **Correlation extensions:** optional, in CloudEvents' lower-case extension names: `entityid`, `site`, `tenant`, `riskids`, `severity` and `traceparent`.

## Exit readiness as an SLO
A zone with an `exit` block in its watch entry (`model`, `lock`, `target_seconds`) gets a third check, `exit`, every round.
- **Exit time** is the simulator's: the zone's exit model with the waits the explorer proves safe, scheduled under the registry lock profile (`sim.locks`), plus the drain time until no cache can hold an earlier state. The parent's TTLs are the registry's (`sim.ttls`); the DNSKEY TTL is the zone file's own when it has one.
- **Ready** means the exit time is at most the target and, for a zone with providers, the standby is in parity under the exit's own model (parity runs under it for that zone). A T0 objective on a signed zone is never ready: T0 leaves the DS behind. When parity has no verdict, neither has `exit`: readiness is unknown, not 0.
- **Modelled, not measured.** Every exit series carries `basis="modelled"`: the number comes from the simulator, which rehearsals on real DNS software have not yet validated (ROADMAP, v0.3). It rests on the TTLs and the registry-lock profile in the config, and those lock times are planning assumptions until the registry or registrar confirms them (each profile names its `source`). "Ready" leaves out everything outside DNS: the registrar's and the organisation's own process and approvals, and dependencies such as mail and certificates. Do not present it as a tested exit. When a measured basis exists, it will be a second `basis` value, never a silent replacement.
- **The SLO** is `lostname_exit_ready` over a 30-day window, 99% by default. The shipped rules alert on multi-window burn rates: 14.4 times the budget rate over 1 hour and 5 minutes, and 1 times over 3 days and 6 hours. A round without a verdict burns no budget; the silence alert covers it.

## Traces (OTLP)
With `watch.traces` on, every check run is one OpenTelemetry trace, sent once per round to `watch.otlp_endpoint` at `/v1/traces`.
- **Root span:** `lostname.check.lint`, `lostname.check.parity` or `lostname.check.exit`, with `lostname.zone`, `lostname.check`, `lostname.check.verdict` and `lostname.dns.queries`. A run without a verdict has an error status; a `fail` verdict is a result, not an error.
- **A child span per DNS query** (`dns.query`, kind client), with `dns.question.name`, `dns.question.type`, `network.transport`, `server.address`, `server.port`, and `dns.response_code`, `lostname.dns.aa`, `lostname.dns.tc` for an answer or `error.type` (`timeout`, `connection_refused`, `other`) for none.
- **No answer data:** spans carry the question, never the records that came back.
- **Joined to the events:** each event of a check carries the check's root span as `traceparent`; as an OTLP log record it also carries the record's own `traceId` and `spanId`.

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
| `LostnameWatchAbsent` | no `lostname_check_verdict` series at all for 3 intervals | warning | notify | check that `watch` is running and its metrics reach the stack |
| `LostnamePathIntercepted` | `lostname_probe_intercepted == 1` | warning | notify | run `watch` from a network path without DNS interception |
| `LostnameExitBudgetBurnFast` | readiness error rate over 14.4 x budget in 1 h and 5 min | warning | notify | restore readiness: standby into parity, or a shorter exit |
| `LostnameExitBudgetBurnSlow` | readiness error rate over the budget rate in 3 d and 6 h | info | notify | plan the fix within the budget period |

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

**Run on 2026-11-06, passed:** the OpenTelemetry Collector (contrib 0.163.2) writing to Prometheus v3.15.1 and to VictoriaMetrics v1.154.1, on a throwaway lab box. Both stacks answered all 18 fixture queries as expected, including the blind zone's result series as absent. The fixture is `tools/conformance/` (`emit` pushes it with Lostname's own OTLP code, `expected.json` holds the answers, `run_on_box.py` drives one run), and the record is `tools/conformance/results/2026-11-06.json`. CI does not run it yet: it needs the three containers, so it runs on a lab box.
