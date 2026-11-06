<!-- Generated from private/src/model.md by tools/publicize.py. Edit the source, not this file. -->
# Lostname model (draft 2, 2026-11-05)

Lostname lets a zone owner, or the IT partner acting for them, prove they can leave their DNS provider. This document fixes the vocabulary, data model, rules, timing and threats. Every rule traces to a finding of the M0 lab (`m0/FINDINGS.md`, F1-F9) or to a standard (`references.md`).

## 0. Scope
Release order and status are in `../ROADMAP.md`.

## 1. Principles
- **P1. No verdict without authority.** Every compared answer needs AA with NOERROR or NXDOMAIN, or a referral where a referral is expected. Otherwise the command exits 2: no verdict (F8).
- **P1b. Detect interception.** If a server that should be authoritative sets RA, or answers without AA, Lostname reports "path intercepted" and gives no verdict. M0 F9: a residential network rewrote port-53 traffic to the .be servers. Fallback: an encrypted resolver (DoH) for facts that tolerate caching. Never for parity.
- **P2. Build on, never replace.** DNSControl (pinned version, absolute path, checksum verified on every call) does export, import and push. Lostname reads `print-ir`, `get-zones` and `preview --report` and queries authoritative servers itself.
- **P3. The owner acts, Lostname advises.** Read-only until `drill --apply` (later release). Lostname never opens `creds.json`.
- **P4. Facts with provenance.** Every fact records its source (server, address and transport, or file and line), its time and the tool versions. Capabilities record their date and the evidence behind them; older than 12 months becomes `unknown`.
- **P5. Evidence as a by-product.** Every command writes a bundle with a manifest, good result or bad.

## 2. Entities
| Entity | Fields | Source |
|---|---|---|
| `Zone` | apex, parent, desired records (IR), DNSSEC intent, wildcard owners, delegations | `dnscontrol print-ir` |
| `Provider` | DNSControl type and name, authoritative addresses (v4/v6), capability profile | IR + live + overlay |
| `CapabilityProfile` | record types; `soa_required`; `dual_host`; `dnskey_import`; `cds_import`; `cds_publish`; `ds_api`; algorithms offered; NSEC/NSEC3 and parameters; ALIAS semantics (`none`, `apex_only`, `any`, `needs_resolver`); TTL limits; TXT splitting; `zone_file_import`; `private_key_export`. Each value is `yes`, `no` or `unknown`, with a source and a date | vendored DNSControl matrix + `capabilities/overlay.yaml` |
| `Snapshot` | per address and transport: query, rcode, AA, RA, TC, EDNS size, answer, authority, additional, RRSIG validity (inception, expiry, key tag known), time | live queries with DO |
| `KeySet` | per signer: DNSKEYs (tag, algorithm, flags), CDS/CDNSKEY, the DS needed per KSK, NSEC or NSEC3 with parameters | live |
| `ParentState` | DS RRset and its original TTL (from the RRSIG), delegation NS and glue with TTLs, negative TTL (`min(SOA MINIMUM, SOA TTL)`, RFC 2308), CDS scanning yes/no/unknown, registrar and registry locks (EPP status, RFC 5731), publication delay `Dp` (documented or unknown) | parent servers + overlay + owner |
| `Finding` | id, rule, severity (`blocker`, `risk`, `note`), subject, facts, basis, fix hint | lint, parity, plan |
| `Plan` | model, steps with preconditions, the wait before the next step (formula, inputs, value), rollback per step, the hashes of the IR and the exports it was made for | `plan` |
| `Drill` | from, to, plan hash, steps done, parity before and after, outcome | `drill` |
| `EvidenceBundle` | inputs, snapshots, findings, plan, parity, versions, `MANIFEST.sha256`, optional RFC 3161 token | every command |

## 3. Lint rules
| Id | Rule | Severity | Basis |
|---|---|---|---|
| L-01 | Target needs an SOA in the config and none is present: push deletes it, the zone stops serving | blocker | F2, U-12 |
| L-02 | Record type unsupported by the target | blocker | DNSControl matrix |
| L-03 | ALIAS/ANAME present (not standard, not portable, semantics differ) | risk; blocker if the target is `none` | F5, F6 |
| L-04 | DNSSEC intent missing from the config while the source signs | blocker for an exit | F1, F3 |
| L-05 | Provider metadata the target needs is missing (e.g. `default_ns`) | risk | F1 |
| L-06 | TTL outside the target's limits | risk | provider limits |
| L-07 | CAA without `accounturi`, or tied to a provider-held ACME account | note / risk | RFC 8657 |
| L-08 | CNAME at the apex, or a CNAME next to other data (only DNSSEC records may share the owner) | blocker | RFC 1034 3.6.2, RFC 2181 10.1 |
| L-09 | In-domain delegation without glue (referrals must carry all available in-domain glue, or set TC=1) | blocker | RFC 9471 sec 3.1 |
| L-10 | Provider-specific metadata (proxy, geo, weighted) dropped on export | risk | F1 |
| L-11 | Sub-delegation NS pointing at the old provider's servers: lame after the exit | blocker | C |
| L-12 | Targets on the provider's own names (`*.provider-dns.*`, proxy, redirect or mail-forwarding hosts) | risk | C |
| L-13 | SVCB/HTTPS AliasMode (SvcPriority 0) or SvcParams the target lacks | risk | RFC 9460 |
| L-14 | CAA with the critical flag and an unknown or unsupported tag (a CA must not issue) | risk | RFC 8659 4.1 |
| L-15 | Fewer than two apex NS after the move | risk | C |
| L-16 | Responses near the EDNS limit (large DNSKEY or TXT) that truncate; TXT split differently | note | C |
| L-17 | No common signing algorithm (or common set of algorithms) at the two providers | blocker for T2 and T3 | RFC 8901 sec 4 |
| L-18 | DNAME present, or MX/NS pointing at an alias | risk | RFC 2181 10.3 |
| L-19 | CDS published while the parent scans CDS, and the two providers' CDS differ (in model 2 CDS/CDNSKEY must be cross-imported) | blocker | RFC 8901 secs 8-9, model 2 |

## 4. Parity
- **Coverage:** every (name, type) in the union of the IR and both exports, plus probes: apex SOA, NS, DNSKEY, CDS/CDNSKEY; a random NXDOMAIN name; a random label under every wildcard owner (tests synthesis, C); every empty non-terminal; DS at every cut.
- **Transport:** each authoritative address (v4 and v6) over UDP with EDNS 1232 and DO, and over TCP. TC without a working TCP answer is a failure. Never ANY: our inference from RFC 8482, which lets responders decline conventional ANY answers.
- **Authority:** P1 and P1b.
  - **Below a cut:** a referral is expected; NS and glue are compared, and the parent's glue against the child's.
  - **DS at a cut:** an authoritative answer from this zone, compared as an RRset.
- **Denial:** NXDOMAIN versus NODATA per name is compared. An empty non-terminal answered NXDOMAIN is a failure (RFC 8020 sec 2, and sec 3.1, which clarifies that the correct response to an ENT is NODATA). NSEC versus NSEC3 is reported as a risk, not a validation failure: it defeats NSEC3's protection against enumeration and may affect negative caching; exclusive use of one is preferred (RFC 8901 sec 5 and 5.1).
- **Signatures:** validated, not just counted: inception and expiry, the key tag present in that server's DNSKEY, and the chain to the parent's DS where the model expects one.
- **Expected differences, model-dependent:**
  - apex NS: expected in T0/T1, a failure in T2, where both serve A+B;
  - SOA MNAME and serial: expected;
  - REFRESH, RETRY, EXPIRE: reported;
  - MINIMUM: a risk, since it sets the negative TTL;
  - DNSKEY, RRSIG and NSEC material: expected per signer.
- **Comparison rules:** ASCII letters in labels case-insensitive (RFC 4343); TXT compared as the string list and as the concatenation (a split difference is reported, not failed); stop at the first CNAME.
- **Failures:**
  - differing RRsets or TTLs;
  - an IR record answering empty;
  - invalid or missing signatures where signing is intended;
  - non-authoritative answers;
  - interception.

## 5. DNSSEC transition models (`plan`)
Notation:
- `TTL_DS` and `TTL_NSp`: parent DS and delegation NS (original TTLs);
- `TTL_NSc` and `TTL_DNSKEY`: the child's own NS and DNSKEY TTLs;
- `TTL_max`: the zone's largest TTL;
- `Neg_p`: the parent's negative TTL;
- `Dp`: the parent's publication delay;
- `M`: margin.

Unknown inputs make the plan say "unknown", never a default.

| Model | Needs | Steps | Validation gap |
|---|---|---|---|
| T0 unsigned to unsigned | nothing | 0) lower TTLs at A, wait the old TTLs; 1) B serves identical data (parity); 2) switch NS at the parent; 3) wait `Dp + max(TTL_NSp, TTL_NSc) + M`; set A's apex NS to B and wait `TTL_NSc`; 4) A stops (section 8: dangling delegation) | none |
| T0s unsigned to signed | B signs | T0 steps 0-4, then T1 steps 5-6 | none (the zone was unsigned before) |
| T1 insecure swap | nothing from the providers | 0) lower TTLs at A (NS, DNSKEY, records), wait the old TTLs; if A publishes CDS and the parent scans, publish the CDS delete signal `CDS 0 0 0 0` / `CDNSKEY 0 3 0 0` (RFC 8078 sec 4) or have scanning turned off; 1) remove the DS at the parent and confirm at the parent's servers (not just "API ok"); 2) wait `Dp + TTL_DS + M`; 3) B serves identical data (parity, unsigned or signed without DS); 4) switch NS, wait `Dp + max(TTL_NSp, TTL_NSc) + M`; set A's apex NS to B, wait `TTL_NSc`; 5) B signs; check DNSKEY and RRSIG validity at every B address; wait `TTL_DNSKEY + M` (finding S1, section 5b); 6) publish B's DS, confirm at the parent, wait `Dp + max(TTL_DS, Neg_p) + M` before declaring the zone secure | unsigned from step 1 to step 6 |
| T2 multi-signer, model 2 (RFC 8901 sec 2.1.2 and 3); procedure per IETF draft-ietf-dnsop-dnssec-automation (add signer, remove signer), as implemented in MuSiC; to align step by step before v0.2 | `dnskey_import` and `cds_import` at both providers; the same algorithm (L-17) | 0) lower TTLs; 1) cross-import ZSKs (and CDS/CDNSKEY); wait `TTL_DNSKEY + M`; 2) add B's DS next to A's, wait `Dp + TTL_DS + M`; 3) both serve apex NS = A+B (our design choice for a mixed period; RFC 8901 does not prescribe it, and RFC 6781 4.3.5.2 only says the NS set changes at re-delegation); 4) parent NS = B (or A+B first), wait `Dp + max(TTL_NSp, TTL_NSc) + M`; 5) A's apex NS = B only, wait `TTL_NSc`; 6) after `Dp + max(TTL_NSp, TTL_NSc) + TTL_DNSKEY + M` from step 4 (finding S2, section 5b), remove A's DS, wait `Dp + TTL_DS + M`; 7) after `TTL_max`, remove A's ZSK from B (A's cached signatures have expired from caches); 8) A stops | none |
| T3 key transfer | `private_key_export` at A, import at B; same algorithm and NSEC/NSEC3 parameters | move the keys, then T0 steps 2-4 | none; but the private key leaves A, a security trade-off chosen by the owner |
| T5 model 1 (owner holds the KSK) | owner-run KSK; providers accept an external DNSKEY RRset signature; no CSK | per RFC 8901 sec 2/7 | none; rare for SMEs, listed for completeness |
| T6 hidden primary | the owner signs; both providers act as secondaries | NS swap as T0, signatures stay identical | none |
| T4 double-DS without key import | (none) | **refused**: a resolver with A's DNSKEY or DS cached sees B's data as bogus until those TTLs expire | intermittent failures |

Model choice:
- T6 if a hidden primary exists;
- T2 if both providers support key and CDS import with the same algorithm;
- otherwise T1, with the gap stated in hours (T0 or T0s for unsigned zones);
- T3 and T5 only on the owner's explicit choice.

Timing reference: RFC 6781 section 4.3.5 for changing DNS operators: 4.3.5.1 for cooperating operators (the basis of T2) and 4.3.5.2 for non-cooperating operators (T1 is a simplification of it; to compare step by step before v0.2). RFC 7583 covers rollover timing within one operator and is used only for its waiting logic.

**.be facts (measured 2026-11-05 on a .be domain):**
- DS original TTL 86,400 s (from the RRSIG); delegation NS TTL 86,400 s;
- `.be` SOA: TTL 86,400 s, MINIMUM 600 s, so `Neg_p` = 600 s;
- `Dp` and CDS scanning by DNS Belgium: unknown (to ask; and the draft mail to DNS Belgium is not sent yet).

### 5b. The formal model and what it found (package `sim`, 2026-11-05)
- **What it is.** The transition models are written as data (`internal/sim/plans.go`). An explorer (`internal/sim/explore.go`) enumerates, at the start of every step, every combination of NS, DS and DNSKEY data a resolver can still hold:
  - each fetched in an earlier step;
  - each within its TTL;
  - DNSKEYs only from a provider the resolver could still reach at the moment of fetching.
  
  It then classifies the answer from every server the resolver could ask as secure, insecure, bogus or lame.
- **Invariant:** no bogus and no lame answer is reachable.
- **Self-test:** the explorer finds by itself why T4 (double DS without key import) fails. A resolver holding A's DNSKEY RRset asks B and gets signatures from a key it doesn't have.

**Findings on the plans as drafted** (tests in `internal/sim/explore_test.go`):
- **S1, T1.** Publishing B's DS right after B starts signing is unsafe. A resolver can still hold A's DNSKEY RRset, or B's empty DNSKEY answer from before B signed. The simulator's minimal safe hold is **exactly one DNSKEY TTL** (3,600 s in the default case). Step 5 of T1 therefore becomes: B signs, checked at every B address; **wait `TTL_DNSKEY + M`**; then step 6.
- **S2, T2.** Removing A's DS one NS TTL after the switch to B is unsafe. A resolver can still hold A's DNSKEY RRset, fetched just before its NS cache expired. The minimal safe hold is **NS TTL + DNSKEY TTL** (90,000 s with .be values and a 3,600 s DNSKEY TTL). The draft passed only because its margin equalled the DNSKEY TTL; with a one-day DNSKEY TTL it fails. Step 6 of T2 therefore waits `Dp + max(TTL_NSp, TTL_NSc) + TTL_DNSKEY + M` after step 4.

**Limits of this first version, each to add before results are shown to users:**
- **Child-centric NS:** resolvers that follow the child's apex NS RRset are not modelled.
- **NODATA:** an empty DNSKEY answer is cached for the DNSKEY TTL, not the zone's negative TTL.
- **Not yet modelled:** serve-stale (RFC 8767), aggressive NSEC (RFC 8198) and cached signed data.
- **Validation:** checked at the start of each step only, which is the worst moment because caches only expire later.
- **Parent publication delay:** handled by the rule "timers start when a change is observed" (section 5c), not by the model.

### 5c. Key rolls, registry locks and the parent's delay (package `sim`, 2026-11-05)
- **KSK rolls in place are plans too** (`internal/sim/rolls.go`), for zones that stay with their provider: Insular's most frequent change, and every signed zone's yearly one.
  - The explorer finds by itself that swapping key and DS at once is unsafe.
  - It derives the minimal waits of both methods in RFC 6781 4.1.2 (timing as in RFC 7583). This validates the model on a second family of plans:
    - **double-DS:** one DS TTL after the double DS, then one DNSKEY TTL after the key switch;
    - **double-signature:** one DNSKEY TTL after both keys appear, then one DS TTL after the DS swap.
  - Providers may now hold several signing KSKs.
- **S3: registry locks cost one unlock per parent change on .be** (`internal/sim/schedule.go`).
  - **Domain Shield:** its 24-hour unlock never covers two parent changes, because every plan waits at least a DS or NS TTL (one day) plus a margin between them.
  - **Domain Guard:** each change request needs its own phone confirmation.
  - Planning assumptions (to be replaced by stated or measured times): Shield 4 h per unlock, Guard 2 days.

  | Plan | Parent changes | No lock | Shield | Guard |
  |---|---|---|---|---|
  | T1 | 3 | 52 h | 64 h | 196 h |
  | T2 | 4 | 103 h | 119 h | 295 h |
  | KSK roll, double-DS | 2 | 27 h | 35 h | 123 h |
  | KSK roll, double-signature | 1 | 27 h | 31 h | 75 h |

  **Consequences:**
  - Exit time (D1) includes the lock.
  - `plan` asks for the lock state and schedules the unlock requests.
  - `lint` notes a lock it can see, through the registrar's EPP status codes or the owner's statement.
- **S4: under a lock, prefer the plan with fewer parent changes.** A double-signature roll changes the parent once, against twice for double-DS. Under Guard it takes 75 h against 123 h, and it needs one phone call instead of two. Without a lock, both take the same time. `plan` picks the method by lock state.
- **Timers start when a change is observed, not when it is requested.** The parent's publication delay `Dp` is not a constant to assume: `plan` polls every parent server (authoritatively, P1) until the change is visible at all of them, and only then starts the step's wait. This removes `Dp` from the timing formulas. What remains is the measured time, which the evidence bundle records.

## 6. Evidence bundle
```
evidence/<utc-stamp>-<command>/
  inputs/      ir.json, export-<provider>.zone, capability profile, their SHA-256
  snapshots/   <address>-<transport>.json (query, flags, answer, time)
  findings.json, parity.json, plan.json (as applicable)
  versions.json  lostname, dnscontrol (path and checksum), capability matrix version
  MANIFEST.sha256, tsa/ (optional RFC 3161)
```
No credentials, nothing outside the owner's zone. The report notes that a bundle shows internal names, so sharing is the owner's choice.

## 7. Commands and exit codes
Exit codes: 0 = ok; 1 = findings at or above the threshold; 2 = no verdict (P1, P1b); 3 = usage or tool error.

| Command | Release | Exits 1 when |
|---|---|---|
| `lint [--to P]` | v0.1 | any blocker (or a risk with `--strict`) |
| `parity --providers A,B [--model T0\|T1\|T2]` | v0.1 | any failure in section 4 |
| `plan --from A --to B` | v0.2 | no safe model |
| `drill` (read-only), `report` | v0.3 | preconditions fail / never |
| `drill --apply` | later | preconditions or parity after a step fail |

## 8. Threats and controls
| Threat | Severity | Control |
|---|---|---|
| False all-clear (F8) | blocker | P1, fail closed; test: REFUSED servers exit 2 |
| Intercepted DNS path (F9) | blocker | P1b; test: an RA-setting "authoritative" server exits 2 |
| Push deletes records not in the IR (provider-managed records, metadata lost on export) | blocker | before any apply, diff the target against the IR; refuse deletes that are not in the plan (or use `NO_PURGE`) |
| Push without filters also writes to A | blocker | force `--domains` and `--providers`; refuse a config that contains A in drill mode |
| Time-of-check versus time-of-use | major | the plan binds the hashes of the IR and the exports; re-check before every step |
| Drill against production | major | default to a test zone or label; production needs `--production` plus the zone name typed |
| Registrar or registry lock blocks the NS or DS change | major | `ParentState.locks`; an unknown lock makes `Dp` unknown |
| Registrar delays DS removal, or restores it from CDS | major | precondition "confirmed at the parent's servers"; L-19 and the CDS delete step |
| Dangling delegation: A's zone or account is deleted while A's NS is still cached, and someone claims the zone at A | major | "decommission A" only after the NS waits and after A's apex NS points to B; a check that A answers REFUSED |
| Credential exposure | major | never open `creds.json`; a test asserts no read; no network beyond DNSControl and DNS queries |
| Substituted DNSControl binary | minor | absolute path and a checksum on every call |
| Stale capability data | minor | P4 expiry |

## 9. Non-goals
Lostname does not:
- host DNS;
- sign zones;
- store credentials;
- monitor continuously;
- fix zones automatically;
- call provider APIs (DNSControl does);
- scan third parties;
- check SPF lookup counts or mail policy (they don't change with a provider move; trust-checks covers them).

## 10. Prior art (gh pass 2026-11-05)
| Project | What it does | Why Lostname differs |
|---|---|---|
| DNSControl (about 4.0k stars) | DNS as code: export, preview, push | the base; no provider parity, no DNSSEC transition (F3, F4); no open issue or PR on these |
| OctoDNS (about 3.8k) | DNS as code, `compare` | strict validation refuses some zones (F5); no DNSSEC |
| NLnet Labs Cascade (77, BSD-3, active) | DNSSEC signing pipeline | a signer; it could be the owner's hidden primary in T6 |
| johanix/tdns (11, active) | experimental server with multi-signer work | research, not an owner's tool |
| DNSSEC-Provisioning multi-signer-controller (3, 2021), shuque/multisigntools (2020) | multi-signer group control, IETF draft tooling | dormant; reference for T2 |
| Akamai multi-signer webhook example (2025) | one provider's multi-signer hook | single vendor; evidence that `dnskey_import` exists at some providers |
| Zonemaster, DNSViz | validate a live zone | a snapshot, no transition; possible pre-switch checks for B |

## 13. Planned features
Features D1-D21 (simulator, exit time, continuity checks, exit kit, rehearsal, evidence and more) and their release are listed in `../ROADMAP.md`.

### 13.8 The four pillars and the features they add
Lostname has four core pillars: **sovereignty, reliability, automatability and observability**. A feature belongs in Lostname when it strengthens a pillar *and* reuses the engine (zone model, lint, parity, sim, watch). This replaces the narrower "must change an exit plan or exit time" test.

| # | Pillar | Feature | Effort | Release |
|---|---|---|---|---|
| SV-1 | sovereignty | **Jurisdiction map:** per role (registrar, DNS hosts, CA, mail host), the legal entity, HQ, parent company and the law that reaches it; from an open offline dataset and RIR/AS snapshots; facts, no verdicts | M | v0.2 |
| SV-2 | sovereignty | **EU-only resolution check:** can the zone be resolved and validated using only EU-operated infrastructure? | M | v0.2 |
| SV-3 | sovereignty | **Key custody lint:** who holds the signing keys, and can the owner export them? | S | v0.2 |
| SV-4 | sovereignty | **The tool's own supply chain:** reproducible builds, SBOM, signed releases, fully offline mode | M | v0.3 |
| RL-1 | reliability | **Serial drift:** SOA serials differ between one provider's own servers (a stale secondary), in `parity` | S | v0.1 |
| RL-2 | reliability | **Algorithm lint** (RFC 8624): DNSKEY algorithms that must not or should not be used for signing; SHA-1 DS digests | S | v0.1 |
| RL-3 | reliability | **Diversity score:** networks, prefixes, countries and anycast behind the nameservers (extends L-20) | M | v0.2 |
| RL-4 | reliability | **TTL pre-staging advisor:** the simulator computes how much lowering NS and DNSKEY TTLs before an exit saves | S | v0.1 |
| RL-5 | reliability | **Encrypted second path:** DoH and DoT to EU validating resolvers, an outside view that a VPN or middlebox can't intercept (F10) | M | v0.2 |
| AU-1 | automatability | **SARIF output** for code-scanning views in GitHub and GitLab | S | v0.1 |
| AU-2 | automatability | **Baseline diff:** `lint --baseline` reports only what a change made worse | S | v0.1 |
| AU-3 | automatability | **Policy as code:** Rego policies over the JSON, conftest-compatible, with a policy pack | M | v0.2 |
| AU-4 | automatability | **Executable plans:** a resumable, idempotent step machine with pre- and post-conditions, events per step and autonomy-level gates | L | v0.2 |
| AU-5 | automatability | **Distribution:** container image, GitHub Action, GitLab CI component, stable Go library API | M | v0.2 |
| OB-1 | observability | **Traces:** each check as an OpenTelemetry trace with a span per server query | S | v0.1 |
| OB-2 | observability | **Exit readiness as an SLO:** "exit time at most N hours" as an SLI with burn-rate alerts | S | v0.1 |
| OB-3 | observability | **Dashboards as code** for the contract's metrics | S | v0.2 |
| OB-4 | observability | **RIPE Atlas multi-vantage** (EU-run): real resolvers worldwide, which also checks the simulator's predictions | M | v0.3 |

## 11. Open questions
- Which EU providers support `dnskey_import` and `cds_import`? M1 tests deSEC, Hetzner and OVH.
- DNS Belgium: `Dp`, CDS/CDNSKEY scanning, and lock behaviour.
- The real-provider part of M0: run it before v0.1.

