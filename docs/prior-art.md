<!-- Generated from private/src/prior-art.md by tools/publicize.py. Edit the source, not this file. -->
# Prior art: wide GitHub search (2026-11-05)

**Method:**
- a deterministic `gh search repos` pass over 66 keyword variants in eight families (migration, parity, DNSSEC transition, redundancy, dangling or takeover, exit, lint, evidence) plus 12 topics;
- 354 unique repositories, deduplicated with the queries that hit;
- the READMEs of the relevant ones read.

**Limits:**
- `gh search` matches names, descriptions and topics, not code.
- GitLab, Codeberg and non-git tools (ldns, Knot `kzonecheck`, `pdnsutil check-zone`) are not covered.
- A zero-hit query is weak evidence.

**Zero-hit queries** (selection; nothing on GitHub matches these words):
- "migrate dns provider", "nameserver migration", "dns compare providers", "authoritative nameserver comparison";
- "dnssec migration", "dnssec provider change", "dnssec key transfer";
- "dns provider diversity", "dns single point of failure", "anycast provider asn check";
- "sitting ducks dns", "dns delegation hijack";
- "vendor lock-in dns", "dns portability";
- "dns evidence report", "dns audit report", "dns compliance report".

## Shoulders and neighbours, per Lostname feature
| Feature | Closest prior art | State | Lostname's difference | Use it how |
|---|---|---|---|---|
| `parity` | **joshenders/dnsdiff** (227 stars): "compares the responses between two nameservers", run "before delegating authority of a zone to a new provider" | Python, **no licence**, last push 2020-12 | DNSSEC validation, authority and interception checks (P1/P1b), wildcard and denial probes, model-aware expected differences, evidence | idea only: no licence, so no code reuse; cite it |
| `parity` | **joemiller/dns_compare** (68): zone file against an authoritative server, "when migrating from one DNS server to another" | Python, MIT, 2022-05 | the same differences; and server-to-server, not file-to-server | MIT: test cases and edge cases may be reused with attribution |
| `lint` | **soplinger/zonecheck** (0, 2026-10): offline zone-file linter (SOA, apex NS, CNAME rules, glue, TXT length, dangling targets) | Python, no licence, brand new | Lostname lints for **portability to a target provider** (capabilities, SOA requirement, ALIAS, metadata, algorithms, CDS), not general zone hygiene | complementary; overlap L-08, L-09, L-15 (general rules) |
| `lint` | privateMwb/DnsLint (0) | health checker, mail focus | out of scope | none |
| `plan` / D3 rehearsal | **iana-org/dnssec-rollercoaster** (2, 2026-08): simulates and tests DNSSEC **algorithm rollovers**, with a Docker Compose test bed (BIND, NSD, Unbound, root hints, trust anchors); built by Kirei AB for ICANN | Python, BSD-3, active | Rollercoaster rehearses a rollover inside one operator; Lostname rehearses a **handover between two providers** (T1/T2) with parent timing | **strong shoulder:** reuse the test bed and possibly the engine (BSD-3, attribution) |
| `plan` / D3 | **DNSViz** "Pre-Deployment DNS Testing": analyse a zone from local zone files and alternate delegations (`-x`, `-N`) before deploying | GPL-2.0, mature | DNSViz judges one state; Lostname sequences states over time with resolver caches | call DNSViz per plan step as an independent validator (run as a tool, not linked) |
| `plan` | shuque/multi-provider-dnssec, shuque/multisigntools (2020), DNSSEC-Provisioning/multi-signer-controller (2021), akamai/multi-signer-dnssec-webhook (2025) | drafts and dormant tools | owner-side planning across arbitrary providers | references for T2 |
| `plan` | rfc-editor-drafts/rfc9975 "Clarifications on CDS/CDNSKEY and CSYNC Consistency"; desec-io DNSSEC bootstrapping draft; ietf-wg-dnsop dnssec-automation draft; johanix multi-provider requirements draft (2025-11) | standards work | - | **normative input:** read RFC 9975 for L-19; the johanix draft for T2 |
| D2 fake-redundancy | GoogleCloudPlatform/multi-provider-dns-with-clouddns (12, archived 2024-06); getnamingo/cardo-dns, AptS-1547/dns-orchestrator (multi-provider management panels) | management, not independence analysis | nobody checks whether two providers are independent (group, AS, anycast, cloud) | none; unique |
| D5 lost-name guard | **pwnesia/dnstake** (859, Go, MIT): "missing hosted DNS zones that can lead to subdomain takeover"; **blacklanternsecurity/baddns** (450, active): takeovers including NS; EdOverflow/can-i-take-over-xyz (5.8k): fingerprints | mature attacker and defender tools | **D5's guard part is not unique.** The `retire` mode (null MX, SPF -all, DMARC reject, lock, evidence) is | reference baddns or dnstake for the post-move check, or reuse dnstake's logic (MIT) |
| D8 exit drill as code | **fabriziosalmi/dnscontrol-actions** (20, MIT): DNSControl preview, push and rollback in GitHub Actions | active | Lostname's template runs `parity` against the standby provider, not deploys | complementary; point to it |
| exit framing | **moveinfra/cloud-switching-kit** (Apache-2.0, 2026-10): cloud exit fees and an EU Data Act switching notice, in the browser | new | compute and data exit, not DNS | evidence that "exit" is a live EU theme; possible ally |
| D11 simulator | no DNS cache or exit simulator on GitHub: "dns simulator", "dns resolver simulation" give only coursework; "dns cache simulation", "dnssec simulator", "dns ttl simulation", "dns digital twin" give zero hits. Code search: **mattyopon/faultray** (16 stars, Apache-2.0, 2026-10) has a `dns_resilience.py` that simulates provider outages, failover and TTL strategies on an abstract infrastructure graph | active | Lostname simulates a real zone, the parent and a DNSSEC handover per resolver cache state | neighbour; cite |
| T2 reference | **johanix/tdns** code (Go, BSD-2): multi-signer keystore and commands (code search) | active | an experimental server, not an owner's planner | reference for T2 |
| CI deploy | dnscontrol GitHub topic: 30+ wrappers and actions | - | - | none |

## Verdict per candidate differentiator (model section 13)
| Id | Unique? | Note |
|---|---|---|
| Parity (core) | partly | dnsdiff and dns_compare exist but are dormant, with no DNSSEC, authority or evidence |
| Lint (core) | yes, in its framing | general zone linters exist; portability to a target does not |
| D1 Exit time | **yes** | no tool or query hit |
| D2 Fake-redundancy | **yes** | no tool or query hit; standards discussion exists (johanix draft) |
| D3 Rehearsal | partly: **build on rollercoaster and DNSViz** | the novelty is the provider handover with parent timing, not the test bed |
| D4 Exit evidence | **yes** | no "dns evidence/audit/compliance report" tool |
| D5 Lost-name guard | **no** for the guard, **yes** for `retire` | dnstake, baddns |
| D6 Portability dataset | partly | DNSControl's matrix covers features; nobody has tested DNSKEY/CDS import |
| D7 ccTLD packs | yes, but small | |
| D8 Exit drill as code | low | close to dnscontrol-actions |
| D9 Portfolio | low | generic |
| D10 Multilingual | low | generic |
| D11 Exit simulator | **yes** | no simulator of DNS caches or exits beyond coursework; faultray is abstract and not DNSSEC-handover specific |

## Big brothers of faultray, and what they mean for D11 and D3 (2026-11-05)
Faultray (Apache-2.0, 16 stars): model-based infrastructure chaos simulation, "no production fault injection". Its larger relatives fall into three families.

| Family | Projects (stars, licence) | What they do | Meaning for Lostname |
|---|---|---|---|
| Chaos engineering (inject faults into running systems) | Toxiproxy (12.5k, MIT), comcast (10.5k), Chaos Mesh (8.0k, Apache-2.0, CNCF), ChaosBlade (6.5k), LitmusChaos (5.7k, CNCF), Pumba (3.2k), Chaos Toolkit (2.0k), krkn (518, Red Hat) | break live or staging systems on purpose | the opposite of Lostname's rule (owner's zone, no production experiments); nothing DNS-provider specific |
| Model-based reliability and risk analysis | SCRAM (168, GPL-3: fault and event trees), PFTA, dftlib (dynamic fault trees), librbd (reliability block diagrams) | formal availability and risk models | the formal tradition D11 belongs to; nothing on DNS |
| Simulators and emulators that run real software | **Shadow** (1.7k): a discrete-event network simulator that **runs real applications in virtual time**; OMNeT++ INET (537); ns-3 modules; Kathara (655, GPL-3: container network emulation, used for DNS teaching labs); IMUNES | real binaries on simulated networks and time | **D3 rehearsal:** Shadow could run real resolvers and nameservers (Unbound, NSD, Knot) in virtual time, which answers the CISO's "faking time is fragile" point; Kathara is a lighter lab |

## Formal DNS verification: the real big brothers of "fully modelled" (dns-groot, SIGCOMM 2020 and later)
| Project | Licence, state | What it does | Meaning for Lostname |
|---|---|---|---|
| **dns-groot/groot** (84 stars) | MIT, last push 2023-01 | static verification of DNS zone files: it computes equivalence classes of all possible queries and checks properties over **every** query, not a sample | **parity by proof, not by probes:** GRoot-style equivalence classes could show that two providers' zones answer every possible query alike. A candidate core for D11 and for `parity`; dormant, so a fork or port to Go is a decision |
| **dns-groot/Ferret** (35) and FerretDataset | MIT, 2023 | automatic test generation and differential testing of nameserver implementations | test cases for how different providers' servers answer the same zone (implementation differences behind F5 and F6) |

**Correction to the "unique" claim:** a fully modelled check of DNS configurations exists as research (GRoot). What remains new:
- the **exit across time and resolver caches** (D11), with the DNSSEC handover and parent timing;
- the **owner-facing tool**.

Lostname cites GRoot and Ferret as its foundation and does not claim the modelling idea.

## Beyond GitHub: GitLab, Codeberg and the DNS software itself (2026-11-05)
**GitLab.com and Codeberg:**
- 30 queries from the same families (GitLab API search on names, paths and descriptions; Codeberg Forgejo search API).
- **GitLab hits:**
  - `dandrews/dnsdiff` (2015): "diff the responses between two nameservers", an older sibling of joshenders/dnsdiff;
  - `lp-sysadmin-tools/keyroller` (2020): BIND key rollover;
  - `prinoX/MADNSimulator` (2018, no description);
  - `graybeam/switchboard` (2026-08): a mail migration orchestrator that also cuts over DNS, a neighbour on the mail side;
  - otherwise DNSControl and OctoDNS configurations and examples.
- **Codeberg hits:** DNSControl and OctoDNS configurations only, plus two zone-file repositories.
- Nothing contradicts the GitHub verdicts.

**DNS software (official docs and the APNIC blog):**

| Software | Feature | Source | Meaning for Lostname |
|---|---|---|---|
| **IETF draft-ietf-dnsop-dnssec-automation** (repo active 2026-07) | specifies the multi-signer processes: adding a signer, removing a signer, algorithm rollover, on RFC 8901 model 2, RFC 8078 (CDS/CDNSKEY) and RFC 7477 (CSYNC) | APNIC blog 2023-06-22 L27; MuSiC README | **T2 follows this draft:** "add B as signer, switch, remove A as signer" is the draft's procedure. Lostname cites it and implements no own variant |
| **MuSiC** (DNSSEC-Provisioning/music, Go, no licence, last push 2024-11) | proof-of-concept Multi-Signer Controller implementing the draft | README | the closest automation tool for T2: no licence (idea only), dormant, and it needs signers that accept dynamic updates, which commercial providers rarely do |
| **Knot DNS 3.5** | `dnskey-sync` section: DNSKEY dynamic-update synchronisation for multi-signer groups | knot-dns.cz reference, L1339-L1344 (sha 38d5856c3065aa42) | signer-side multi-signer support exists; relevant to T6 and to providers that run Knot |
| **BIND 9** | multi-signer via dynamic updates of DNSKEY, CDS, CDNSKEY and CSYNC; tested with `dnssec-policy`, with quirks | APNIC blog L11, L31-L33 (sha 521677717c9347d3) | same; the "quirks" are a reason for D3 rehearsal |
| **PowerDNS Authoritative** | DNSSEC modes of operation (online signing, pre-signed, front-signing) | doc.powerdns.com "Modes of Operation" (search result; import of a foreign DNSKEY not checked) | to test in M1 (D6) |
| **ldns** | `ldns-compare-zones`: compares two zone files offline | man page (search result) | file parity exists; Lostname's parity is live, authoritative, over UDP and TCP, with signatures |

**Verdict after the full check:**
- **No owner-facing tool plans, simulates or verifies a provider exit across time and resolver caches** (D11, D1, D3), anywhere we looked.
- **Unique:** the shared-fate check (D2) and exit evidence (D4).
- **Not ours to invent:**
  - the multi-signer procedure (IETF draft, MuSiC, Knot, BIND);
  - formal zone verification (GRoot);
  - file comparison (ldns);
  - two-server diffing (dnsdiff, twice).
- **In one line:** Lostname builds on GRoot, rollercoaster, DNSViz and the IETF dnssec-automation draft to give zone owners a simulated and rehearsed exit plan, including providers that do not support multi-signer.

## Second wide pass: shoulders for D12-D21 (2026-11-05)
| Project | Licence, state | Relevance |
|---|---|---|
| **ANSSI-FR/transdep** (65 stars) | BSD-2, Go, 2018 | single points of failure in DNS dependency graphs (names, NS IPs, /24 and /48); **base for D2** |
| **acme-dns/acme-dns** (2.9k) | MIT | provider-independent DNS-01; **what D12 recommends** |
| **514-labs/dnsglobe** (1.4k) | MIT, Rust, 2026-09 | propagation over 34 public resolvers; **base or neighbour for D19** (no validation) |
| unfrl/dug (372) | 2026-01 | propagation checker; neighbour for D19 |
| **shanyukollipara/dns-failure-workbench** (0) | MIT, Python, 2026-09 | deterministic local resolver lab with a manual clock (negative-caching replay); neighbour for D11 and D20 |
| RIPE-NCC/rcdss (9) | BSD-3, 2023 | CDS scanner for RIPE reverse zones (no bootstrapping); reference for CDS handling |
| moveinfra/cloud-exit-cost-analyzer, NimbusSage/exit-cost | 2026 | generic exit-cost tools; why D-exit-cost was dropped |
| IANA RDAP bootstrap | - | no RDAP service for .be or .eu, so registrar facts for them come from intake |

