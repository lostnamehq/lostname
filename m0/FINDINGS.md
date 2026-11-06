# M0 falsifier: what DNSControl and OctoDNS do for an exit drill without new code

Date: 2026-11-05. Lab: two PowerDNS 5.0.8 authoritative servers (official image `powerdns/pdns-auth-50`), each with its own API and its own DNSSEC signer, standing in for two providers. Tools: DNSControl v5.7.2 (release binary, SHA-256 checked against `checksums.txt`), OctoDNS 1.22.0 with octodns-powerdns 1.2.0, dnspython 2.9.2. Fixture: `fixture.js`, zone `lostname.test` (RFC 6761). Runner: `run_m0.py`; evidence per run in `runs/<stamp>/` with `MANIFEST.sha256` (not in git).

**Not covered yet:**
- real providers (deSEC, Hetzner, OVH; accounts to be created by the operator);
- UDP (Podman on Windows forwards only TCP in this lab);
- a parent zone (no real DS handover).

## Question
Is an exit drill between two providers about 50 lines of glue around existing tools? If yes, there is little reason to build Lostname.

## Answer: no for correctness, DNSSEC and evidence; yes for plain export and import
| # | Finding | Evidence |
|---|---|---|
| F1 | **Export and import of standard records works with little glue.** `get-zones --format=djs` gives a good first draft. Loading it into B took four edits: the provider name, the provider metadata (`default_ns` is not exported), `AUTODNSSEC_ON` (DNSSEC state is not exported) and the SOA (commented out by design). | `run_m0.py` `glue_for_b()`, about 10 lines |
| F2 | **Silent breakage.** Without the SOA edit, pushing the export to PowerDNS deletes the SOA (documented: the provider needs an SOA in the config since v4.16). The zone is no longer served (REFUSED), while `push` reports SUCCESS and the next run 0 corrections. Neither tool warns. | first lab run; upstream register U-12 |
| F3 | **DNSSEC is not handled at all.** Each provider signs with its own key (key tags 5337 and 39697, both ECDSAP256SHA256); no key is published by both; CDS is not published by default. No tool tells the owner that switching nameservers needs either an insecure window or multi-signer (RFC 8901), nor computes the wait times. | `8-dnssec.txt` |
| F4 | **No A-versus-B comparison in DNSControl.** `preview` compares each provider with one desired config. Putting both providers in one config means dual-host: it then wants to rewrite the SOA and add the other provider's NS records. A parity check between two independently run providers is glue. | `5-preview.txt`, `preview-report.json` |
| F5 | **OctoDNS `compare` cannot read the zone.** It rejects a non-apex ALIAS ("non-root ALIAS not allowed"), so a real zone with one such record cannot be compared at all. Its validation is stricter than DNSControl's. | `6-octodns.txt` |
| F6 | **A record can be present and serve nothing.** The ALIAS on `edge` was accepted by DNSControl, exported as the non-standard `IN ALIAS` in the zone file, and answers empty on both servers (PowerDNS needs a resolver configured to expand ALIAS). A naive parity check calls this "equal". | live queries in `7-parity.txt` and the M0 session log |
| F7 | **No evidence.** `--report` only counts corrections. Nothing records what each server serves, which keys sign, or when. | `preview-report.json` |
| F8 | **Glue is easy to get wrong.** The first live-parity script reported "0 differences" while both servers answered REFUSED. It needed three iterations: authority (AA) checks, referrals below a zone cut, apex NS that differ by design, and CNAME chasing. It still shows two artefact differences (NS queries on CNAME names follow the chain to the apex). | `parity_live.py` history |
| F9 | **The network path can lie.** Querying a `.be` TLD server (`a.nsset.be`, 194.0.6.1) from a residential connection returned RA set, AA not set and a decremented TTL, over UDP and TCP: something on the path intercepts port-53 traffic and answers from a cache. An authority check catches it; a naive check would take a cached answer as the provider's. | measurement 2026-11-05, model P1b |
| F10 | **Interception is detectable with one probe, and it changes the answer that matters.** On 2026-11-05, from the same residential connection, a DNS query to 203.0.113.1 (TEST-NET-3, RFC 5737, where no server can exist) was answered over UDP and TCP, and a root server's answer for the root SOA came back without AA. Every port-53 answer came from a middlebox. A registrability check ("is this name in the .be zone?") gave NXDOMAIN without AA and "no delegation" for a domain known to exist, so the earlier "probably free" reading was not evidence. Lostname must send this canary probe before any measurement and refuse a verdict when it is answered (P1b). The same probe from a hosted server got no answer, and the .be servers then answered with AA and an NSEC3 denial: the cause was the client side (a VPN client that redirects DNS is the likely source). | probe script output, 2026-11-05 |

**Glue written for a lab-only drill, without planning or a report:** about 210 lines (`run_m0.py` 92, `parity_live.py` 73, `dnssec_facts.py` 45), and still fragile.

## What this means for Lostname
- **Not new:** export and import (DNSControl does it) and a diff (OctoDNS `compare`, where it can read the zone). Lostname calls these and doesn't rebuild them.
- **New and needed, each shown by a finding:**
  - `lint`: silent breakage (F2), non-portable records (F5, F6), missing provider metadata and DNSSEC state (F1);
  - `plan`: the DNSSEC handover (F3);
  - `parity`: an authority-aware comparison of two independent providers (F4, F8);
  - `report`: evidence of what was served and signed, and when (F7).
- **Verdict:** the falsifier does not kill the case for Lostname. It narrows it to lint, the DNSSEC transition and the evidence. The project should lead with F2 and F3: an owner can believe they have moved while their zone is broken or unsigned.
- **Still to run:** the same drill against at least two real EU providers (deSEC plus Hetzner or OVH), once the accounts exist, including UDP and a parent with a real DS.
