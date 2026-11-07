#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Mutation suite: each entry breaks one rule in the code in a way that still builds; the tests must then fail.

Usage: python tools/mutate.py [NAME_SUBSTRING]

A mutation that survives (the tests still pass) means a rule is not tested. A mutation whose text is no longer in
the file fails too: the code moved, and the entry must follow it, so the suite never decays into a list that tests
nothing. The original file is restored after every mutation, also on error. Too slow for the push gate (each entry
builds and runs a package's tests); run it before a release and after changing a rule. Every entry is one of the
falsifications done when the rule was written (plan v0.1, "tests that fail on the old code").
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (name, file, original, mutant, package, test regexp)
MUTATIONS = [
    ("lint: L-11 sees only exact provider names", "internal/lint/provider.go",
     "if targets[t] || providers[registered(t)] {", 'if targets[t] || providers[""] {', "./internal/lint", "L11"),
    ("lint: L-16 limit four times too high", "internal/lint/provider.go",
     "if n := m.Len(); n > udpLimit {", "if n := m.Len(); n > 4*udpLimit {", "./internal/lint", "L16"),
    ("lint: L-20 compares whole addresses only", "internal/lint/provider.go",
     "case len(a) == 4 && bytes.Equal(a[:3], b[:3]):", "case len(a) == 4 && bytes.Equal(a[:4], b[:4]):",
     "./internal/lint", "L20"),
    ("lint: L-22 ignores signing", "internal/lint/provider.go",
     'signed := len(z.At(z.Origin, "DNSKEY")) > 0', "signed := true", "./internal/lint", "L22"),
    ("lint: the owner's own domain counts as the provider", "internal/lint/provider.go",
     "delete(providers, registered(z.Origin))", "_ = providers", "./internal/lint", "RT3OwnRegistered"),
    ("mail: two SPF records allowed", "internal/records/records.go",
     "case len(recs) > 1:\n\t\treturn nil, append(fs, Finding{\"M-01\"",
     "case len(recs) > 99:\n\t\treturn nil, append(fs, Finding{\"M-01\"", "./internal/records", "SPF"),
    ("mail: TXT strings joined with a space", "internal/records/records.go",
     'strings.Join(r.RR().(*dns.TXT).Txt, "")', 'strings.Join(r.RR().(*dns.TXT).Txt, " ")', "./internal/records", "SPF"),
    ("mail: a revoked DKIM key is not seen", "internal/records/records.go",
     'case key == "":', 'case key == "x":', "./internal/records", "DKIM"),
    ("mail: the MTA-STS id is not checked", "internal/records/records.go",
     "var stsID = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)", "var stsID = regexp.MustCompile(`^.{1,64}$`)",
     "./internal/records", "MTASTS"),
    ("parity: the referral proof is never asked", "internal/parity/denial.go",
     "if !ctx.signed || ctx.secureCuts[q.name] {", "if true || ctx.secureCuts[q.name] {", "./internal/parity",
     "Referral"),
    ("parity: the opt-out flag is ignored", "internal/parity/denial.go",
     "if c.Cover(next) && c.Flags&1 == 1 {", "if c.Cover(next) {", "./internal/parity", "NoDSProven"),
    ("parity: NSEC3 owners outside the chain count", "internal/parity/denial.go",
     "return ok && len(label) == 32 && strings.EqualFold(rest, origin)",
     "return ok && len(label) == 32 && strings.EqualFold(rest, origin) || true", "./internal/parity",
     "RT3NSEC3Owner"),
    ("parity: CDS sets of two providers not compared", "internal/parity/signatures.go",
     "if sets[typ][a].set != sets[typ][b].set {", 'if sets[typ][a].set == "x" {', "./internal/parity", "CDS"),
    ("parity: the query budget is ignored", "internal/parity/parity.go",
     "if o.MaxQueries > 0 && ctx.queries[addr] >= o.MaxQueries {", "if o.MaxQueries < 0 {", "./internal/parity",
     "Budget"),
    ("parity: no rate-limit label", "internal/parity/parity.go",
     'case ctx.answered[addr] && (strings.HasPrefix(reason, "no answer") || reason == "rcode REFUSED"):',
     "case false:", "./internal/parity", "RateLimit"),
    ("watch: no_verdict closes findings", "internal/watch/events.go",
     'if r.Verdict == "no_verdict" {\n\t\treturn out', 'if r.Verdict == "no_verdict&" {\n\t\treturn out',
     "./internal/watch", "EventsFollow"),
    ("watch: the zone key is not applied", "internal/watch/metrics.go",
     "r = anonymise(s.zoneKey, r)", "_ = anonymise", "./internal/watch", "ZoneName"),
    ("watch: the state file loses findings", "internal/watch/events.go",
     "t.findings[k][f.Finding.key()] = f.Finding", "_ = k", "./internal/watch", "StateSurvives"),
    ("watch: exit time without the drain", "internal/watch/run.go",
     "Window: l.Window}).Total+rep.Drain", "Window: l.Window}).Total+0*rep.Drain", "./internal/watch", "Exit"),
    ("watch: an unprobed round ends the episode", "internal/watch/events.go",
     "} else if probed {", "} else if true {", "./internal/watch", "RT3Interception"),
]


def go_env() -> dict:
    return {**os.environ, "GOFLAGS": "-mod=readonly"}


def run_one(name, rel, original, mutant, pkg, tests) -> str:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    if text.count(original) != 1:
        return "STALE"
    try:
        path.write_text(text.replace(original, mutant), encoding="utf-8", newline="\n")
        b = subprocess.run(["go", "build", pkg], cwd=ROOT, env=go_env(), capture_output=True, text=True)
        if b.returncode != 0:
            return "NO-BUILD"  # a mutant that does not build proves nothing
        t = subprocess.run(["go", "test", "-count=1", "-run", tests, pkg], cwd=ROOT, env=go_env(),
                           capture_output=True, text=True)
        return "caught" if t.returncode != 0 else "SURVIVED"
    finally:
        path.write_text(text, encoding="utf-8", newline="\n")


def main(argv: list[str]) -> int:
    want = argv[0] if argv else ""
    bad = 0
    for m in MUTATIONS:
        if want and want not in m[0]:
            continue
        result = run_one(*m)
        bad += result != "caught"
        print(f"{result:9} {m[0]}")
    print(f"mutate: {bad} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
