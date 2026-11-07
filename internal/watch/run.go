package watch

import (
	"path/filepath"
	"strings"
	"time"

	"lostname.be/lostname/internal/config"
	"lostname.be/lostname/internal/lint"
	"lostname.be/lostname/internal/parity"
	"lostname.be/lostname/internal/sim"
	"lostname.be/lostname/internal/zone"
)

// Round runs every configured check once and records the results in s. A zone file that cannot be read gives
// no_verdict for both checks of that zone: the measurement is missing, and the metrics say so. It returns the
// interception probe's answer when any zone's path was caught, for the events.
func Round(cfg *config.Config, s *Snapshot, now func() time.Time) *Interception {
	probed, intercepted := false, false
	var caughtBy *Interception
	for _, wz := range zones(cfg, s, now) {
		start := now()
		z, err := zone.ReadFile(wz.ZoneFile, wz.Origin)
		if err != nil {
			d := now().Sub(start)
			checks := []string{"lint"}
			if len(wz.Providers) >= 2 {
				checks = append(checks, "parity")
			}
			if wz.Exit != nil {
				checks = append(checks, "exit")
			}
			for _, c := range checks {
				r := CheckResult{Zone: dnsName(wz.Origin), Check: c, Verdict: "no_verdict", Duration: d, Finished: now()}
				if c == "exit" {
					r.ExitTarget = wz.Exit.Target
				}
				if cfg.Watch.Traces {
					r.Trace = NewTrace(start)
					r.Trace.End = r.Finished
				}
				s.Record(r)
			}
			continue
		}
		s.Record(lintResult(cfg, z, start, now))
		parityVerdict := ""
		if len(wz.Providers) >= 2 {
			r, ran, caught := parityResult(cfg, z, wz, now)
			s.Record(r)
			parityVerdict = r.Verdict
			probed, intercepted = probed || ran, intercepted || caught != nil
			if caughtBy == nil {
				caughtBy = caught
			}
		}
		if wz.Exit != nil {
			s.Record(exitResult(cfg, z, wz, parityVerdict, now))
		}
	}
	// Red team 2, W1: zones probe different paths (IPv4, IPv6); one caught path is enough to raise the gauge.
	if probed {
		s.SetIntercepted(intercepted)
	}
	return caughtBy
}

// zones returns the zones of one round: the listed ones, then every catalog's members (RFC 9432) that are not
// listed already, sorted. A catalog that cannot be read is a `catalog` check without a verdict for it; its members
// are then not checked this round, and say so through their checks' silence.
func zones(cfg *config.Config, s *Snapshot, now func() time.Time) []config.WatchZone {
	out := append([]config.WatchZone(nil), cfg.Watch.Zones...)
	listed := map[string]bool{}
	for _, z := range out {
		listed[dnsName(z.Origin)] = true
	}
	for _, c := range cfg.Watch.Catalogs {
		start := now()
		r := CheckResult{Zone: dnsName(c.Origin), Check: "catalog", Verdict: "pass"}
		var members []string
		cz, err := zone.ReadFile(c.CatalogFile, c.Origin)
		if err == nil {
			members, err = zone.CatalogMembers(cz)
		}
		if err != nil {
			r.Verdict = "no_verdict"
		}
		r.Finished = now()
		r.Duration = r.Finished.Sub(start)
		s.Record(r)
		for _, m := range members {
			if listed[m] {
				continue // an explicitly listed zone keeps its own settings
			}
			listed[m] = true
			out = append(out, config.WatchZone{Origin: m, ZoneFile: filepath.Join(c.ZoneDir,
				strings.TrimSuffix(m, ".")+".zone"), Providers: c.Providers, Parent: c.Parent, Exit: c.Exit})
		}
	}
	return out
}

func lintResult(cfg *config.Config, z *zone.Zone, start time.Time, now func() time.Time) CheckResult {
	fs := lint.Apply(lint.Run(z), cfg.Lint.Disabled, cfg.Lint.Severity)
	r := CheckResult{Zone: z.Origin, Check: "lint", Verdict: "pass",
		LintFindings: map[string]int{"blocker": 0, "risk": 0, "note": 0}}
	for _, f := range fs {
		r.LintFindings[string(f.Severity)]++
		r.Findings = append(r.Findings, Finding{Rule: f.Rule, Severity: string(f.Severity), Name: f.Name,
			Type: f.Type, Ref: f.Ref})
	}
	if lint.Fails(fs, false) {
		r.Verdict = "fail"
	}
	r.Finished = now()
	r.Duration = r.Finished.Sub(start)
	if cfg.Watch.Traces {
		r.Trace = NewTrace(start)
		r.Trace.End = r.Finished
	}
	return r
}

// dnssecFailKinds are the parity findings that make a provider bogus for validating resolvers.
var dnssecFailKinds = map[string]bool{"rrsig-missing": true, "rrsig-invalid": true, "rrsig-expired": true,
	"rrsig-not-yet-valid": true, "rrsig-unknown-key": true, "ds-no-matching-key": true,
	"dnskey-not-signed-by-ds-key": true, "denial-missing": true, "denial-invalid": true, "wildcard-proof-missing": true,
	"ds-without-dnskey": true, "dnskey-transport-differs": true, "rrsig-revoked-key": true}

// dnssecStatus derives each provider's DNSSEC state from a parity report with a verdict: indeterminate when the
// provider left questions unanswered, bogus on a failed signature, chain or denial check, secure when it served
// valid signatures, insecure otherwise (an unsigned zone, or a parent without DS).
func dnssecStatus(rep parity.Report, ps []parity.Provider) map[string]string {
	st := map[string]string{}
	gaps, bogus, noDS := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, g := range rep.Gaps {
		gaps[g.Provider] = true
	}
	for _, f := range rep.Findings {
		if f.Severity == parity.Fail && dnssecFailKinds[f.Kind] {
			bogus[f.Provider] = true
		}
		if f.Kind == "parent-no-ds" {
			noDS[f.Provider] = true
		}
	}
	for _, p := range ps {
		_, signed := rep.SignatureExpiry[p.Name]
		switch {
		case gaps[p.Name]:
			st[p.Name] = "indeterminate"
		case bogus[p.Name]:
			st[p.Name] = "bogus"
		case signed && !noDS[p.Name]:
			st[p.Name] = "secure"
		default:
			st[p.Name] = "insecure"
		}
	}
	return st
}

// mismatchKinds are the parity findings that mean "the two providers serve different data" (docs/observability.md:
// RRsets that differ between two providers).
var mismatchKinds = map[string]bool{"rrset-differs": true, "ttl-differs": true}

func parityResult(cfg *config.Config, z *zone.Zone, wz config.WatchZone, now func() time.Time) (CheckResult, bool, *Interception) {
	start := now()
	var ps []parity.Provider
	for _, p := range wz.Providers {
		ps = append(ps, parity.Provider{Name: p.Name, Addrs: p.Addrs})
	}
	var tr *Trace
	var observe func(parity.Exchange)
	if cfg.Watch.Traces {
		tr = NewTrace(start)
		observe = func(e parity.Exchange) { tr.Exchanges = append(tr.Exchanges, e) }
	}
	// Red team 3, W3-3: a zone with an exit objective is judged in parity under that exit's model, so "ready" for T2
	// means the standby is in T2 parity, not in the global default's.
	model := cfg.Parity.Model
	if wz.Exit != nil {
		model = wz.Exit.Model
	}
	rep, err := parity.Run(z, ps, parity.Options{Model: model,
		Timeout: config.Seconds(cfg.Parity.Timeout), EDNSBuffer: uint16(cfg.Parity.EDNSBuffer),
		NXProbe: cfg.Parity.NXProbe, Canary: cfg.Probe.Canary, Canary6: cfg.Probe.CanaryV6,
		ProbeTimeout: config.Seconds(cfg.Probe.Timeout), Now: start, MinSigLife: config.Seconds(cfg.Parity.MinSigLife), Deadline: config.Seconds(cfg.Parity.Deadline), MaxQueries: cfg.Parity.MaxQueries,
		Pace:   time.Duration(cfg.Parity.Pace) * time.Millisecond,
		Parent: wz.Parent, Observe: observe})
	r := CheckResult{Zone: z.Origin, Check: "parity", Verdict: rep.Verdict, Probed: err == nil}
	if err != nil {
		r.Verdict = "no_verdict"
	} else {
		r.Mismatches = map[[2]string]int{}
		r.Answering, r.Expected = map[string]int{}, map[string]int{}
		silent := map[string]bool{} // provider|addr that left any question without an authoritative answer
		blind := map[string]bool{}  // providers with any gap
		for _, g := range rep.Gaps {
			silent[g.Provider+"|"+g.Addr] = true
			blind[g.Provider] = true
		}
		// Red team 2, W2: a pair is counted only when both sides answered everything; otherwise its mismatch count
		// is a missing measurement, absent, never 0.
		for _, p := range ps[1:] {
			if !blind[rep.Reference] && !blind[p.Name] {
				r.Mismatches[[2]string{rep.Reference, p.Name}] = 0
			}
		}
		for _, f := range rep.Findings {
			r.Findings = append(r.Findings, Finding{Rule: f.Kind, Severity: string(f.Severity), Name: f.Name,
				Type: f.Type, Provider: f.Provider})
			k := [2]string{rep.Reference, f.Provider}
			if _, counted := r.Mismatches[k]; counted && mismatchKinds[f.Kind] {
				r.Mismatches[k]++
			}
		}
		for _, p := range ps {
			r.Expected[p.Name] = len(p.Addrs)
			for _, a := range p.Addrs {
				if !silent[p.Name+"|"+a] {
					r.Answering[p.Name]++
				}
			}
		}
	}
	r.Finished = now()
	r.Duration = r.Finished.Sub(start)
	if tr != nil {
		tr.End = r.Finished
		r.Trace = tr
	}
	if err == nil {
		r.DNSSEC = dnssecStatus(rep, ps)
		r.SigExpiry = map[string]int64{}
		for p, e := range rep.SignatureExpiry {
			r.SigExpiry[p] = e - r.Finished.Unix()
		}
	}
	var caught *Interception
	if err == nil && rep.Intercepted && rep.Interception != nil {
		caught = &Interception{Probe: rep.Interception.Probe, Protocols: rep.Interception.Protocols}
	}
	return r, err == nil, caught
}

// exitResult is the exit-readiness check (OB-2): the exit time of the zone's exit model under its registry lock,
// caches drained (the explorer's drain time, model section 5c), against the objective. The parent's TTLs are the
// registry's (sim.ttls); the DNSKEY TTL is the zone's own when it has one. A zone with providers is ready only when
// its standby is in parity; when parity has no verdict, neither has this check.
func exitResult(cfg *config.Config, z *zone.Zone, wz config.WatchZone, parityVerdict string, now func() time.Time) CheckResult {
	start := now()
	e := wz.Exit
	r := CheckResult{Zone: z.Origin, Check: "exit", ExitTarget: e.Target}
	t := sim.TTLs{DS: cfg.Sim.TTLs.DS, Neg: cfg.Sim.TTLs.Negative, NSParent: cfg.Sim.TTLs.NSParent,
		DNSKEY: cfg.Sim.TTLs.DNSKEY, Margin: cfg.Sim.Margin}
	if ttl, ok := dnskeyTTL(z); ok {
		t.DNSKEY = ttl
	}
	l := cfg.Sim.Locks[e.Lock]
	p := sim.SafePlans[e.Model](t)
	rep := sim.Explore(p)
	r.ExitModel, r.ExitTime = e.Model, sim.ScheduleWith(p, sim.Lock{Name: e.Lock, Latency: l.Latency, Window: l.Window}).Total+rep.Drain
	_, signed := dnskeyTTL(z)
	switch {
	case parityVerdict == "no_verdict":
		r.Verdict, r.ExitModel = "no_verdict", "" // the time is known, the readiness is not
	// Red team 3, W3-4: T0 is the unsigned-to-unsigned exit; on a signed zone it leaves the DS behind, and the zone
	// goes bogus.
	case !rep.OK() || r.ExitTime > e.Target || parityVerdict == "fail" || (e.Model == "T0" && signed):
		r.Verdict = "fail"
	default:
		r.Verdict = "pass"
	}
	r.Finished = now()
	r.Duration = r.Finished.Sub(start)
	if cfg.Watch.Traces {
		r.Trace = NewTrace(start)
		r.Trace.End = r.Finished
	}
	return r
}

// dnskeyTTL is the largest DNSKEY TTL at the zone's apex: the one a cache can hold longest.
func dnskeyTTL(z *zone.Zone) (int, bool) {
	ttl, ok := 0, false
	for _, rec := range z.Records {
		if rec.Type == "DNSKEY" && strings.EqualFold(rec.Name, z.Origin) {
			ttl, ok = max(ttl, int(rec.TTL)), true
		}
	}
	return ttl, ok
}

func dnsName(s string) string {
	s = strings.ToLower(s)
	if s == "" || s[len(s)-1] != '.' {
		return s + "."
	}
	return s
}

// Worst returns the worst verdict in the snapshot: no_verdict over fail over pass, for `watch --once` exit codes.
func (s *Snapshot) Worst() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	worst := "pass"
	for _, r := range s.results {
		switch {
		case r.Verdict == "no_verdict":
			return "no_verdict"
		case r.Verdict == "fail":
			worst = "fail"
		}
	}
	return worst
}
