package sim

import (
	"fmt"
	"sort"
)

// Violation is one reachable bad answer: when it happens and which cached state leads to it.
type Violation struct {
	Step     int     // index of the step during which the answer is possible
	StepName string  //
	Outcome  Outcome // Bogus or Lame
	Server   string  // the server the resolver asked
	NSFrom   int     // step whose NS RRset the resolver used
	DSFrom   int     // step whose DS RRset the resolver used
	KeysFrom int     // step whose DNSKEY RRset the resolver used (-1 when not needed)
	KeysOf   string  // provider that served that DNSKEY RRset
}

func (v Violation) String() string {
	return fmt.Sprintf("step %d (%s): %s from %s; NS from step %d, DS from step %d, DNSKEY from step %d at %s",
		v.Step, v.StepName, v.Outcome, v.Server, v.NSFrom, v.DSFrom, v.KeysFrom, v.KeysOf)
}

// Report is the result of exploring a plan.
type Report struct {
	Plan        string
	Violations  []Violation
	Counts      map[Outcome]int // how many explored (state, server) combinations ended in each outcome
	Drain       int             // seconds after the last step until no cache can hold an earlier step's state (M10)
	Assumptions []string        // what the verdict assumes about resolvers; it holds only as far as they do
}

// Assumptions the explorer makes about resolvers (M10). A report carries them, so a verdict is never read without
// them; each one is a place where a real resolver can behave differently.
var Assumptions = []string{
	"resolvers keep a record no longer than its TTL: no serve-stale (RFC 8767) beyond it, no minimum-TTL override",
	"negative answers for the parent's DS are cached for min(SOA MINIMUM, SOA TTL) (RFC 2308 section 5)",
	"a validating resolver takes the DNSKEY RRset from a server it could still reach under its cached NS RRset",
	"step timers start once a change is visible at every parent server; the publication delay is measured, not modelled",
}

// OK reports whether the plan keeps the invariant: no bogus and no lame answer is reachable.
func (r Report) OK() bool { return len(r.Violations) == 0 }

const epsilon = 0.5 // seconds after a step starts: the worst moment, since caches only expire later

// span returns the start and end of each step. Step 0 has held since long before the exit started.
func span(p Plan) (start, end []float64) {
	n := len(p.Steps)
	start, end = make([]float64, n), make([]float64, n)
	t := 0.0
	for i, s := range p.Steps {
		start[i] = t
		if i == 0 {
			start[i] = -1e12
		}
		t += float64(s.Hold)
		end[i] = t
	}
	return start, end
}

// cachedFrom lists the steps j <= i from which a record with lifetime ttl(j) can still sit in a cache at time now:
// it must have been fetched during step j and less than ttl ago.
func cachedFrom(i int, now float64, start, end []float64, ttl func(j int) int) []int {
	var out []int
	for j := 0; j <= i; j++ {
		lo, hi := start[j], end[j]
		if hi > now {
			hi = now
		}
		if from := now - float64(ttl(j)); lo < from {
			lo = from
		}
		if lo < hi || j == i { // the current step can always be fetched fresh
			out = append(out, j)
		}
	}
	return out
}

// lastReach is the latest moment during step j at which a resolver can still send a query to provider p: the end
// of step j if p is in that step's NS RRset, otherwise the end of an earlier step whose NS RRset named p plus the
// NS TTL (the latest fetch of that RRset expires then). It returns -inf when p cannot be reached during step j.
func lastReach(p Plan, j int, prov string, start, end []float64) float64 {
	best := -1e18
	for m := 0; m <= j; m++ {
		named := false
		for _, ns := range p.Steps[m].World.ParentNS {
			named = named || ns == prov
		}
		if !named {
			continue
		}
		t := end[m] + float64(p.TTL.NSParent)
		if m == j {
			t = end[j]
		}
		if t > end[j] {
			t = end[j]
		}
		if t > start[j] && t > best {
			best = t
		}
	}
	return best
}

// Explore checks every reachable resolver state at the start of every step of the plan.
func Explore(p Plan) Report {
	start, end := span(p)
	rep := Report{Plan: p.Name, Counts: map[Outcome]int{}}
	seen := map[string]bool{}
	for i := range p.Steps {
		now := start[i] + epsilon
		if i == 0 {
			now = 0 // steady state: anything fetched within one TTL before the exit started
		}
		w := p.Steps[i].World
		nsSteps := cachedFrom(i, now, start, end, func(int) int { return p.TTL.NSParent })
		dsSteps := cachedFrom(i, now, start, end, func(j int) int {
			if len(p.Steps[j].World.ParentDS) == 0 {
				return p.TTL.Neg
			}
			return p.TTL.DS
		})
		keySteps := cachedFrom(i, now, start, end, func(int) int { return p.TTL.DNSKEY })
		for _, jn := range nsSteps {
			for _, server := range p.Steps[jn].World.ParentNS {
				for _, jd := range dsSteps {
					for _, v := range evaluate(p, i, now, w, server, jn, jd, keySteps, start, end) {
						rep.Counts[v.Outcome]++
						if v.Outcome == Bogus || v.Outcome == Lame {
							k := v.String()
							if !seen[k] {
								seen[k] = true
								rep.Violations = append(rep.Violations, v)
							}
						}
					}
				}
			}
		}
	}
	sort.SliceStable(rep.Violations, func(a, b int) bool { return rep.Violations[a].Step < rep.Violations[b].Step })
	rep.Drain = drain(p, start, end)
	rep.Assumptions = Assumptions
	return rep
}

// drain is how long after the end of the last step a resolver can still hold parent NS, parent DS or a DNSKEY RRset
// from an earlier step that differs from the last step's (M10). The plan is not over until then: the exit time
// includes it, and nothing from an earlier step (the old provider's servers or keys) may be relied on to be gone
// before it.
func drain(p Plan, start, end []float64) int {
	last := len(p.Steps) - 1
	if last < 1 {
		return 0
	}
	final := p.Steps[last].World
	until := end[last]
	for j := 0; j < last; j++ {
		w := p.Steps[j].World
		if !sameNames(w.ParentNS, final.ParentNS) && end[j]+float64(p.TTL.NSParent) > until {
			until = end[j] + float64(p.TTL.NSParent)
		}
		if !sameKeys(w.ParentDS, final.ParentDS) {
			ttl := p.TTL.DS
			if len(w.ParentDS) == 0 {
				ttl = p.TTL.Neg
			}
			if end[j]+float64(ttl) > until {
				until = end[j] + float64(ttl)
			}
		}
		for name, prov := range w.Providers {
			if !prov.Serving || len(prov.DNSKEY) == 0 || sameKeys(prov.DNSKEY, final.Providers[name].DNSKEY) {
				continue
			}
			if t := lastReach(p, j, name, start, end) + float64(p.TTL.DNSKEY); t > until {
				until = t
			}
		}
	}
	return int(until - end[last])
}

// evaluate classifies the answers a resolver gets from server, given where its NS and DS came from, for every
// DNSKEY RRset it could hold.
func evaluate(p Plan, i int, now float64, w World, server string, jn, jd int, keySteps []int, start, end []float64) []Violation {
	base := Violation{Step: i, StepName: p.Steps[i].Name, Server: server, NSFrom: jn, DSFrom: jd, KeysFrom: -1}
	srv := w.Providers[server]
	if !srv.Serving {
		v := base
		v.Outcome = Lame
		return []Violation{v}
	}
	ds := p.Steps[jd].World.ParentDS
	if len(ds) == 0 {
		v := base
		v.Outcome = Insecure
		return []Violation{v}
	}
	var out []Violation
	for _, jk := range keySteps {
		for name, prov := range p.Steps[jk].World.Providers {
			if !prov.Serving {
				continue
			}
			// The DNSKEY RRset must have been fetched from a server the resolver could still ask, less than one
			// DNSKEY TTL before now.
			if jk < i && lastReach(p, jk, name, start, end) <= now-float64(p.TTL.DNSKEY) {
				continue
			}
			if jk == i && name != server { // fresh DNSKEY comes from the server being asked
				continue
			}
			v := base
			v.KeysFrom, v.KeysOf = jk, name
			// The DNSKEY RRset validates when at least one of its signing keys is in it and matches a cached DS.
			keysValid := false
			for _, k := range prov.KSKs {
				keysValid = keysValid || (has(ds, k) && has(prov.DNSKEY, k))
			}
			switch {
			case srv.ZSK == "", !keysValid, !has(prov.DNSKEY, srv.ZSK):
				v.Outcome = Bogus
			default:
				v.Outcome = Secure
			}
			out = append(out, v)
		}
	}
	return out
}
