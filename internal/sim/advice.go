package sim

import "fmt"

// SafePlans builds each exit model with the waits the explorer proves sufficient (model section 5b: S1 for T1, one
// DNSKEY TTL plus margin after B signs; S2 for T2, the parent NS TTL plus the DNSKEY TTL plus margin after the switch).
var SafePlans = map[string]func(TTLs) Plan{
	"T0": T0,
	"T1": func(t TTLs) Plan { return T1(t, t.DNSKEY+t.Margin) },
	"T2": func(t TTLs) Plan { return T2(t, t.NSParent+t.DNSKEY+t.Margin) },
}

// Advice is what lowering the DNSKEY TTL before an exit buys (model RL-4). The owner controls the DNSKEY TTL; the
// parent's DS and NS TTLs belong to the registry (86,400 s on .be) and are not the owner's to lower. The child's
// apex NS TTL is not in the model yet.
type Advice struct {
	Plan        string
	DNSKEYFrom  int  // seconds, the zone's DNSKEY TTL now
	DNSKEYTo    int  // seconds, the lowered TTL
	ExitBefore  int  // seconds from the first change until caches drain, at the current TTL
	ExitAfter   int  // the same at the lowered TTL
	PreStage    int  // the wait before the exit may start: one old DNSKEY TTL, so no cache holds the longer one
	SafeAtLower bool // the plan keeps the invariant at the lowered TTL (explored, not assumed)
}

// Saving is the shorter exit, in seconds: the time the zone is in transition.
func (a Advice) Saving() int { return a.ExitBefore - a.ExitAfter }

// Worth says whether pre-staging pays off in elapsed time too, the pre-stage wait included. Even when it does not,
// a shorter transition can be worth it: less time in a mixed state, a shorter registry-lock window.
func (a Advice) Worth() bool { return a.SafeAtLower && a.Saving() > a.PreStage }

func (a Advice) String() string {
	return fmt.Sprintf("%s: DNSKEY TTL %d s to %d s shortens the exit from %.1f h to %.1f h (%.1f h saved) after a "+
		"pre-stage wait of %.1f h; safe at the lower TTL: %v", a.Plan, a.DNSKEYFrom, a.DNSKEYTo,
		float64(a.ExitBefore)/3600, float64(a.ExitAfter)/3600, float64(a.Saving())/3600, float64(a.PreStage)/3600,
		a.SafeAtLower)
}

// PreStage computes the advice for one exit model, under a registry lock profile.
func PreStage(name string, t TTLs, lowDNSKEY int, l Lock) (Advice, error) {
	build, ok := SafePlans[name]
	if !ok {
		return Advice{}, fmt.Errorf("sim: no exit model %q (have T0, T1, T2)", name)
	}
	if lowDNSKEY <= 0 || lowDNSKEY > t.DNSKEY {
		return Advice{}, fmt.Errorf("sim: the lowered DNSKEY TTL must be positive and at most the current %d s", t.DNSKEY)
	}
	exit := func(t TTLs) (int, bool) {
		p := build(t)
		r := Explore(p)
		return ScheduleWith(p, l).Total + r.Drain, r.OK()
	}
	low := t
	low.DNSKEY = lowDNSKEY
	before, _ := exit(t)
	after, safe := exit(low)
	wait := t.DNSKEY
	if after == before {
		wait = 0 // nothing to gain (an unsigned exit), so nothing to pre-stage
	}
	return Advice{Plan: build(t).Name, DNSKEYFrom: t.DNSKEY, DNSKEYTo: lowDNSKEY, ExitBefore: before, ExitAfter: after,
		PreStage: wait, SafeAtLower: safe}, nil
}
