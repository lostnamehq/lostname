package sim

import (
	"testing"

	"lostname.be/lostname/internal/config"
)

// L15: the parent's DS and NS sets compare as multisets, so a duplicate is a change.
func TestParentSetsCompareAsMultisets(t *testing.T) {
	if !sameKeys([]Key{"a", "b"}, []Key{"b", "a"}) {
		t.Error("order must not matter")
	}
	if sameKeys([]Key{"a", "a"}, []Key{"a", "b"}) || sameKeys([]Key{"a", "b"}, []Key{"a", "a"}) {
		t.Error("[a a] and [a b] must differ, in both directions")
	}
	if sameNames([]string{"ns1", "ns2"}, []string{"ns1", "ns1"}) {
		t.Error("[ns1 ns2] and [ns1 ns1] must differ")
	}
}

// M11: the lock fixtures are the shipped defaults, so a test can never pass on a value users do not get.
func TestLockFixturesMatchTheDefaults(t *testing.T) {
	c, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	for key, l := range map[string]Lock{"none": NoLock, "domain-shield": DomainShield, "domain-guard": DomainGuard} {
		d := c.Sim.Locks[key]
		if d.Latency != l.Latency || d.Window != l.Window {
			t.Errorf("%s: fixture latency %d window %d, defaults %d and %d", key, l.Latency, l.Window, d.Latency, d.Window)
		}
	}
}

// M10: the plan is not over at its last step. T0 ends with A stopping after the NS has drained: nothing is left. T1
// ends by publishing B's DS: a cached "no DS" lives one negative TTL more. Double-DS ends by removing the old DS:
// the double DS lives one DS TTL more. Every report carries the resolver assumptions.
func TestDrainAfterTheLastStep(t *testing.T) {
	tt := DefaultTTLs
	for _, c := range []struct {
		p    Plan
		want int
	}{
		{T0(tt), 0},
		{T1(tt, tt.DNSKEY+M), tt.Neg},
		{DoubleDS(tt, tt.DS+M, tt.DNSKEY+M), tt.DS},
	} {
		r := Explore(c.p)
		if r.Drain != c.want {
			t.Errorf("%s: drain %d s, want %d", c.p.Name, r.Drain, c.want)
		}
		if len(r.Assumptions) == 0 {
			t.Errorf("%s: the report must list its resolver assumptions", c.p.Name)
		}
	}
}
