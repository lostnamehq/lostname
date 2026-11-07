package lint

import (
	"os"
	"testing"

	"lostname.be/lostname/internal/target"
	"lostname.be/lostname/internal/zone"
)

func irZone(t *testing.T) *zone.Zone {
	t.Helper()
	f, err := os.Open("../zone/testdata/print-ir-v5.7.0.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := zone.ReadDNSControlIR(f, "print-ir-v5.7.0.json", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func byRule(fs []Finding) map[string][]Finding {
	m := map[string][]Finding{}
	for _, f := range fs {
		m[f.Rule+" "+string(f.Severity)+" "+f.Type] = append(m[f.Rule+" "+string(f.Severity)+" "+f.Type], f)
	}
	return m
}

// The fixture config (A, AAAA, MX, TXT, CNAME, CAA, SRV, NS, DS, an ALIAS; no SOA) against four real targets.
func TestTargetRules(t *testing.T) {
	z := irZone(t)
	for _, c := range []struct {
		provider string
		want     []string // rule, severity and type of every expected finding
	}{
		{"BIND", []string{"L-03 risk ALIAS"}},
		{"HETZNER_V2", []string{"L-03 blocker ALIAS"}},
		{"SCALEWAY", []string{"L-02 blocker DS", "L-03 risk ALIAS"}},
		{"POWERDNS", []string{"L-01 blocker SOA", "L-03 risk ALIAS"}},
	} {
		p, err := target.Lookup(c.provider)
		if err != nil {
			t.Fatal(err)
		}
		got := byRule(RunTarget(z, p))
		for _, w := range c.want {
			if len(got[w]) != 1 {
				t.Errorf("%s: want one %q, got %v", c.provider, w, got)
			}
			delete(got, w)
		}
		if len(got) != 0 {
			t.Errorf("%s: unexpected findings %v", c.provider, got)
		}
	}
}
