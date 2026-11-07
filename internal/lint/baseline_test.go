package lint

import "testing"

func TestDiffAgainstABaseline(t *testing.T) {
	a := Finding{"L-08", Blocker, "www.example.test.", "CNAME", "CNAME next to other data (TXT)", "RFC 1034 3.6.2"}
	b := Finding{"L-07", Note, "example.test.", "CAA", "no accounturi", "RFC 8657"}
	c := Finding{"L-15", Risk, "example.test.", "NS", "fewer than two NS", "RFC 1034 4.1"}
	raised := b
	raised.Severity = Risk
	lowered := c
	lowered.Severity = Note

	for _, tc := range []struct {
		name               string
		base, now          []Finding
		wantWorse, wantFix int
	}{
		{"unchanged", []Finding{a, b}, []Finding{a, b}, 0, 0},
		{"new finding", []Finding{a}, []Finding{a, b}, 1, 0},
		{"fixed finding", []Finding{a, b}, []Finding{a}, 0, 1},
		{"severity raised", []Finding{b}, []Finding{raised}, 1, 0},
		{"severity lowered", []Finding{c}, []Finding{lowered}, 0, 0},
		{"empty baseline", nil, []Finding{a, b, c}, 3, 0},
		{"duplicate in baseline fixed once", []Finding{a, a}, nil, 0, 1},
	} {
		worse, fixed := Diff(tc.base, tc.now)
		if len(worse) != tc.wantWorse || len(fixed) != tc.wantFix {
			t.Errorf("%s: %d worse and %d fixed, want %d and %d", tc.name, len(worse), len(fixed), tc.wantWorse, tc.wantFix)
		}
	}
}

// Red team 2, P5: a baseline cannot turn "not a zone" into a pass.
func TestBaselineNeverHidesL00(t *testing.T) {
	notAZone := Finding{"L-00", Blocker, "example.test.", "", "the zone has no records", "RFC 1035 5.2"}
	worse, _ := Diff([]Finding{notAZone}, []Finding{notAZone})
	if len(worse) != 1 {
		t.Fatal("an L-00 finding must stay in the report whatever the baseline")
	}
}
