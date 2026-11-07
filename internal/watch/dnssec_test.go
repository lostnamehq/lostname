package watch

import (
	"testing"

	"lostname.be/lostname/internal/parity"
)

func TestDNSSECStatusPerProvider(t *testing.T) {
	ps := []parity.Provider{{Name: "secure"}, {Name: "bogus"}, {Name: "nods"}, {Name: "unsigned"}, {Name: "blind"}}
	rep := parity.Report{
		SignatureExpiry: map[string]int64{"secure": 1, "bogus": 1, "nods": 1, "blind": 1},
		Findings: []parity.Finding{
			{Severity: parity.Fail, Kind: "rrsig-invalid", Provider: "bogus"},
			{Severity: parity.Note, Kind: "parent-no-ds", Provider: "nods"},
			{Severity: parity.Fail, Kind: "rrset-differs", Provider: "secure"}, // not a DNSSEC failure
		},
		Gaps: []parity.Gap{{Provider: "blind"}},
	}
	want := map[string]string{"secure": "secure", "bogus": "bogus", "nods": "insecure", "unsigned": "insecure",
		"blind": "indeterminate"}
	got := dnssecStatus(rep, ps)
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: %s, want %s", p, got[p], w)
		}
	}
}
