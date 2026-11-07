package target

import "testing"

func TestCapabilities(t *testing.T) {
	if s := From(); s.Tag == "" || len(s.Commit) != 40 {
		t.Fatalf("the data must name its pinned source, got %+v", s)
	}
	h, err := Lookup("hetzner_v2")
	if err != nil {
		t.Fatal(err)
	}
	for typ, want := range map[string]Support{"A": Yes, "TXT": Yes, "CAA": Yes, "ALIAS": No, "SSHFP": No} {
		if got := h.Supports(typ); got != want {
			t.Errorf("HETZNER_V2 %s: %s, want %s", typ, got, want)
		}
	}
	if o, _ := Lookup("OVH"); o.Supports("LOC") != Unknown {
		t.Error("OVH LOC is a question mark in the matrix: unknown")
	}
	if p, _ := Lookup("POWERDNS"); p.NeedsSOA() == "" {
		t.Error("POWERDNS needs an SOA in the config (M0 F2)")
	}
	if h.Feature("AUTODNSSEC") != No {
		t.Error("HETZNER_V2 cannot sign through DNSControl")
	}
	if p, _ := Lookup("POWERDNS"); p.Feature("AUTODNSSEC") != Yes {
		t.Error("POWERDNS can sign through DNSControl")
	}
	if h.NeedsSOA() != "" {
		t.Error("HETZNER_V2 has no SOA requirement on record")
	}
	if _, err := Lookup("NO_SUCH_PROVIDER"); err == nil {
		t.Error("an unknown provider must be refused")
	}
}
