package zone

import (
	"os"
	"strings"
	"testing"
)

// The fixture is real output of DNSControl v5.7.0 `print-ir --pretty` for testdata/dnsconfig.js (README in testdata).
func TestReadDNSControlIR(t *testing.T) {
	f, err := os.Open("testdata/print-ir-v5.7.0.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := ReadDNSControlIR(f, "print-ir-v5.7.0.json", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 11 || len(z.Pseudo) != 1 || z.Pseudo[0].Type != "ALIAS" ||
		z.Pseudo[0].Name != "apex-alias.example.test." {
		t.Fatalf("want 11 records and the ALIAS apart, got %d and %+v", len(z.Records), z.Pseudo)
	}
	if got := z.At("sip.example.test.", "A"); len(got) != 1 || got[0].TTL != 60 {
		t.Fatalf("the per-record TTL must survive: %+v", got)
	}
	if got := z.At("sub.example.test.", "DS"); len(got) != 1 {
		t.Fatal("the DS at the delegation must be read")
	}
	if _, err := ReadDNSControlIR(strings.NewReader(`{"domains":[{"name":"other.test","records":[]}]}`), "x", "example.test"); err == nil ||
		!strings.Contains(err.Error(), "other.test") {
		t.Fatalf("a missing domain must be refused, naming what is there: %v", err)
	}
	if _, err := ReadDNSControlIR(strings.NewReader("not json"), "x", "example.test"); err == nil {
		t.Fatal("non-JSON input must be refused")
	}
}
