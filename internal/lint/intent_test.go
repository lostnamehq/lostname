package lint

import (
	"os"
	"strings"
	"testing"

	"lostname.be/lostname/internal/target"
	"lostname.be/lostname/internal/zone"
)

func readIR(t *testing.T, path string) *zone.Zone {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := zone.ReadDNSControlIR(f, path, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// L-04, with real print-ir output with and without AUTODNSSEC_ON.
func TestDNSSECIntent(t *testing.T) {
	plain := readIR(t, "../zone/testdata/print-ir-v5.7.0.json")
	on := readIR(t, "../zone/testdata/print-ir-v5.7.0-autodnssec.json")
	if plain.DNSSECIntent != "" || on.DNSSECIntent != "on" {
		t.Fatalf("intent read as %q and %q", plain.DNSSECIntent, on.DNSSECIntent)
	}
	signed, err := zone.Read(strings.NewReader("$ORIGIN example.test.\n@ 3600 IN DNSKEY 257 3 13 AwEAAcw=\n"), "now", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	hetzner, _ := target.Lookup("HETZNER_V2")
	powerdns, _ := target.Lookup("POWERDNS")
	for _, c := range []struct {
		name    string
		cfg     *zone.Zone
		current *zone.Zone
		p       *target.Provider
		want    int
	}{
		{"signed now, no intent", plain, signed, nil, 1},
		{"signed now, intent on, target can sign", on, signed, &powerdns, 0},
		{"intent on, target cannot sign", on, nil, &hetzner, 1},
		{"no current zone, no target", plain, nil, nil, 0},
	} {
		if got := len(RunIntent(c.cfg, c.current, c.p)); got != c.want {
			t.Errorf("%s: %d L-04 finding(s), want %d", c.name, got, c.want)
		}
	}
}
