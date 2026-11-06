package zone

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzRead feeds arbitrary text to the zone-file reader. It must never panic, and a zone it accepts must survive a
// write and re-read with the same records (the round trip `fetch` relies on).
func FuzzRead(f *testing.F) {
	f.Add("$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns.example.test. h.example.test. 1 2 3 4 5\n@ IN NS ns.example.test.\nns IN A 192.0.2.1\n")
	f.Add("www.example.test. 300 IN TXT \"a\" \"b\"\nexample.test. 300 IN CAA 0 issue \"ca.example\"\n")
	f.Add("$INCLUDE /etc/passwd\n")
	f.Add("x 1 IN CNAME y.example.test.\nx 1 IN A 192.0.2.2\n")
	f.Fuzz(func(t *testing.T, text string) {
		z, err := Read(strings.NewReader(text), "fuzz", "example.test")
		if err != nil {
			return
		}
		var buf bytes.Buffer
		if err := z.WriteZoneFile(&buf); err != nil {
			t.Fatalf("write: %v", err)
		}
		z2, err := Read(&buf, "roundtrip", "example.test")
		if err != nil {
			t.Fatalf("re-read of written zone failed: %v\n%s", err, buf.String())
		}
		if len(z2.Records) != len(z.Records) {
			t.Fatalf("round trip changed the record count: %d -> %d", len(z.Records), len(z2.Records))
		}
	})
}
