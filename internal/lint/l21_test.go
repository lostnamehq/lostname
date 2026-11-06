package lint

import (
	"strings"
	"testing"

	"lostname.be/lostname/internal/zone"
)

// The key material is a placeholder; L-21 reads only the algorithm and digest type fields.
const algZone = `$ORIGIN example.test.
$TTL 3600
@     IN SOA    ns1.example.test. hostmaster.example.test. 1 7200 900 1209600 300
@     IN NS     ns1.example.test.
@     IN NS     ns2.example.test.
ns1   IN A      192.0.2.53
ns2   IN A      198.51.100.53
@     IN DNSKEY 257 3 1 AwEAAcw=
@     IN DNSKEY 256 3 5 AwEAAcw=
@     IN DNSKEY 257 3 13 AwEAAcw=
sub   IN NS     ns.other.invalid.
sub   IN DS     12345 13 1 0123456789ABCDEF0123456789ABCDEF01234567
sub   IN DS     12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
`

func TestL21Algorithms(t *testing.T) {
	z, err := zone.Read(strings.NewReader(algZone), "alg", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	var risks, notes int
	for _, f := range Run(z) {
		if f.Rule != "L-21" {
			continue
		}
		t.Logf("%s %s %s: %s", f.Severity, f.Name, f.Type, f.Message)
		switch f.Severity {
		case Risk:
			risks++
		case Note:
			notes++
		}
	}
	// RSAMD5 key and the SHA-1 DS are risks; the RSASHA1 key is a note; ECDSA (13) and the SHA-256 DS pass.
	if risks != 2 || notes != 1 {
		t.Fatalf("want 2 risks and 1 note, got %d and %d", risks, notes)
	}
}
