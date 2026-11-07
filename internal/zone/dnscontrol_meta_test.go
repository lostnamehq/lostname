package zone

import (
	"strings"
	"testing"
)

// Metadata keys reach lint messages, so a key that is not a plain name is refused, like a record name.
func TestIRMetadataKeys(t *testing.T) {
	ir := func(key string) string {
		return `{"domains":[{"name":"example.test","records":[{"type":"A","typenum":1,"ttl":300,"name":"www",` +
			`"comparablev3":"192.0.2.1","filepos":"[line:1:1]","meta":{"` + key + `":"on"}}]}]}`
	}
	z, err := ReadDNSControlIR(strings.NewReader(ir("cloudflare_proxy")), "t", "example.test")
	if err != nil || len(z.Meta) != 1 || z.Meta[0].Keys[0] != "cloudflare_proxy" || z.Meta[0].Name != "www.example.test." {
		t.Fatalf("a plain key is kept: %v %+v", err, z)
	}
	for _, bad := range []string{"a b", "x\u202e", strings.Repeat("k", 65), ""} {
		if _, err := ReadDNSControlIR(strings.NewReader(ir(bad)), "t", "example.test"); err == nil {
			t.Errorf("metadata key %q accepted", bad)
		}
	}
}
