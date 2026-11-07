package zone

import (
	"strings"
	"testing"
)

func TestRedteamGenerateBypass(t *testing.T) {
	head := "$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns1 h 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
	for _, gen := range []string{
		"$GENERATE 0-65535 h$ A 192.0.2.2\n",
		"\r$GENERATE 0-65535 h$ A 192.0.2.2\n",
		"$GEN\rERATE 0-65535 h$ A 192.0.2.2\n",
		"($GENERATE 0-65535 h$ A 192.0.2.2)\n",
		"$GEN()ERATE 0-65535 h$ A 192.0.2.2\n",
	} {
		z, err := Read(strings.NewReader(head+gen), "t.zone", "example.test")
		if err != nil {
			t.Logf("%q: refused: %v", gen, err)
			continue
		}
		t.Errorf("%q: ACCEPTED, %d records", gen, len(z.Records))
	}
}
