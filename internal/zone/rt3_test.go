package zone

import (
	"strings"
	"testing"
)

// L3-9: the IR type string is not checked: a pseudo-type with control characters or a line break reaches
// Zone.Pseudo and Zone.Meta[].Type, and from there lint findings (L-10 Type, L-02 message) and text output.
func TestRT3IRTypeMustBePlain(t *testing.T) {
	ir := `{"domains":[{"name":"example.test","records":[{"type":"X\nL-00 blocker forged\u001b[2J","typenum":65300,` +
		`"ttl":300,"name":"www","comparablev3":"1","filepos":"[line:1:1]","meta":{"k":"v"}}]}]}`
	z, err := ReadDNSControlIR(strings.NewReader(ir), "t", "example.test")
	if err == nil {
		t.Errorf("a type with a line break and ESC is accepted: pseudo=%q meta=%q", z.Pseudo[0].Type, z.Meta[0].Type)
	}
}
