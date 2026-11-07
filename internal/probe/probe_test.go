package probe

import (
	"reflect"
	"testing"
)

// M9: each family a measurement uses gets its own probe; a host name gets both.
func TestCanariesFollowTheTargetFamilies(t *testing.T) {
	const v4, v6 = "203.0.113.1:53", "[2001:db8::53]:53"
	for _, c := range []struct {
		name    string
		targets []string
		want    []string
	}{
		{"IPv4 only", []string{"192.0.2.1:53", "198.51.100.7:53"}, []string{v4}},
		{"IPv6 only", []string{"[2001:db8::1]:53"}, []string{v6}},
		{"both", []string{"192.0.2.1:53", "[2001:db8::1]:53"}, []string{v4, v6}},
		{"host name", []string{"ns1.example.test:53"}, []string{v4, v6}},
		{"none", nil, nil},
	} {
		if got := Canaries(c.targets, v4, v6); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
