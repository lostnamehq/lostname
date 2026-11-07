package parity

import (
	"strings"
	"testing"
	"time"

	"lostname.be/lostname/internal/authtest"
)

// Parity over IPv6: providers reached on the IPv6 loopback, alone and next to IPv4, with and without a difference,
// and a signed zone with its chain (DNSKEY over UDP and TCP, the parent's DS) all over IPv6.
func TestParityOverIPv6(t *testing.T) {
	z := zoneOf(t, base)
	a6 := authtest.Start6(t, z, authtest.None)
	b6 := authtest.Start6(t, z, authtest.None)
	a4 := authtest.Start(t, z, authtest.None)
	if !strings.HasPrefix(a6.Addr, "[::1]:") {
		t.Fatalf("want an IPv6 server, got %s", a6.Addr)
	}
	for _, c := range []struct {
		name string
		a, b string
	}{{"both IPv6", a6.Addr, b6.Addr}, {"IPv4 and IPv6", a4.Addr, b6.Addr}} {
		r := mustRun(t, z, []Provider{{"A", []string{c.a}}, {"B", []string{c.b}}}, opts(t, "T0", quiet(t)))
		if r.Verdict != "pass" {
			t.Errorf("%s: verdict %s, gaps %v", c.name, r.Verdict, r.Gaps)
		}
	}
	changed := authtest.Start6(t, zoneOf(t, strings.Replace(base, "192.0.2.25", "192.0.2.99", 1)), authtest.None)
	r := mustRun(t, z, []Provider{{"A", []string{a6.Addr}}, {"B", []string{changed.Addr}}}, opts(t, "T0", quiet(t)))
	if r.Verdict != "fail" || !kinds(r)["rrset-differs"] {
		t.Errorf("a difference over IPv6: %s %v", r.Verdict, kinds(r))
	}

	now := time.Now()
	sz := authtest.Sign(t, z, authtest.NewKeys(t, "example.test"), now.Add(-time.Hour), now.Add(14*24*time.Hour))
	s1, s2 := authtest.Start6(t, sz, authtest.None), authtest.Start6(t, sz, authtest.None)
	o := opts(t, "T0", quiet(t))
	o.Parent = []string{parentWithDS(t, dsOf(sz))}
	r = mustRun(t, sz, []Provider{{"A", []string{s1.Addr}}, {"B", []string{s2.Addr}}}, o)
	if r.Verdict != "pass" {
		t.Errorf("a signed zone over IPv6: %s %v gaps %v", r.Verdict, kinds(r), r.Gaps)
	}
}
