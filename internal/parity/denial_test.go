package parity

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/zone"
)

func signedWith(t *testing.T, d authtest.Denial) *zone.Zone {
	t.Helper()
	now := time.Now()
	return authtest.SignWith(t, zoneOf(t, base), authtest.NewKeys(t, "example.test"), now.Add(-time.Hour),
		now.Add(14*24*time.Hour), d)
}

// The test zone has an NXDOMAIN probe, an empty non-terminal (b) and NODATA questions: each needs its proof.
func TestDenialProofsPass(t *testing.T) {
	for _, d := range []authtest.Denial{authtest.WithNSEC, authtest.WithNSEC3} {
		z := signedWith(t, d)
		r := signedRunZones(t, z, z, authtest.None)
		if r.Verdict != "pass" {
			t.Errorf("denial %d: verdict %s, want pass: %v", d, r.Verdict, kinds(r))
		}
	}
}

func TestDenialFaultsFail(t *testing.T) {
	for _, d := range []authtest.Denial{authtest.WithNSEC, authtest.WithNSEC3} {
		z := signedWith(t, d)
		for _, c := range []struct {
			f    authtest.Fault
			kind string
		}{{authtest.NoDenial, "denial-missing"}, {authtest.WrongDenial, "denial-invalid"}} {
			r := signedRunZones(t, z, z, c.f)
			if r.Verdict != "fail" || !onlyAt(r, c.kind, "B") {
				t.Errorf("denial %d, fault %d: want fail with %s at B only, got %s %v", d, c.f, c.kind, r.Verdict, kinds(r))
			}
		}
	}
}

// One provider with NSEC and one with NSEC3, each proving its answers: a risk, not a failure.
func TestDifferentDenialTypesAreARisk(t *testing.T) {
	ref, other := signedWith(t, authtest.WithNSEC), signedWith(t, authtest.WithNSEC3)
	r := signedRunParent(t, ref, other, authtest.None, []string{parentWithDS(t, append(dsOf(ref), dsOf(other)...))})
	if !kinds(r)["denial-type-differs"] {
		t.Fatalf("want the risk denial-type-differs, got %s %v", r.Verdict, kinds(r))
	}
	for _, f := range r.Findings {
		if f.Kind == "denial-invalid" || f.Kind == "denial-missing" {
			t.Fatalf("both proofs are sound, got %s at %s", f.Kind, f.Provider)
		}
	}
}

// The NXDOMAIN proofs need every part: for NSEC3 the closest encloser's match, the next closer name covered and the
// wildcard covered; for NSEC the name covered and the wildcard covered. Each part alone must not prove anything.
func TestNXDOMAINProofNeedsEveryPart(t *testing.T) {
	const name, origin = "lostname-nx-probe.example.test.", "example.test."
	for _, d := range []authtest.Denial{authtest.WithNSEC, authtest.WithNSEC3} {
		z := signedWith(t, d)
		srv := authtest.Start(t, z, authtest.None)
		a, reason := query(srv.Addr, "tcp", question{name, "A", "nx-probe"}, time.Second, 1232, nil)
		if reason != "" || a.class != "nxdomain" || len(a.denial) == 0 {
			t.Fatalf("denial %d: want an NXDOMAIN with proof, got %s %q", d, a.class, reason)
		}
		proves := nsecProves
		if d == authtest.WithNSEC3 {
			proves = nsec3Proves
		}
		if !proves(name, rrtype("A"), true, origin, a.denial) {
			t.Fatalf("denial %d: the full proof must prove", d)
		}
		for i := range a.denial {
			part := append(append([]dns.RR{}, a.denial[:i]...), a.denial[i+1:]...)
			if len(part) > 0 && proves(name, rrtype("A"), true, origin, part) {
				t.Errorf("denial %d: the proof without %s still proves NXDOMAIN", d, a.denial[i].Header().Name)
			}
		}
	}
}

// A signed zone with a wildcard at the apex: the NXDOMAIN probe is answered from the wildcard, which needs the proof
// that the probe name itself does not exist. Without it validators reject the answer.
func TestWildcardAnswerNeedsItsProof(t *testing.T) {
	now := time.Now()
	for _, d := range []authtest.Denial{authtest.WithNSEC, authtest.WithNSEC3} {
		z := authtest.SignWith(t, zoneOf(t, base+"*          IN A     192.0.2.99\n"), authtest.NewKeys(t, "example.test"),
			now.Add(-time.Hour), now.Add(14*24*time.Hour), d)
		r := signedRunZones(t, z, z, authtest.None)
		if r.Verdict != "pass" || !kinds(r)["nx-probe-wildcard"] {
			t.Errorf("denial %d: want pass with the wildcard note, got %s %v", d, r.Verdict, kinds(r))
		}
		r = signedRunZones(t, z, z, authtest.NoWildcardProof)
		if r.Verdict != "fail" || !onlyAt(r, "wildcard-proof-missing", "B") {
			t.Errorf("denial %d: want fail with wildcard-proof-missing at B only, got %s %v", d, r.Verdict, kinds(r))
		}
	}
}

// The test zone delegates sub insecurely (no DS): a signed referral must prove that, with NSEC, NSEC3, or NSEC3
// opt-out (RFC 4035 3.1.4.1, RFC 5155 7.2.7). Without the proof, or with a chain that does not prove it, B fails.
func TestReferralNoDSProof(t *testing.T) {
	all := []authtest.Denial{authtest.WithNSEC, authtest.WithNSEC3, authtest.WithNSEC3OptOut}
	for _, d := range all {
		z := signedWith(t, d)
		if r := signedRunZones(t, z, z, authtest.None); r.Verdict != "pass" {
			t.Errorf("denial %d: verdict %s, want pass: %v", d, r.Verdict, kinds(r))
		}
		if r := signedRunZones(t, z, z, authtest.NoReferralDenial); r.Verdict != "fail" ||
			!onlyAt(r, "referral-denial-missing", "B") {
			t.Errorf("denial %d, no referral proof: want referral-denial-missing at B, got %s %v", d, r.Verdict, kinds(r))
		}
	}
	// Opt-out without the flag proves nothing: the covering NSEC3 says the cut's hash is absent, and without opt-out
	// that would mean the delegation does not exist.
	z := signedWith(t, authtest.WithNSEC3OptOut)
	stripped := []dns.RR{}
	for _, r := range z.Records {
		rr := r.RR()
		if n, ok := rr.(*dns.NSEC3); ok {
			c := *n
			c.Flags = 0
			rr = &c
		}
		stripped = append(stripped, rr)
	}
	bad, err := zone.FromRRs(z.Origin, "stripped", stripped)
	if err != nil {
		t.Fatal(err)
	}
	// The NSEC3 signatures no longer match the cleared flag, so the proof fails as invalid either way.
	if r := signedRunZones(t, z, bad, authtest.None); r.Verdict != "fail" || !onlyAt(r, "denial-invalid", "B") {
		t.Errorf("opt-out flag cleared at B: want denial-invalid at B, got %s %v", r.Verdict, kinds(r))
	}
}

// A delegation with a DS in the zone is secure: its referral carries the DS, and no no-DS proof is asked.
func TestSecureDelegationNeedsNoDenial(t *testing.T) {
	src := base + "sub IN DS 12345 13 2 " + strings.Repeat("AB", 32) + "\n"
	now := time.Now()
	z := authtest.SignWith(t, zoneOf(t, src), authtest.NewKeys(t, "example.test"), now.Add(-time.Hour),
		now.Add(14*24*time.Hour), authtest.WithNSEC3OptOut)
	r := signedRunZones(t, z, z, authtest.NoReferralDenial)
	for k := range kinds(r) {
		if k == "referral-denial-missing" {
			t.Fatalf("a secure delegation needs no no-DS proof: %v", kinds(r))
		}
	}
}

// noDSProven directly: the opt-out flag is what turns "not covered" into "insecure delegation".
func TestNoDSProvenOptOut(t *testing.T) {
	z := signedWith(t, authtest.WithNSEC3OptOut)
	var n3 []dns.RR
	for _, r := range z.Records {
		if n, ok := r.RR().(*dns.NSEC3); ok {
			n3 = append(n3, n)
		}
	}
	if !noDSProven("sub.example.test.", "example.test.", n3) {
		t.Fatal("the opt-out chain proves sub has no DS")
	}
	var cleared []dns.RR
	for _, rr := range n3 {
		c := *rr.(*dns.NSEC3)
		c.Flags = 0
		cleared = append(cleared, &c)
	}
	if noDSProven("sub.example.test.", "example.test.", cleared) {
		t.Fatal("without the opt-out flag, a covering NSEC3 proves the name absent, not insecure")
	}
}

// An NSEC at the cut proves an insecure delegation only with NS and without DS and SOA.
func TestNoDSProvenNSECBitmap(t *testing.T) {
	nsec := func(types ...uint16) []dns.RR {
		return []dns.RR{&dns.NSEC{Hdr: dns.RR_Header{Name: "sub.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
			NextDomain: "www.example.test.", TypeBitMap: types}}
	}
	for _, tc := range []struct {
		name  string
		types []uint16
		want  bool
	}{
		{"NS only", []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}, true},
		{"NS and DS: secure, not proven insecure", []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC}, false},
		{"SOA: the child's apex, not the parent's cut", []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC}, false},
		{"no NS: not a delegation", []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}, false},
	} {
		if got := noDSProven("sub.example.test.", "example.test.", nsec(tc.types...)); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
