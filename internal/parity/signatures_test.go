package parity

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/zone"
)

// signedRun serves base signed with k (window from-to) at A and B, B with fault f, and runs parity against the
// signed zone file.
func signedRun(t *testing.T, k *authtest.Keys, from, to time.Time, f authtest.Fault) Report {
	t.Helper()
	z := authtest.Sign(t, zoneOf(t, base), k, from, to)
	return signedRunZones(t, z, z, f)
}

func signedRunZones(t *testing.T, ref, served *zone.Zone, f authtest.Fault) Report {
	t.Helper()
	return signedRunParent(t, ref, served, f, []string{parentWithDS(t, dsOf(ref))})
}

func signedRunParent(t *testing.T, ref, served *zone.Zone, f authtest.Fault, parent []string) Report {
	t.Helper()
	a := authtest.Start(t, ref, authtest.None)
	b := authtest.Start(t, served, f)
	o := opts(t, "T0", quiet(t))
	o.Parent = parent
	r := mustRun(t, ref, []Provider{{"A", []string{a.Addr}}, {"B", []string{b.Addr}}}, o)
	for _, x := range r.Findings {
		t.Logf("%s %s %s %s %s: %s", x.Severity, x.Kind, x.Name, x.Type, x.Provider, x.Detail)
	}
	return r
}

func onlyAt(r Report, kind, provider string) bool {
	found := false
	for _, f := range r.Findings {
		if f.Kind == kind {
			if f.Provider != provider {
				return false
			}
			found = true
		}
	}
	return found
}

func TestValidSignaturesPass(t *testing.T) {
	now := time.Now()
	expires := now.Add(14 * 24 * time.Hour)
	r := signedRun(t, authtest.NewKeys(t, "example.test"), now.Add(-time.Hour), expires, authtest.None)
	if r.Verdict != "pass" {
		t.Fatalf("verdict %s, want pass", r.Verdict)
	}
	for _, p := range []string{"A", "B"} {
		if r.SignatureExpiry[p] != expires.Unix() {
			t.Errorf("%s: earliest signature expiry %d, want %d", p, r.SignatureExpiry[p], expires.Unix())
		}
	}
}

func TestSignatureFaultsFail(t *testing.T) {
	now := time.Now()
	k := authtest.NewKeys(t, "example.test")
	for _, c := range []struct {
		name string
		f    authtest.Fault
		kind string
	}{
		{"corrupted", authtest.BadSig, "rrsig-invalid"},
		{"stripped", authtest.NoSig, "rrsig-missing"},
	} {
		r := signedRun(t, k, now.Add(-time.Hour), now.Add(14*24*time.Hour), c.f)
		if r.Verdict != "fail" || !onlyAt(r, c.kind, "B") {
			t.Errorf("%s: want fail with %s at B only, got %s %v", c.name, c.kind, r.Verdict, kinds(r))
		}
	}
}

func TestSignatureWindow(t *testing.T) {
	now := time.Now()
	k := authtest.NewKeys(t, "example.test")
	for _, c := range []struct {
		name     string
		from, to time.Time
		verdict  string
		kind     string
	}{
		{"expired", now.Add(-30 * 24 * time.Hour), now.Add(-time.Hour), "fail", "rrsig-expired"},
		{"not yet valid", now.Add(time.Hour), now.Add(30 * 24 * time.Hour), "fail", "rrsig-not-yet-valid"},
		{"expiring soon", now.Add(-time.Hour), now.Add(time.Hour), "pass", "rrsig-expires-soon"},
	} {
		r := signedRun(t, k, c.from, c.to, authtest.None)
		if r.Verdict != c.verdict || !kinds(r)[c.kind] {
			t.Errorf("%s: want %s with %s, got %s %v", c.name, c.verdict, c.kind, r.Verdict, kinds(r))
		}
	}
}

// A server whose signatures come from a key it does not publish fails, even though the signatures themselves are
// sound: a resolver cannot validate them.
func TestSignatureByUnpublishedKeyFails(t *testing.T) {
	now := time.Now()
	from, to := now.Add(-time.Hour), now.Add(14*24*time.Hour)
	ref := authtest.Sign(t, zoneOf(t, base), authtest.NewKeys(t, "example.test"), from, to)
	other := authtest.Sign(t, zoneOf(t, base), authtest.NewKeys(t, "example.test"), from, to)
	// B serves its own signatures but the reference's DNSKEY RRset.
	var rrs []zone.Record
	for _, r := range other.Records {
		if r.Type != "DNSKEY" && !(r.Type == "RRSIG" && r.Name == other.Origin && covers(r, "DNSKEY")) {
			rrs = append(rrs, r)
		}
	}
	for _, r := range ref.Records {
		if r.Type == "DNSKEY" || (r.Type == "RRSIG" && covers(r, "DNSKEY")) {
			rrs = append(rrs, r)
		}
	}
	served := mixed(t, ref.Origin, rrs)
	r := signedRunZones(t, ref, served, authtest.None)
	if r.Verdict != "fail" || !onlyAt(r, "rrsig-unknown-key", "B") {
		t.Fatalf("want fail with rrsig-unknown-key at B, got %s %v", r.Verdict, kinds(r))
	}
}

func covers(r zone.Record, typ string) bool {
	s, ok := r.RR().(*dns.RRSIG)
	return ok && s.TypeCovered == dns.StringToType[typ]
}

func mixed(t *testing.T, origin string, recs []zone.Record) *zone.Zone {
	t.Helper()
	var rrs []dns.RR
	for _, r := range recs {
		rrs = append(rrs, r.RR())
	}
	z, err := zone.FromRRs(origin, "mixed", rrs)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// dsOf returns the SHA-256 DS of every KSK in z's apex DNSKEY RRset.
func dsOf(z *zone.Zone) []*dns.DS {
	var out []*dns.DS
	for _, r := range z.At(z.Origin, "DNSKEY") {
		if k := r.RR().(*dns.DNSKEY); k.Flags&dns.SEP != 0 {
			out = append(out, k.ToDS(dns.SHA256))
		}
	}
	return out
}

// parentWithDS serves the parent zone "test." delegating example.test with the given DS RRset (none: unsigned).
func parentWithDS(t *testing.T, ds []*dns.DS) string {
	t.Helper()
	src := "$ORIGIN test.\n$TTL 3600\n@ IN SOA ns.test. h.test. 1 7200 900 1209600 300\n@ IN NS ns.test.\n" +
		"ns IN A 192.0.2.1\nexample IN NS ns1.example.test.\n"
	for _, d := range ds {
		src += d.String() + "\n"
	}
	z, err := zone.Read(strings.NewReader(src), "parent", "test")
	if err != nil {
		t.Fatal(err)
	}
	return authtest.Start(t, z, authtest.None).Addr
}

func signedZone(t *testing.T) *zone.Zone {
	t.Helper()
	now := time.Now()
	return authtest.Sign(t, zoneOf(t, base), authtest.NewKeys(t, "example.test"), now.Add(-time.Hour), now.Add(14*24*time.Hour))
}

func TestDSForAnotherKeyFails(t *testing.T) {
	z := signedZone(t)
	r := signedRunParent(t, z, z, authtest.None, []string{parentWithDS(t, dsOf(signedZone(t)))})
	if r.Verdict != "fail" || !kinds(r)["ds-no-matching-key"] {
		t.Fatalf("want fail with ds-no-matching-key, got %s %v", r.Verdict, kinds(r))
	}
}

func TestSignedZoneWithoutParentGivesNoVerdict(t *testing.T) {
	z := signedZone(t)
	r := signedRunParent(t, z, z, authtest.None, nil)
	found := false
	for _, g := range r.Gaps {
		found = found || strings.Contains(g.Reason, "--parent")
	}
	if r.Verdict != "no_verdict" || !found {
		t.Fatalf("want no_verdict naming --parent, got %s, gaps %v", r.Verdict, r.Gaps)
	}
}

func TestParentWithoutDSIsANote(t *testing.T) {
	z := signedZone(t)
	r := signedRunParent(t, z, z, authtest.None, []string{parentWithDS(t, nil)})
	if r.Verdict != "pass" || !kinds(r)["parent-no-ds"] {
		t.Fatalf("want pass with the note parent-no-ds, got %s %v", r.Verdict, kinds(r))
	}
}

// B serves the DS key but drops the signature over the DNSKEY RRset: the chain breaks at B only.
func TestDNSKEYNotSignedByDSKeyFails(t *testing.T) {
	z := signedZone(t)
	var keep []zone.Record
	for _, r := range z.Records {
		if !(r.Type == "RRSIG" && covers(r, "DNSKEY")) {
			keep = append(keep, r)
		}
	}
	r := signedRunZones(t, z, mixed(t, z.Origin, keep), authtest.None)
	if r.Verdict != "fail" || !onlyAt(r, "dnskey-not-signed-by-ds-key", "B") {
		t.Fatalf("want fail with dnskey-not-signed-by-ds-key at B only, got %s %v", r.Verdict, kinds(r))
	}
}
