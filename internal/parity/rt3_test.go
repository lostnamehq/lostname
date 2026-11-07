package parity

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/zone"
)

// Red team round 3.

func cdsLine(tag string) string {
	return "@ IN CDS " + tag + " 13 2 " + strings.Repeat("AB", 32) + "\n"
}

func cdsKinds(r Report) map[string]int {
	got := map[string]int{}
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Kind, "cds-") {
			got[f.Kind+"/"+string(f.Severity)+"/"+f.Provider]++
		}
	}
	return got
}

// P3-1: the reference publishes no CDS; B and C publish different sets. A scanning parent installs either: fail.
func TestRT3CDSNonReferenceProvidersDiffer(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	b := authtest.Start(t, zoneOf(t, base+cdsLine("11111")), authtest.None)
	c := authtest.Start(t, zoneOf(t, base+cdsLine("22222")), authtest.None)
	r := mustRun(t, zoneOf(t, base), []Provider{{"A", []string{a.Addr}}, {"B", []string{b.Addr}}, {"C", []string{c.Addr}}},
		opts(t, "T0", quiet(t)))
	t.Logf("verdict %s, cds %v", r.Verdict, cdsKinds(r))
	if r.Verdict == "pass" || !kinds(r)["cds-differs"] {
		t.Errorf("BREAK: B and C publish different CDS sets, want cds-differs/fail, got %s %v", r.Verdict, cdsKinds(r))
	}
}

// P3-2: B's server refuses (or drops) CDS/CDNSKEY queries while answering everything else. compareCDS skips it
// silently: no gap, no finding, verdict pass. A is publishing CDS, so B's set is unknown: no verdict at least.
func TestRT3CDSUnansweredHidesGap(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base+cdsLine("11111")), authtest.None)
	up := authtest.Start(t, zoneOf(t, base+cdsLine("22222")), authtest.None)
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, _ string) *dns.Msg {
		if qt := req.Question[0].Qtype; qt == dns.TypeCDS || qt == dns.TypeCDNSKEY {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			return m
		}
		return resp
	})
	r := runRT(t, zoneOf(t, base), opts(t, "T0", quiet(t)), a.Addr, b)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: B refuses CDS (it serves a different set), verdict pass with no gap: %v", cdsKinds(r))
	}
}

// P3-3: CDS is asked over TCP only. B serves the same CDS as A over TCP and a different one over UDP (where parent
// scanners usually ask). Parity passes.
func TestRT3CDSUDPDiffersFromTCP(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base+cdsLine("11111")), authtest.None)
	up := authtest.Start(t, zoneOf(t, base+cdsLine("11111")), authtest.None)
	other, _ := dns.NewRR("example.test. 3600 IN CDS 22222 13 2 " + strings.Repeat("CD", 32))
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, network string) *dns.Msg {
		if network == "udp" && req.Question[0].Qtype == dns.TypeCDS {
			resp.Answer = []dns.RR{other}
		}
		return resp
	})
	r := runRT(t, zoneOf(t, base), opts(t, "T0", quiet(t)), a.Addr, b)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: B's CDS over UDP (22222) differs from TCP (11111), verdict pass")
	}
}

// P3-4: CDS signatures are never checked. B serves the same CDS as A with a corrupted RRSIG; a parent that validates
// (RFC 7344 requires the CDS RRset to be signed) ignores B's set. Parity passes.
func TestRT3CDSBadSignatureAccepted(t *testing.T) {
	now := time.Now()
	z := authtest.SignWith(t, zoneOf(t, base+cdsLine("11111")), authtest.NewKeys(t, "example.test"),
		now.Add(-time.Hour), now.Add(14*24*time.Hour), authtest.WithNSEC)
	a := authtest.Start(t, z, authtest.None)
	up := authtest.Start(t, z, authtest.None)
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, _ string) *dns.Msg {
		if req.Question[0].Qtype == dns.TypeCDS {
			for _, rr := range resp.Answer {
				if s, ok := rr.(*dns.RRSIG); ok {
					s.Signature = "AAAA" + s.Signature[4:]
				}
			}
		}
		return resp
	})
	o := opts(t, "T0", quiet(t))
	o.Parent = []string{parentWithDS(t, dsOf(z))}
	r := runRT(t, z, o, a.Addr, b)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: B's CDS RRSIG is corrupted, verdict pass")
	}
}

// Sound check: CDS sets that differ only in order, owner case and TTL are the same set.
func TestRT3CDSCaseOrderTTLAreEqual(t *testing.T) {
	two := cdsLine("11111") + cdsLine("22222")
	a := authtest.Start(t, zoneOf(t, base+two), authtest.None)
	up := authtest.Start(t, zoneOf(t, base+two), authtest.None)
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, _ string) *dns.Msg {
		if req.Question[0].Qtype == dns.TypeCDS && len(resp.Answer) == 2 {
			resp.Answer[0], resp.Answer[1] = resp.Answer[1], resp.Answer[0]
			for _, rr := range resp.Answer {
				rr.Header().Name = "EXAMPLE.Test."
				rr.Header().Ttl = 60
			}
		}
		return resp
	})
	r := runRT(t, zoneOf(t, base), opts(t, "T0", quiet(t)), a.Addr, b)
	if len(cdsKinds(r)) != 0 {
		t.Errorf("false cds finding: %v", cdsKinds(r))
	}
}

// Sound check: RFC 8078 delete records compare as sets like any other.
func TestRT3CDSDelete(t *testing.T) {
	del := "@ IN CDS 0 0 0 00\n"
	for _, tc := range []struct{ a, b, want string }{
		{del, del, ""}, {del, cdsLine("11111"), "cds-differs/fail/B"}, {del, "", "cds-one-sided/risk/B"},
	} {
		sa := authtest.Start(t, zoneOf(t, base+tc.a), authtest.None)
		sb := authtest.Start(t, zoneOf(t, base+tc.b), authtest.None)
		r := runRT(t, zoneOf(t, base), opts(t, "T0", quiet(t)), sa.Addr, sb.Addr)
		got := cdsKinds(r)
		if (tc.want == "" && len(got) != 0) || (tc.want != "" && got[tc.want] != 1) {
			t.Errorf("%q vs %q: %v, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// P3-5: an NSEC3 whose owner is not directly under the zone apex (here <hash(sub)>.sub.example.test., below the cut)
// is not part of this zone's chain (RFC 5155 section 3: owner = hash label + zone name); validators ignore it.
// miekg Match only checks that the owner's suffix is an ancestor of the name, and Verify only a string suffix of the
// signer, so the forged record proves "no DS" and the run passes.
func TestRT3NSEC3OwnerBelowApexAccepted(t *testing.T) {
	now := time.Now()
	k := authtest.NewKeys(t, "example.test")
	z := authtest.SignWith(t, zoneOf(t, base), k, now.Add(-time.Hour), now.Add(14*24*time.Hour), authtest.WithNSEC3)
	cut := "sub.example.test."
	h := dns.HashName(cut, dns.SHA1, 0, "")
	forged := &dns.NSEC3{Hdr: dns.RR_Header{Name: strings.ToLower(h) + "." + cut, Rrtype: dns.TypeNSEC3,
		Class: dns.ClassINET, Ttl: 300}, Hash: dns.SHA1, Flags: 0, Iterations: 0, SaltLength: 0, Salt: "",
		HashLength: 20, NextDomain: h[:len(h)-1] + "0", TypeBitMap: []uint16{dns.TypeNS}}
	if !forged.Match(cut) {
		t.Fatal("setup: forged NSEC3 must Match the cut")
	}
	if noDSProven(cut, "example.test.", []dns.RR{forged}) {
		t.Errorf("BREAK (unit): NSEC3 owned below the apex (%s) proves no DS", forged.Hdr.Name)
	}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: forged.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		Algorithm: k.ZSK.Algorithm, SignerName: "example.test.", KeyTag: k.ZSK.KeyTag(),
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(24 * time.Hour).Unix())}
	if err := sig.Sign(unexported(k, "zskPriv"), []dns.RR{forged}); err != nil {
		t.Fatal(err)
	}
	a := authtest.Start(t, z, authtest.None)
	up := authtest.Start(t, z, authtest.None)
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, _ string) *dns.Msg {
		if strings.EqualFold(req.Question[0].Name, cut) && req.Question[0].Qtype == dns.TypeNS {
			var ns []dns.RR
			for _, rr := range resp.Ns {
				switch v := rr.(type) {
				case *dns.NSEC3:
					continue
				case *dns.RRSIG:
					if v.TypeCovered == dns.TypeNSEC3 {
						continue
					}
				}
				ns = append(ns, rr)
			}
			resp.Ns = append(ns, forged, sig)
		}
		return resp
	})
	o := opts(t, "T0", quiet(t))
	o.Parent = []string{parentWithDS(t, dsOf(z))}
	r := runRT(t, z, o, a.Addr, b)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: B proves sub has no DS with an NSEC3 outside the zone's chain, verdict pass")
	}
}

// Sound check: a referral proof whose RRSIG has expired, or is by an unrelated key, fails.
func TestRT3ReferralProofExpiredOrForeignKey(t *testing.T) {
	now := time.Now()
	k := authtest.NewKeys(t, "example.test")
	z := authtest.SignWith(t, zoneOf(t, base), k, now.Add(-time.Hour), now.Add(14*24*time.Hour), authtest.WithNSEC)
	cut := "sub.example.test."
	for _, mode := range []string{"expired", "foreign"} {
		other := authtest.NewKeys(t, "example.test")
		a := authtest.Start(t, z, authtest.None)
		up := authtest.Start(t, z, authtest.None)
		b := proxy(t, up.Addr, func(req, resp *dns.Msg, _ string) *dns.Msg {
			if !strings.EqualFold(req.Question[0].Name, cut) {
				return resp
			}
			var nsec *dns.NSEC
			var keep []dns.RR
			for _, rr := range resp.Ns {
				if n, ok := rr.(*dns.NSEC); ok {
					nsec = n
				}
				if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeNSEC {
					continue
				}
				keep = append(keep, rr)
			}
			if nsec == nil {
				return resp
			}
			signer, priv := k.ZSK, unexported(k, "zskPriv")
			inc, exp := now.Add(-48*time.Hour), now.Add(-24*time.Hour)
			if mode == "foreign" {
				signer, priv = other.ZSK, unexported(other, "zskPriv")
				inc, exp = now.Add(-time.Hour), now.Add(24*time.Hour)
			}
			s := &dns.RRSIG{Hdr: dns.RR_Header{Name: nsec.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
				Algorithm: signer.Algorithm, SignerName: "example.test.", KeyTag: signer.KeyTag(),
				Inception: uint32(inc.Unix()), Expiration: uint32(exp.Unix())}
			if err := s.Sign(priv, []dns.RR{nsec}); err != nil {
				return resp
			}
			resp.Ns = append(keep, s)
			return resp
		})
		o := opts(t, "T0", quiet(t))
		o.Parent = []string{parentWithDS(t, dsOf(z))}
		r := runRT(t, z, o, a.Addr, b)
		if r.Verdict != "fail" || !onlyAt(r, "denial-invalid", "B") {
			t.Errorf("%s: want denial-invalid at B, got %s %v", mode, r.Verdict, kinds(r))
		}
	}
}

// P3-6: shared fate between providers that name the same server by host name (or by a host name and its address):
// hostIP gives nil and nothing is reported, not even a note that L-20 could not be checked.
func TestRT3SharedFateHostNames(t *testing.T) {
	fs := sharedFate("example.test.", []Provider{{"A", []string{"ns1.shared.example:53"}},
		{"B", []string{"ns1.shared.example:53"}}})
	if len(fs) == 0 {
		t.Errorf("BREAK: both providers use ns1.shared.example:53, no shared-fate finding")
	}
}

// Sound check: IPv4-mapped IPv6 and plain IPv4 of one server are one address.
func TestRT3SharedFateMapped(t *testing.T) {
	fs := sharedFate("example.test.", []Provider{{"A", []string{"[::ffff:192.0.2.1]:53"}}, {"B", []string{"192.0.2.1:53"}}})
	if len(fs) != 1 {
		t.Errorf("mapped: %+v", fs)
	}
}

var _ = zone.Zone{}

// P3-8: each provider publishes a CDS for one key and a CDNSKEY for another. Both providers agree, so compareCDS is
// silent, but a parent that reads CDNSKEY installs a different DS than one that reads CDS (RFC 7344: when both are
// published they must describe the same keys). Expected: a finding.
func TestRT3CDSAndCDNSKEYDisagree(t *testing.T) {
	k1, k2 := authtest.NewKeys(t, "example.test"), authtest.NewKeys(t, "example.test")
	cds := k1.KSK.ToDS(dns.SHA256).ToCDS()
	cdnskey := k2.KSK.ToCDNSKEY()
	extra := cds.String() + "\n" + cdnskey.String() + "\n"
	sa := authtest.Start(t, zoneOf(t, base+extra), authtest.None)
	sb := authtest.Start(t, zoneOf(t, base+extra), authtest.None)
	r := runRT(t, zoneOf(t, base), opts(t, "T0", quiet(t)), sa.Addr, sb.Addr)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: CDS names key %d, CDNSKEY key %d, at both providers: verdict pass", cds.KeyTag,
			cdnskey.KeyTag())
	}
}
