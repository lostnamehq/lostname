package parity

import (
	"crypto"
	"encoding/base64"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/zone"
)

// proxy serves on loopback UDP+TCP, forwards each query over TCP to upstream, and lets mutate rewrite the reply.
// network is "udp" or "tcp" (how the client asked).
func proxy(t *testing.T, upstream string, mutate func(req, resp *dns.Msg, network string) *dns.Msg) string {
	t.Helper()
	var pc net.PacketConn
	var l net.Listener
	for i := 0; i < 2000 && pc == nil; i++ {
		var err error
		if l, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if pc, err = net.ListenPacket("udp", l.Addr().String()); err != nil {
			l.Close()
			pc = nil
		}
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		c := &dns.Client{Net: "tcp", Timeout: time.Second}
		resp, _, err := c.Exchange(req.Copy(), upstream)
		if err != nil {
			return
		}
		resp.Id = req.Id
		if mutate != nil {
			resp = mutate(req, resp, w.RemoteAddr().Network())
		}
		_ = w.WriteMsg(resp)
	})
	udp, tcp := &dns.Server{PacketConn: pc, Handler: h}, &dns.Server{Listener: l, Handler: h}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
	return pc.LocalAddr().String()
}

func runRT(t *testing.T, ref *zone.Zone, o Options, addrs ...string) Report {
	t.Helper()
	ps := []Provider{{"A", []string{addrs[0]}}, {"B", []string{addrs[1]}}}
	r := mustRun(t, ref, ps, o)
	for _, x := range r.Findings {
		t.Logf("%s %s %s %s %s: %s", x.Severity, x.Kind, x.Name, x.Type, x.Provider, x.Detail)
	}
	for _, g := range r.Gaps {
		t.Logf("gap %+v", g)
	}
	t.Logf("verdict %s", r.Verdict)
	return r
}

const childDS = "sub        IN DS    12345 13 2 " +
	"1111111111111111111111111111111111111111111111111111111111111111\n"

// RT-1: the DS RRset at a delegation is never asked (questions() turns every record at or below a cut into a
// referral NS question). Provider B serves a different DS for the secure child: parity passes.
func TestRTDelegationDSNeverCompared(t *testing.T) {
	ref := base + childDS
	served := base + strings.Replace(childDS, "12345", "54321", 1)
	a := authtest.Start(t, zoneOf(t, ref), authtest.None)
	b := authtest.Start(t, zoneOf(t, served), authtest.None)
	r := runRT(t, zoneOf(t, ref), opts(t, "T0", quiet(t)), a.Addr, b.Addr)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: B serves a different DS for sub.example.test, verdict pass")
	}
}

// RT-2: glue below a cut is never asked; a referral is compared only by NS targets. B serves glue pointing elsewhere.
func TestRTGlueNeverCompared(t *testing.T) {
	served := strings.Replace(base, "ns.sub     IN A     192.0.2.54", "ns.sub     IN A     203.0.113.66", 1)
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	b := authtest.Start(t, zoneOf(t, served), authtest.None)
	r := runRT(t, zoneOf(t, base), opts(t, "T0", quiet(t)), a.Addr, b.Addr)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: B serves glue ns.sub A 203.0.113.66 (zone: 192.0.2.54), verdict pass")
	}
}

// RT-3: a "referral" is accepted with AA set and the NS RRset in the answer: B answers the cut as if it were
// authoritative for the child (it serves its own copy of the child zone instead of delegating).
func TestRTAuthoritativeReferralAccepted(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	up := authtest.Start(t, zoneOf(t, base), authtest.None)
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, _ string) *dns.Msg {
		q := req.Question[0]
		if dns.IsSubDomain("sub.example.test.", strings.ToLower(q.Name)) {
			resp.Authoritative = true
			if q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, "sub.example.test.") {
				resp.Answer = append(resp.Answer, resp.Ns...)
			} else {
				rr, _ := dns.NewRR(q.Name + " 3600 IN A 203.0.113.66")
				resp.Answer = []dns.RR{rr}
			}
			resp.Extra = resp.Extra[:0:0]
		}
		return resp
	})
	r := runRT(t, zoneOf(t, base), opts(t, "T0", quiet(t)), a.Addr, b)
	// show what a resolver gets below the cut from B
	m := new(dns.Msg)
	m.SetQuestion("www.sub.example.test.", dns.TypeA)
	if x, err := dns.Exchange(m, b); err == nil {
		t.Logf("B for www.sub.example.test A: AA=%v answer=%v", x.Authoritative, x.Answer)
	}
	if r.Verdict == "pass" {
		t.Errorf("BREAK: B answers the delegation authoritatively (AA, NS in answer, own data below the cut), verdict pass")
	}
}

// RT-4: TXT comparison strips every space, so TXT strings with different meaning compare "equal" (Note only).
// "v=spf1 ip4:192.0.2.1 -all" vs the two strings "v=spf1 ip4:192.0.2.1" "-all", which an SPF verifier concatenates
// without a space (RFC 7208 section 3.3) into "v=spf1 ip4:192.0.2.1-all": a broken SPF record.
func TestRTTXTSpaceStrippedComparesEqual(t *testing.T) {
	ref := base + "@ IN TXT \"v=spf1 ip4:192.0.2.1 -all\"\n"
	served := base + "@ IN TXT \"v=spf1 ip4:192.0.2.1\" \"-all\"\n"
	a := authtest.Start(t, zoneOf(t, served), authtest.None)
	b := authtest.Start(t, zoneOf(t, served), authtest.None)
	r := runRT(t, zoneOf(t, ref), opts(t, "T0", quiet(t)), a.Addr, b.Addr)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: both providers serve a TXT whose concatenated text differs from the zone file, verdict pass")
	}
	// even simpler: one string with its spaces removed
	served2 := base + "@ IN TXT \"v=spf1ip4:192.0.2.1-all\"\n"
	c := authtest.Start(t, zoneOf(t, served2), authtest.None)
	r2 := runRT(t, zoneOf(t, ref), opts(t, "T0", quiet(t)), c.Addr, c.Addr+"")
	_ = r2
}

// RT-5: unsigned zone file, parent publishes a DS (stale, from a previous signed setup), providers serve the zone
// unsigned. Validators: bogus (DS present, no matching DNSKEY). Parity never asks the parent.
func TestRTStaleParentDSUnsignedZone(t *testing.T) {
	stale := dsOf(signedZone(t))
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	b := authtest.Start(t, zoneOf(t, base), authtest.None)
	o := opts(t, "T0", quiet(t))
	o.Parent = []string{parentWithDS(t, stale)}
	r := runRT(t, zoneOf(t, base), o, a.Addr, b.Addr)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: parent has a DS, no provider serves a DNSKEY, verdict pass")
	}
}

// RT-5b: unsigned zone file (provider-side signing), A signs, B does not; parent DS points to A's KSK. Validators
// reaching B get no DNSKEY/RRSIG under a secure delegation: bogus.
func TestRTUnsignedProviderUnderParentDS(t *testing.T) {
	signed := signedZone(t)
	a := authtest.Start(t, signed, authtest.None)
	b := authtest.Start(t, zoneOf(t, base), authtest.None)
	o := opts(t, "T0", quiet(t))
	o.Parent = []string{parentWithDS(t, dsOf(signed))}
	r := runRT(t, zoneOf(t, base), o, a.Addr, b.Addr)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: secure delegation, B serves the zone unsigned, verdict pass")
	}
}

// RT-6: an empty non-terminal in the zone file answered with data by every provider: only NXDOMAIN is checked.
func TestRTDataAtEmptyNonTerminal(t *testing.T) {
	served := base + "b          IN A     203.0.113.66\n"
	a := authtest.Start(t, zoneOf(t, served), authtest.None)
	b := authtest.Start(t, zoneOf(t, served), authtest.None)
	r := runRT(t, zoneOf(t, base), opts(t, "T0", quiet(t)), a.Addr, b.Addr)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: b.example.test is an ENT in the zone file, both providers serve an A there, verdict pass")
	}
}

// RT-7: RR class is not compared: B answers with the right RDATA in class CH (BIND resolvers: FORMERR).
func TestRTWrongClassAccepted(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	up := authtest.Start(t, zoneOf(t, base), authtest.None)
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, _ string) *dns.Msg {
		for _, rr := range resp.Answer {
			rr.Header().Class = dns.ClassCHAOS
		}
		return resp
	})
	r := runRT(t, zoneOf(t, base), opts(t, "T0", quiet(t)), a.Addr, b)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: B answers every RRset in class CH, verdict pass")
	}
}

// RT-8: the DNSKEY RRset is only ever fetched over TCP. B serves it over UDP without its RRSIG (a validator asking
// over UDP, the normal case, cannot authenticate the keys: bogus).
func TestRTDNSKEYOverUDPNeverChecked(t *testing.T) {
	z := signedZone(t)
	a := authtest.Start(t, z, authtest.None)
	up := authtest.Start(t, z, authtest.None)
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, network string) *dns.Msg {
		if network == "udp" && req.Question[0].Qtype == dns.TypeDNSKEY {
			var keep []dns.RR
			for _, rr := range resp.Answer {
				if _, ok := rr.(*dns.RRSIG); !ok {
					keep = append(keep, rr)
				}
			}
			resp.Answer = keep
		}
		return resp
	})
	o := opts(t, "T0", quiet(t))
	o.Parent = []string{parentWithDS(t, dsOf(z))}
	r := runRT(t, z, o, a.Addr, b)
	m := new(dns.Msg)
	m.SetQuestion("example.test.", dns.TypeDNSKEY)
	m.SetEdns0(1232, true)
	if x, err := dns.Exchange(m, b); err == nil {
		t.Logf("B DNSKEY over UDP: TC=%v %d answer RRs, RRSIG present=%v", x.Truncated, len(x.Answer),
			strings.Contains(x.String(), "RRSIG"))
	}
	if r.Verdict == "pass" {
		t.Errorf("BREAK: B serves its DNSKEY RRset over UDP unsigned, verdict pass")
	}
}

// unexported reads an unexported field of authtest.Keys (test-only reflection).
func unexported(k *authtest.Keys, name string) crypto.Signer {
	f := reflect.ValueOf(k).Elem().FieldByName(name)
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface().(crypto.Signer)
}

// RT-9: key tag collision. B's DNSKEY RRset (properly signed by the KSK) holds the ZSK plus a second key with the
// same tag and algorithm. judge() keeps only the LAST key with that tag; validators try every candidate (RFC 4035
// section 5.3.1, RFC 6840 section 5.? key tag collisions). Expected: pass (the zone is secure). Parity: fail.
func TestRTKeyTagCollisionFalseFail(t *testing.T) {
	now := time.Now()
	k := authtest.NewKeys(t, "example.test")
	z := authtest.Sign(t, zoneOf(t, base), k, now.Add(-time.Hour), now.Add(14*24*time.Hour))
	// a colliding key: swap two public-key bytes at the same parity, which keeps the key tag checksum
	bogus := dns.Copy(k.ZSK).(*dns.DNSKEY)
	raw, _ := base64.StdEncoding.DecodeString(bogus.PublicKey)
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] != raw[i+2] {
			raw[i], raw[i+2] = raw[i+2], raw[i]
			break
		}
	}
	bogus.PublicKey = base64.StdEncoding.EncodeToString(raw)
	if bogus.KeyTag() != k.ZSK.KeyTag() {
		t.Fatalf("no collision: %d vs %d", bogus.KeyTag(), k.ZSK.KeyTag())
	}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm: k.KSK.Algorithm, SignerName: "example.test.", KeyTag: k.KSK.KeyTag(),
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(14 * 24 * time.Hour).Unix())}
	set := []dns.RR{k.KSK, k.ZSK, bogus}
	if err := sig.Sign(unexported(k, "kskPriv"), set); err != nil {
		t.Fatal(err)
	}
	var rrs []dns.RR
	for _, r := range z.Records {
		if s, ok := r.RR().(*dns.RRSIG); ok && s.TypeCovered == dns.TypeDNSKEY {
			continue
		}
		rrs = append(rrs, r.RR())
	}
	rrs = append(rrs, bogus, sig)
	served, err := zone.FromRRs(z.Origin, "collide", rrs)
	if err != nil {
		t.Fatal(err)
	}
	up := authtest.Start(t, served, authtest.None)
	// order the DNSKEY answer with the colliding key last (RRset order carries no meaning)
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, _ string) *dns.Msg {
		if req.Question[0].Qtype == dns.TypeDNSKEY {
			var keys, rest []dns.RR
			for _, rr := range resp.Answer {
				if d, ok := rr.(*dns.DNSKEY); ok && d.PublicKey == bogus.PublicKey {
					keys = append(keys, rr)
				} else {
					rest = append(rest, rr)
				}
			}
			resp.Answer = append(rest, keys...)
		}
		return resp
	})
	// sanity: the DNSKEY RRset served is validly signed by the KSK
	if err := sig.Verify(k.KSK, set); err != nil {
		t.Fatalf("DNSKEY RRset sig: %v", err)
	}
	a := authtest.Start(t, served, authtest.None)
	o := opts(t, "T0", quiet(t))
	o.Parent = []string{parentWithDS(t, dsOf(z))}
	r := runRT(t, z, o, a.Addr, b)
	_ = a
	if r.Verdict != "pass" {
		t.Errorf("WRONG VERDICT: key tag collision with a valid ZSK present, verdict %s (validators: secure)", r.Verdict)
	}
}

// RT-10: a revoked ZSK (REVOKE bit, RFC 5011) signs the data; validators must not use a revoked key except for the
// DNSKEY RRset's self-signature. Parity accepts the signatures.
func TestRTRevokedKeyAccepted(t *testing.T) {
	now := time.Now()
	k := authtest.NewKeys(t, "example.test")
	zsk := reflect.ValueOf(k).Elem().FieldByName("ZSK").Interface().(*dns.DNSKEY)
	zsk.Flags |= dns.REVOKE
	z := authtest.Sign(t, zoneOf(t, base), k, now.Add(-time.Hour), now.Add(14*24*time.Hour))
	a := authtest.Start(t, z, authtest.None)
	b := authtest.Start(t, z, authtest.None)
	o := opts(t, "T0", quiet(t))
	o.Parent = []string{parentWithDS(t, dsOf(z))}
	r := runRT(t, z, o, a.Addr, b.Addr)
	if r.Verdict == "pass" {
		t.Errorf("BREAK: every RRset is signed only by a revoked key, verdict pass")
	}
}
