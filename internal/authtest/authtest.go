// Package authtest runs a small authoritative DNS server on loopback for tests: it serves a zone with correct
// authority (AA), referrals at zone cuts with glue, NXDOMAIN versus NODATA, empty non-terminals and CNAMEs, over UDP
// and TCP on the same port. Faults can be switched on to test fail-closed behaviour. A signed zone (see Sign) is served
// with its RRSIGs and NSEC or NSEC3 proofs when the query sets DO. A wildcard answers for names that do not exist
// below its closest encloser (RFC 4592), for the types the wildcard has; NODATA from a wildcard is not synthesised.
package authtest

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/zone"
)

// Fault makes the server misbehave in one way.
type Fault int

const (
	None             Fault = iota
	Refuse                 // answer REFUSED to everything (a lame server)
	NoAA                   // answer correctly but without the AA flag (a resolver or proxy, not the authority)
	Silent                 // never answer
	NXForENT               // answer NXDOMAIN for empty non-terminals (RFC 8020 violation)
	BadSig                 // serve every RRSIG with a corrupted signature
	NoSig                  // serve no RRSIGs, even when DO is set
	NoDenial               // serve negative answers without NSEC or NSEC3
	WrongDenial            // serve the apex's NSEC or NSEC3 with every negative answer, which proves nothing
	NoWildcardProof        // serve wildcard answers without the proof that the exact name does not exist
	NoReferralDenial       // serve referrals to insecure delegations without the proof that the cut has no DS
)

// Server serves one zone.
type Server struct {
	Addr  string
	zone  *zone.Zone
	fault Fault
	names map[string]bool
	cuts  []string
}

// Start serves z on 127.0.0.1, UDP and TCP on one port, until the test ends.
func Start(t *testing.T, z *zone.Zone, f Fault) *Server {
	t.Helper()
	return StartOn(t, "127.0.0.1", z, f)
}

// Start6 serves z on the IPv6 loopback, [::1]. It skips the test when the host has no IPv6 loopback.
func Start6(t *testing.T, z *zone.Zone, f Fault) *Server {
	t.Helper()
	if l, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	} else {
		l.Close()
	}
	return StartOn(t, "::1", z, f)
}

// StartOn serves z on host (an IP literal), UDP and TCP on one port, until the test ends.
func StartOn(t *testing.T, host string, z *zone.Zone, f Fault) *Server {
	t.Helper()
	s := &Server{zone: z, fault: f, names: map[string]bool{}, cuts: z.Delegations()}
	for _, r := range z.Records {
		s.names[r.Name] = true
	}
	var pc net.PacketConn
	var l net.Listener
	for i := 0; i < 2000 && pc == nil; i++ { // Windows reserves wide UDP ranges; each try is cheap
		var err error
		// TCP first: on Windows, reserved port ranges (Hyper-V) affect TCP binds more than UDP ones.
		if l, err = net.Listen("tcp", net.JoinHostPort(host, "0")); err != nil {
			t.Fatal(err)
		}
		if pc, err = net.ListenPacket("udp", l.Addr().String()); err != nil {
			l.Close()
			pc = nil
		}
	}
	if pc == nil {
		t.Fatal("authtest: no free port for UDP and TCP")
	}
	s.Addr = pc.LocalAddr().String()
	h := dns.HandlerFunc(s.serve)
	udp, tcp := &dns.Server{PacketConn: pc, Handler: h}, &dns.Server{Listener: l, Handler: h}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
	return s
}

func (s *Server) serve(w dns.ResponseWriter, req *dns.Msg) {
	if s.fault == Silent || len(req.Question) != 1 {
		return
	}
	m := new(dns.Msg)
	m.SetReply(req)
	if o := req.IsEdns0(); o != nil {
		m.SetEdns0(1232, o.Do())
	}
	if s.fault == Refuse {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	if !dns.IsSubDomain(s.zone.Origin, name) {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	m.Authoritative = s.fault != NoAA
	if cut := s.cutAbove(name); cut != "" && !(name == cut && q.Qtype == dns.TypeDS) {
		m.Authoritative = false // a referral is never authoritative
		for _, r := range s.zone.At(cut, "NS") {
			m.Ns = append(m.Ns, r.RR())
			target := strings.ToLower(r.RR().(*dns.NS).Ns)
			for _, g := range append(s.zone.At(target, "A"), s.zone.At(target, "AAAA")...) {
				m.Extra = append(m.Extra, g.RR())
			}
		}
		if req.IsEdns0() != nil && req.IsEdns0().Do() {
			m.Ns = append(m.Ns, s.referralProof(cut)...)
		}
		_ = w.WriteMsg(m)
		return
	}
	do := req.IsEdns0() != nil && req.IsEdns0().Do()
	qt := dns.TypeToString[q.Qtype]
	for _, r := range s.zone.At(name, qt) {
		m.Answer = append(m.Answer, r.RR())
	}
	answered := qt
	if len(m.Answer) == 0 {
		for _, r := range s.zone.At(name, "CNAME") {
			m.Answer = append(m.Answer, r.RR())
		}
		answered = "CNAME"
	}
	if len(m.Answer) > 0 && do {
		m.Answer = append(m.Answer, s.sigs(name, answered)...)
	}
	if len(m.Answer) == 0 && !s.names[name] && !s.isENT(name) {
		m.Answer = s.synthesise(name, qt, do)
		if len(m.Answer) > 0 && do && s.fault != NoWildcardProof {
			m.Ns = append(m.Ns, s.wildcardProof(name)...)
		}
	}
	if len(m.Answer) == 0 {
		ent := s.isENT(name)
		if !s.names[name] && (!ent || s.fault == NXForENT) {
			m.Rcode = dns.RcodeNameError
		}
		for _, r := range s.zone.At(s.zone.Origin, "SOA") {
			m.Ns = append(m.Ns, r.RR())
		}
		if do {
			m.Ns = append(m.Ns, s.sigs(s.zone.Origin, "SOA")...)
			m.Ns = append(m.Ns, s.denial(name, m.Rcode == dns.RcodeNameError)...)
		}
	}
	_ = w.WriteMsg(m)
}

// sigs returns the zone's RRSIGs over (name, type), corrupted under BadSig and absent under NoSig.
func (s *Server) sigs(name, typ string) []dns.RR {
	if s.fault == NoSig {
		return nil
	}
	var out []dns.RR
	for _, r := range s.zone.At(name, "RRSIG") {
		sig := dns.Copy(r.RR()).(*dns.RRSIG)
		if dns.TypeToString[sig.TypeCovered] != typ {
			continue
		}
		if s.fault == BadSig {
			// Corrupt the signature bytes, not the base64 text: a non-base64 character would make the answer
			// impossible to pack, and the test would see silence instead of a bad signature.
			b, err := base64.StdEncoding.DecodeString(sig.Signature)
			if err == nil && len(b) > 0 {
				b[len(b)/2] ^= 0x01
				sig.Signature = base64.StdEncoding.EncodeToString(b)
			}
		}
		out = append(out, sig)
	}
	return out
}

// cutAbove returns the delegation at or above name, or "".
func (s *Server) cutAbove(name string) string {
	for _, c := range s.cuts {
		if dns.IsSubDomain(c, name) {
			return c
		}
	}
	return ""
}

func (s *Server) isENT(name string) bool {
	if s.names[name] {
		return false
	}
	for n := range s.names {
		if n != name && dns.IsSubDomain(name, n) {
			return true
		}
	}
	return false
}

// denial returns the NSEC or NSEC3 records, with their RRSIGs, that prove a negative answer for name: the record at
// the name (NODATA), or the records covering the name and the wildcard at its closest encloser (NXDOMAIN); RFC 4035
// section 3.1.3 and RFC 5155 section 7.2.
func (s *Server) denial(name string, nx bool) []dns.RR {
	if s.fault == NoDenial {
		return nil
	}
	var nsec []*dns.NSEC
	var nsec3 []*dns.NSEC3
	for _, r := range s.zone.Records {
		switch v := r.RR().(type) {
		case *dns.NSEC:
			nsec = append(nsec, v)
		case *dns.NSEC3:
			nsec3 = append(nsec3, v)
		}
	}
	origin := s.zone.Origin
	var out []dns.RR
	seen := map[string]bool{}
	add := func(rr dns.RR) {
		if rr == nil || seen[rr.Header().Name] {
			return
		}
		seen[rr.Header().Name] = true
		out = append(out, rr)
		out = append(out, s.sigs(rr.Header().Name, dns.TypeToString[rr.Header().Rrtype])...)
	}
	if s.fault == WrongDenial {
		for _, n := range nsec {
			if n.Hdr.Name == origin {
				add(n)
			}
		}
		for _, n := range nsec3 {
			if n.Match(origin) {
				add(n)
			}
		}
		return out
	}
	encloser := origin // the closest existing ancestor of name
	for a := name; a != origin; {
		_, a, _ = strings.Cut(a, ".")
		if s.names[a] || s.isENT(a) {
			encloser = a
			break
		}
	}
	if len(nsec) > 0 {
		covering := func(x string) dns.RR {
			for _, n := range nsec {
				if n.Hdr.Name == x || (zone.CanonicalLess(n.Hdr.Name, x) &&
					(zone.CanonicalLess(x, n.NextDomain) || n.NextDomain == origin)) {
					return n
				}
			}
			return nil
		}
		add(covering(name))
		if nx {
			add(covering("*." + encloser))
		}
		return out
	}
	find := func(x string, match bool) dns.RR {
		for _, n := range nsec3 {
			if (match && n.Match(x)) || (!match && n.Cover(x)) {
				return n
			}
		}
		return nil
	}
	if !nx {
		add(find(name, true))
		return out
	}
	labels := dns.SplitDomainName(name)
	nextCloser := dns.Fqdn(strings.Join(labels[len(labels)-dns.CountLabel(encloser)-1:], "."))
	add(find(encloser, true))
	add(find(nextCloser, false))
	add(find("*."+encloser, false))
	return out
}

// referralProof returns what a signed referral carries in its authority section (RFC 4035 section 3.1.4.1, RFC 5155
// section 7.2.7): the DS RRset and its RRSIGs for a secure delegation; for an insecure one the NSEC or NSEC3 at the
// cut, or under opt-out the closest provable encloser's NSEC3 and the opt-out NSEC3 covering the next closer name.
func (s *Server) referralProof(cut string) []dns.RR {
	var out []dns.RR
	if ds := s.zone.At(cut, "DS"); len(ds) > 0 {
		for _, r := range ds {
			out = append(out, r.RR())
		}
		return append(out, s.sigs(cut, "DS")...)
	}
	if s.fault == NoReferralDenial {
		return nil
	}
	var nsec3 []*dns.NSEC3
	for _, r := range s.zone.Records {
		switch v := r.RR().(type) {
		case *dns.NSEC:
			if v.Hdr.Name == cut {
				return append([]dns.RR{v}, s.sigs(cut, "NSEC")...)
			}
		case *dns.NSEC3:
			nsec3 = append(nsec3, v)
		}
	}
	add := func(n *dns.NSEC3) {
		out = append(out, n)
		out = append(out, s.sigs(n.Hdr.Name, "NSEC3")...)
	}
	for _, n := range nsec3 {
		if n.Match(cut) {
			add(n)
			return out
		}
	}
	labels := dns.SplitDomainName(cut)
	for i := 1; i < len(labels); i++ {
		ce := dns.Fqdn(strings.Join(labels[i:], "."))
		for _, n := range nsec3 {
			if n.Match(ce) {
				add(n)
				next := dns.Fqdn(strings.Join(labels[i-1:], "."))
				for _, c := range nsec3 {
					if c.Cover(next) {
						add(c)
						break
					}
				}
				return out
			}
		}
	}
	return out
}

// encloser returns the closest existing ancestor of name.
func (s *Server) encloser(name string) string {
	for a := name; a != s.zone.Origin; {
		_, a, _ = strings.Cut(a, ".")
		if s.names[a] || s.isENT(a) {
			return a
		}
	}
	return s.zone.Origin
}

// synthesise answers name from the wildcard at its closest encloser (RFC 4592 section 3.3), owner rewritten to
// name, with the wildcard's RRSIGs, whose Labels field tells a validator the answer was expanded.
func (s *Server) synthesise(name, qt string, do bool) []dns.RR {
	wild := "*." + s.encloser(name)
	typ := qt
	recs := s.zone.At(wild, qt)
	if len(recs) == 0 {
		typ, recs = "CNAME", s.zone.At(wild, "CNAME")
	}
	var out []dns.RR
	for _, r := range recs {
		rr := dns.Copy(r.RR())
		rr.Header().Name = name
		out = append(out, rr)
	}
	if len(out) > 0 && do {
		for _, sig := range s.sigs(wild, typ) {
			sig.Header().Name = name
			out = append(out, sig)
		}
	}
	return out
}

// wildcardProof returns the NSEC or NSEC3 records, with RRSIGs, that prove name itself does not exist: an NSEC
// covering it, or an NSEC3 covering the next closer name (RFC 4035 section 3.1.3.3, RFC 5155 section 7.2.6).
func (s *Server) wildcardProof(name string) []dns.RR {
	ce := s.encloser(name)
	labels := dns.SplitDomainName(name)
	nextCloser := dns.Fqdn(strings.Join(labels[len(labels)-dns.CountLabel(ce)-1:], "."))
	for _, r := range s.zone.Records {
		switch v := r.RR().(type) {
		case *dns.NSEC:
			if zone.CanonicalLess(v.Hdr.Name, name) && (zone.CanonicalLess(name, v.NextDomain) ||
				v.NextDomain == s.zone.Origin) {
				return append([]dns.RR{v}, s.sigs(v.Hdr.Name, "NSEC")...)
			}
		case *dns.NSEC3:
			if v.Cover(nextCloser) {
				return append([]dns.RR{v}, s.sigs(v.Hdr.Name, "NSEC3")...)
			}
		}
	}
	return nil
}
