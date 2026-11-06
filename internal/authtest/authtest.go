// Package authtest runs a small authoritative DNS server on loopback for tests: it serves a zone with correct
// authority (AA), referrals at zone cuts with glue, NXDOMAIN versus NODATA, empty non-terminals and CNAMEs, over UDP
// and TCP on the same port. Faults can be switched on to test fail-closed behaviour. Wildcard synthesis is not
// implemented.
package authtest

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/zone"
)

// Fault makes the server misbehave in one way.
type Fault int

const (
	None     Fault = iota
	Refuse         // answer REFUSED to everything (a lame server)
	NoAA           // answer correctly but without the AA flag (a resolver or proxy, not the authority)
	Silent         // never answer
	NXForENT       // answer NXDOMAIN for empty non-terminals (RFC 8020 violation)
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
	s := &Server{zone: z, fault: f, names: map[string]bool{}, cuts: z.Delegations()}
	for _, r := range z.Records {
		s.names[r.Name] = true
	}
	var pc net.PacketConn
	var l net.Listener
	for i := 0; i < 200 && pc == nil; i++ {
		var err error
		// TCP first: on Windows, reserved port ranges (Hyper-V) affect TCP binds more than UDP ones.
		if l, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
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
		_ = w.WriteMsg(m)
		return
	}
	qt := dns.TypeToString[q.Qtype]
	for _, r := range s.zone.At(name, qt) {
		m.Answer = append(m.Answer, r.RR())
	}
	if len(m.Answer) == 0 {
		for _, r := range s.zone.At(name, "CNAME") {
			m.Answer = append(m.Answer, r.RR())
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
	}
	_ = w.WriteMsg(m)
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
