package fetch

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/zone"
)

const keyName, keySecret = "transfer.example.test.", "c2VjcmV0LWZvci10ZXN0cy1vbmx5LWxvc3RuYW1lLXRzaWc="

// serve starts an in-process authoritative server on loopback that answers AXFR for the fixture zone. With tsig set,
// it requires and signs with the test key.
func serve(t *testing.T, tsig bool) string {
	t.Helper()
	return serveOn(t, "127.0.0.1:0", tsig)
}

// serveOn is serve on a chosen listen address, for IPv6.
func serveOn(t *testing.T, listen string, tsig bool) string {
	t.Helper()
	z, err := zone.ReadFile(filepath.Join("..", "lint", "testdata", "clean.example.test.zone"), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	var rrs []dns.RR
	for _, r := range z.Records {
		rrs = append(rrs, r.RR())
	}
	var soa dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA {
			soa = rr
		}
	}
	body := []dns.RR{soa}
	for _, rr := range rrs {
		if rr != soa {
			body = append(body, rr)
		}
	}
	body = append(body, soa)
	mux := dns.NewServeMux()
	mux.HandleFunc("example.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		if tsig && (req.IsTsig() == nil || w.TsigStatus() != nil) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		ch := make(chan *dns.Envelope)
		tr := new(dns.Transfer)
		go func() { _ = tr.Out(w, req, ch) }()
		ch <- &dns.Envelope{RR: body}
		close(ch)
		w.Hijack()
	})
	l, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: l, Handler: mux}
	if tsig {
		srv.TsigSecret = map[string]string{keyName: keySecret}
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return l.Addr().String()
}

// quiet is a loopback port where nothing listens: the canary probe gets no answer, as on a clean network.
func quiet(t *testing.T) string {
	t.Helper()
	// Port 1 (tcpmux) is never bound by these tests. A freed ephemeral port could be reused by a parallel test's
	// server, which would then answer the probe and make the run flaky.
	return "127.0.0.1:1"
}

func TestAXFRWithTSIG(t *testing.T) {
	addr := serve(t, true)
	z, err := AXFR(addr, "example.test", Options{TSIG: &TSIG{Name: keyName, Algorithm: dns.HmacSHA256, Secret: keySecret},
		Timeout: 3 * time.Second, Canary: quiet(t), Canary6: quiet(t), ProbeTimeout: time.Second, Deadline: time.Minute, MaxRecords: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 11 {
		t.Fatalf("got %d records, want 11 (the fixture, SOA once)", len(z.Records))
	}
}

func TestAXFRWrongKeyIsRefused(t *testing.T) {
	addr := serve(t, true)
	_, err := AXFR(addr, "example.test", Options{TSIG: &TSIG{Name: keyName, Algorithm: dns.HmacSHA256,
		Secret: "d3Jvbmcta2V5LXdyb25nLWtleS13cm9uZy1rZXk=" /* gitleaks:allow (a test key) */}, Timeout: 3 * time.Second, Canary: quiet(t), Canary6: quiet(t), ProbeTimeout: time.Second, Deadline: time.Minute, MaxRecords: 1000})
	if !errors.Is(err, ErrNoVerdict) {
		t.Fatalf("a transfer with the wrong key must give no verdict, got %v", err)
	}
}

// M5: an unreachable or refusing server is a missing measurement (exit 2), not a usage error (exit 3).
func TestUnreachableServerGivesNoVerdict(t *testing.T) {
	_, err := AXFR(quiet(t), "example.test", Options{Canary: quiet(t), Canary6: quiet(t), Timeout: time.Second, ProbeTimeout: time.Second, Deadline: time.Minute, MaxRecords: 1000})
	if !errors.Is(err, ErrNoVerdict) {
		t.Fatalf("want ErrNoVerdict, got %v", err)
	}
}

func TestUnsignedTransferOnCleanPath(t *testing.T) {
	addr := serve(t, false)
	if _, err := AXFR(addr, "example.test", Options{Canary: quiet(t), Canary6: quiet(t), Timeout: 3 * time.Second, ProbeTimeout: time.Second, Deadline: time.Minute, MaxRecords: 1000}); err != nil {
		t.Fatal(err)
	}
}

func TestUnsignedTransferOnInterceptedPathGivesNoVerdict(t *testing.T) {
	addr := serve(t, false)
	// The "canary" here is a server that answers: exactly what an intercepting middlebox does.
	_, err := AXFR(addr, "example.test", Options{Canary: addr, Canary6: addr, Timeout: 3 * time.Second, ProbeTimeout: time.Second, Deadline: time.Minute, MaxRecords: 1000})
	if !errors.Is(err, ErrNoVerdict) {
		t.Fatalf("want ErrNoVerdict, got %v", err)
	}
}

func TestSOAFrame(t *testing.T) {
	a, _ := dns.NewRR("example.test. 300 IN SOA ns.example.test. h.example.test. 1 1 1 1 1")
	b, _ := dns.NewRR("example.test. 300 IN SOA ns.example.test. h.example.test. 2 1 1 1 1")
	x, _ := dns.NewRR("www.example.test. 300 IN A 192.0.2.1")
	if checkSOAFrame([]dns.RR{a, x, a}, "example.test") != nil {
		t.Error("a complete transfer must pass")
	}
	if checkSOAFrame([]dns.RR{a, x, b}, "example.test") == nil {
		t.Error("a serial change during the transfer must fail")
	}
	if checkSOAFrame([]dns.RR{a, x}, "example.test") == nil {
		t.Error("a transfer without the closing SOA must fail")
	}
	// L14: the frame must be the zone asked for, and one copy of it.
	if checkSOAFrame([]dns.RR{a, x, a}, "other.test") == nil {
		t.Error("a transfer framed by another zone's SOA must fail")
	}
	if checkSOAFrame([]dns.RR{a, x, a, x, a}, "example.test") == nil {
		t.Error("an SOA inside the transfer must fail")
	}
}

// L14: a zone larger than the cap is refused with no verdict, not truncated.
func TestRecordCapRefusesLargeTransfer(t *testing.T) {
	addr := serve(t, false)
	_, err := AXFR(addr, "example.test", Options{Canary: quiet(t), Canary6: quiet(t), Timeout: 3 * time.Second, ProbeTimeout: time.Second,
		Deadline: time.Minute, MaxRecords: 5})
	if !errors.Is(err, ErrNoVerdict) {
		t.Fatalf("want ErrNoVerdict past the record cap, got %v", err)
	}
}

func TestTSIGFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte("# test key\nhmac-sha256 transfer.example.test "+keySecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := ReadTSIGFile(p)
	if err != nil || k.Name != keyName || k.Algorithm != dns.HmacSHA256 {
		t.Fatalf("got %+v, %v", k, err)
	}
}

// Red team 2, P7: the closing SOA must be the opening SOA, not only its serial.
func TestSOAFrameComparesTheWholeSOA(t *testing.T) {
	a, _ := dns.NewRR("example.test. 300 IN SOA ns1.example.test. h.example.test. 7 7200 3600 1209600 300")
	b, _ := dns.NewRR("example.test. 300 IN SOA evil.example.test. x.example.test. 7 1 1 1 86400")
	x, _ := dns.NewRR("www.example.test. 300 IN A 192.0.2.1")
	if checkSOAFrame([]dns.RR{a, x, b}, "example.test") == nil {
		t.Error("a closing SOA with the same serial but other fields must fail")
	}
}

// A transfer over IPv6, with TSIG; the IPv6 probe address is the one consulted.
func TestAXFROverIPv6(t *testing.T) {
	if l, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	} else {
		l.Close()
	}
	addr := serveOn(t, "[::1]:0", true)
	z, err := AXFR(addr, "example.test", Options{TSIG: &TSIG{Name: keyName, Algorithm: dns.HmacSHA256, Secret: keySecret},
		Timeout: 3 * time.Second, Canary: quiet(t), Canary6: "[::1]:1", ProbeTimeout: time.Second, Deadline: time.Minute,
		MaxRecords: 1000})
	if err != nil || len(z.Records) != 11 {
		t.Fatalf("transfer over IPv6: %v", err)
	}
}
