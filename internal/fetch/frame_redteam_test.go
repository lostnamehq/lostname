package fetch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/zone"
)

func mustRR(t *testing.T, s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func TestRedteamSOAFrame(t *testing.T) {
	first := mustRR(t, "example.test. 300 IN SOA ns1.example.test. h.example.test. 7 7200 3600 1209600 300")
	last := mustRR(t, "example.test. 300 IN SOA evil.example.test. x.example.test. 7 1 1 1 86400")
	rrs := []dns.RR{first,
		mustRR(t, "example.test. 300 IN NS ns1.example.test."),
		mustRR(t, "www.example.test. 300 CH A 192.0.2.1"),
		last}
	err := checkSOAFrame(rrs, "example.test")
	t.Logf("differing SOAs (same serial) frame: err=%v", err)
	z, err := zone.FromRRs("example.test", "axfr:t", rrs[:len(rrs)-1])
	t.Logf("FromRRs err=%v", err)
	if z != nil {
		for _, r := range z.Records {
			t.Logf("%s %s %s class=%d", r.Name, r.Type, r.Data, r.RR().Header().Class)
		}
	}
}

func TestRedteamTSIGFile(t *testing.T) {
	d := t.TempDir()
	for name, body := range map[string]string{
		"extra-lines": "hmac-sha256 k. c2VjcmV0\nhmac-md5 other. AAAA\n",
		"bad-alg":     "rot13 k. c2VjcmV0\n",
		"not-base64":  "hmac-sha256 k. !!!notbase64!!!\n",
	} {
		p := filepath.Join(d, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		k, err := ReadTSIGFile(p)
		t.Logf("%s: key=%+v err=%v", name, k, err)
	}
}
