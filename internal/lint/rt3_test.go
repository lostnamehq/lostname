package lint

import (
	"strings"
	"testing"

	"lostname.be/lostname/internal/zone"
)

// L3-10: a sub-zone served by its parent organisation's own nameservers (lab.example.test NS ns1.example.test.):
// registered(ns) is the zone's own registered domain, so every target in the owner's own domain becomes "the
// current DNS provider's own domain" (L-12) and a child delegated to the owner's other server is a Blocker (L-11).
func TestRT3OwnRegisteredDomainIsNotAProvider(t *testing.T) {
	src := "$ORIGIN lab.example.test.\n$TTL 3600\n@ IN SOA ns1.example.test. h 1 7200 900 1209600 300\n" +
		"@ IN NS ns1.example.test.\n@ IN NS ns2.example.test.\n@ IN MX 10 mail.example.test.\n" +
		"www IN CNAME web.example.test.\nx IN NS ns3.example.test.\n"
	z, err := zone.Read(strings.NewReader(src), "test", "lab.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Run(z) {
		if f.Rule == "L-11" || f.Rule == "L-12" {
			t.Errorf("owner's own registered domain treated as a provider: %+v", f)
		}
	}
}

// L3-11: L-22 says "a mail host of this zone" but fires for any _25._tcp owner, including names that are no MX
// target (RFC 7672 2.2.1: the TLSA base domain is the MX host; other names are never queried by DANE SMTP).
func TestRT3L22OnlyForMXHosts(t *testing.T) {
	got := rulesOf(t, head+"@ IN MX 10 mx.example.test.\nmx IN A 192.0.2.25\nwww IN A 192.0.2.80\n"+
		"_25._tcp.www IN TLSA 3 1 1 0000000000000000000000000000000000000000000000000000000000000000\n")
	if len(got["L-22"]) != 0 {
		t.Errorf("www is no mail host: %+v", got["L-22"])
	}
}
