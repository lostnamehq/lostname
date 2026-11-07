package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lostname.be/lostname/internal/zone"
)

const head = "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1.dns-host.example. h 1 7200 900 1209600 300\n" +
	"@ IN NS ns1.dns-host.example.\n@ IN NS ns2.dns-host.example.\n"

func rulesOf(t *testing.T, src string) map[string][]Finding {
	t.Helper()
	z, err := zone.Read(strings.NewReader(src), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]Finding{}
	for _, f := range Run(z) {
		got[f.Rule] = append(got[f.Rule], f)
	}
	return got
}

func TestL11DelegationToTheProvidersServers(t *testing.T) {
	got := rulesOf(t, head+
		"shop IN NS ns1.dns-host.example.\n"+ // the provider's own server: lame after the exit
		"eu IN NS ns3.dns-host.example.\n"+ // another server of the same provider
		"lab IN NS ns.other-host.example.\n") // someone else: fine
	if len(got["L-11"]) != 2 || got["L-11"][0].Severity != Blocker {
		t.Fatalf("want L-11 for shop and eu only, got %+v", got["L-11"])
	}
	for _, f := range got["L-11"] {
		if f.Name == "lab.example.test." {
			t.Errorf("a delegation to another provider is not lame after this exit: %+v", f)
		}
	}
	if rules := rulesOf(t, head+"lab IN NS ns.other-host.example.\n"); len(rules["L-11"]) != 0 {
		t.Errorf("no provider server, no L-11: %+v", rules["L-11"])
	}
}

func TestL12TargetsOnTheProvidersDomain(t *testing.T) {
	got := rulesOf(t, head+
		"@ IN MX 10 mx.forward.dns-host.example.\n"+ // the provider's mail forwarder
		"www IN CNAME proxy.dns-host.example.\n"+ // the provider's proxy
		"api IN CNAME api.cloud.example.\n"+ // elsewhere: fine
		"_sip._tcp IN SRV 0 0 5060 sip.example.test.\n") // in zone: fine
	if len(got["L-12"]) != 2 || got["L-12"][0].Severity != Risk {
		t.Fatalf("want L-12 for the MX and the www CNAME, got %+v", got["L-12"])
	}
	// Public suffixes count: a provider under co.uk is dns-host.co.uk, not co.uk, so a.co.uk is someone else.
	uk := strings.ReplaceAll(head, "dns-host.example.", "dns-host.co.uk.") + "www IN CNAME shop.other.co.uk.\n"
	if rules := rulesOf(t, uk); len(rules["L-12"]) != 0 {
		t.Errorf("another registrant under the same public suffix is not the provider: %+v", rules["L-12"])
	}
}

func TestL16LargeAnswers(t *testing.T) {
	big := head
	for i := 0; i < 6; i++ {
		big += "@ IN TXT \"" + strings.Repeat("v", 250) + "\"\n"
	}
	if got := rulesOf(t, big); len(got["L-16"]) != 1 || got["L-16"][0].Type != "TXT" || got["L-16"][0].Severity != Note {
		t.Fatalf("six 250-byte strings exceed 1232 bytes: want one L-16 note on TXT, got %+v", got["L-16"])
	}
	if got := rulesOf(t, head+"@ IN TXT \"v=spf1 -all\"\n"); len(got["L-16"]) != 0 {
		t.Errorf("a small answer is no L-16: %+v", got["L-16"])
	}
}

func TestL20SharedFate(t *testing.T) {
	vanity := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n"
	for _, tc := range []struct {
		name, glue string
		want       int
	}{
		{"same /24", "ns1 IN A 192.0.2.53\nns2 IN A 192.0.2.54\n", 1},
		{"same address", "ns1 IN A 192.0.2.53\nns2 IN A 192.0.2.53\n", 1},
		{"same /48", "ns1 IN AAAA 2001:db8:1::53\nns2 IN AAAA 2001:db8:1:ff::53\n", 1},
		{"separate networks", "ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\nns1 IN AAAA 2001:db8:1::53\n" +
			"ns2 IN AAAA 2001:db8:2::53\n", 0},
		{"one server, two addresses", "ns1 IN A 192.0.2.53\nns1 IN A 192.0.2.54\nns2 IN A 198.51.100.53\n", 0},
	} {
		if got := rulesOf(t, vanity+tc.glue); len(got["L-20"]) != tc.want {
			t.Errorf("%s: %d L-20, want %d: %+v", tc.name, len(got["L-20"]), tc.want, got["L-20"])
		}
	}
}

func TestL10ProviderMetadata(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "zone", "testdata", "print-ir-v5.7.0-meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := zone.ReadDNSControlIR(f, "meta", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, x := range Run(z) {
		if x.Rule == "L-10" {
			got[x.Name] = x.Message
		}
	}
	if len(got) != 2 || !strings.Contains(got["www.example.test."], "cloudflare_proxy") ||
		!strings.Contains(got["geo.example.test."], "geo_region") {
		t.Fatalf("want L-10 on www (cloudflare_proxy) and geo (geo_region), not on plain: %v", got)
	}
}

func TestL22DANEDependsOnTheHandover(t *testing.T) {
	nl := string(rune(10))
	tlsa := "@ IN MX 10 mx.example.test." + nl + "_25._tcp.mx IN TLSA 3 1 1 " + strings.Repeat("AB", 32) + "\n"
	if got := rulesOf(t, head+tlsa); len(got["L-22"]) != 1 || got["L-22"][0].Severity != Risk {
		t.Errorf("TLSA in an unsigned zone: want one L-22 risk, got %+v", got["L-22"])
	}
	signed := head + "@ IN DNSKEY 257 3 13 " + strings.Repeat("A", 86) + "==\n" + tlsa
	if got := rulesOf(t, signed); len(got["L-22"]) != 1 || got["L-22"][0].Severity != Note {
		t.Errorf("TLSA in a signed zone: want one L-22 note, got %+v", got["L-22"])
	}
	if got := rulesOf(t, head+"_443._tcp.www IN TLSA 3 1 1 "+strings.Repeat("AB", 32)+"\n"); len(got["L-22"]) != 0 {
		t.Errorf("a web TLSA is not mail: %+v", got["L-22"])
	}
}
