package zone

import (
	"strings"
	"testing"
)

func TestRedteamIR(t *testing.T) {
	cases := map[string]string{
		"name-injection-changes-type": `{"domains":[{"name":"example.test","records":[
			{"type":"A","typenum":1,"ttl":300,"name":"www.example.test. 300 IN CNAME other.example.test. ;","comparablev3":"192.0.2.1"}]}]}`,
		"cname-with-pseudo-typenum": `{"domains":[{"name":"example.test","records":[
			{"type":"A","typenum":1,"ttl":300,"name":"www","comparablev3":"192.0.2.1"},
			{"type":"CNAME","typenum":65300,"ttl":300,"name":"www","comparablev3":"other.example.test."}]}]}`,
		"data-newline": `{"domains":[{"name":"example.test","records":[
			{"type":"A","typenum":1,"ttl":300,"name":"www","comparablev3":"192.0.2.1\nwww 300 IN CNAME x."}]}]}`,
		"trailing-garbage": `{"domains":[{"name":"example.test","records":[]}]} {"domains":[{"name":"example.test","records":[{"type":"A","typenum":1,"ttl":1,"name":"x","comparablev3":"1.2.3.4"}]}]}`,
		"duplicate-domain": `{"domains":[{"name":"example.test","records":[]},{"name":"EXAMPLE.test.","records":[{"type":"CNAME","typenum":5,"ttl":1,"name":"@","comparablev3":"x.example.test."}]}]}`,
		"name-with-dot-escape": `{"domains":[{"name":"example.test","records":[
			{"type":"A","typenum":1,"ttl":300,"name":"a\\.b","comparablev3":"192.0.2.1"}]}]}`,
	}
	for name, in := range cases {
		z, err := ReadDNSControlIR(strings.NewReader(in), name, "example.test")
		if err != nil {
			t.Logf("%s: refused: %v", name, err)
			continue
		}
		for _, r := range z.Records {
			t.Logf("%s: record %q %s %q", name, r.Name, r.Type, r.Data)
		}
		for _, r := range z.Pseudo {
			t.Logf("%s: pseudo %q %s %q", name, r.Name, r.Type, r.Data)
		}
		if len(z.Records)+len(z.Pseudo) == 0 {
			t.Logf("%s: accepted, empty", name)
		}
	}
}
