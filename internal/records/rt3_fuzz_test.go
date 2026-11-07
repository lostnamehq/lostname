package records

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"lostname.be/lostname/internal/zone"
)

func FuzzRT3Read(f *testing.F) {
	for _, s := range []string{`@ IN TXT "v=spf1 a/24 -all"`, `_dmarc IN TXT "v=DMARC1;p=none"`, `s._domainkey IN TXT "p="`,
		`_mta-sts IN TXT "v=STSv1; id=1"`, `_smtp._tls IN TXT "v=TLSRPTv1; rua=mailto:a@b"`, `_25._tcp.mx IN TLSA 3 1 1 00`,
		`@ IN TXT "v=spf1 +"`, `@ IN TXT "v=spf1 -"`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, extra string) {
		z, err := zone.Read(strings.NewReader(head+extra+"\n"), "f", "example.test")
		if err != nil {
			return
		}
		p1, f1 := Read(z)
		p2, f2 := Read(z)
		a, _ := json.Marshal([]any{p1, f1})
		b, _ := json.Marshal([]any{p2, f2})
		if !reflect.DeepEqual(a, b) {
			t.Fatal("nondeterministic")
		}
	})
}
