package zone

import (
	"strconv"
	"strings"
	"testing"
)

// Red team 2, P2: only class IN is read; another class could satisfy a check no IN resolver sees.
func TestOtherClassesAreRefused(t *testing.T) {
	src := "$ORIGIN example.test.\n@ CH SOA ns1 h 1 7200 3600 1209600 300\n@ CH NS ns1\nns1 IN A 192.0.2.1\n"
	if _, err := Read(strings.NewReader(src), "chaos.zone", "example.test"); err == nil || !strings.Contains(err.Error(), "class CH") {
		t.Fatalf("a CH record must be refused, got %v", err)
	}
}

// Red team 2, P6: print-ir input the reader would have misread.
func TestCraftedIRIsRefused(t *testing.T) {
	rec := func(name, typ string, num int, data string) string {
		return `{"type":"` + typ + `","typenum":` + strconv.Itoa(num) + `,"ttl":300,"name":"` + name + `","comparablev3":"` + data + `","filepos":"[line:1:1]"}`
	}
	dom := func(name string, recs ...string) string {
		return `{"name":"` + name + `","records":[` + strings.Join(recs, ",") + `]}`
	}
	ir := func(doms ...string) string { return `{"domains":[` + strings.Join(doms, ",") + `]}` }
	for _, c := range []struct{ name, input string }{
		{"CNAME numbered as a pseudo-type", ir(dom("example.test", rec("www", "CNAME", 65300, "x.example.test.")))},
		{"the domain twice", ir(dom("example.test"), dom("EXAMPLE.test."))},
		{"trailing data", ir(dom("example.test")) + ` {"domains":[]}`},
		{"line break in data", ir(dom("example.test", rec("www", "A", 1, `192.0.2.1\nwww 300 IN CNAME x.`)))},
		{"name with a record spliced in", ir(dom("example.test", rec("www.example.test. 300 IN CNAME o.example.test. ;", "A", 1, "192.0.2.1")))},
	} {
		if _, err := ReadDNSControlIR(strings.NewReader(c.input), "ir.json", "example.test"); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
