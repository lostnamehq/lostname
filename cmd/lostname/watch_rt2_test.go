package main

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/watch"
	"lostname.be/lostname/internal/zone"
)

func rt2zone(origin, www string) string {
	return "$ORIGIN " + origin + ".\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
		"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\nwww IN A " + www + "\n"
}

func writeZone(t *testing.T, src string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "z.zone")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func serveZone(t *testing.T, origin, src string) string {
	t.Helper()
	z, err := zone.Read(strings.NewReader(src), "t", origin)
	if err != nil {
		t.Fatal(err)
	}
	return authtest.Start(t, z, authtest.None).Addr
}

func watchOnce(t *testing.T, conf string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	run([]string{"watch", "--config", p, "--once"}, &out, &errb)
	return out.String()
}

// Red team 2, W1: zone one's IPv4 path is intercepted (its canary answers); zone two, checked after it, is reached
// over IPv6 and is not. One caught path must raise the gauge, whatever the order.
func TestInterceptionGaugeCoversEveryZone(t *testing.T) {
	t.Parallel() // independent servers and temp dirs; seconds of probe and query timeouts each
	src1 := rt2zone("example.test", "192.0.2.80")
	a := serveZone(t, "example.test", src1)
	src2 := rt2zone("other.test", "192.0.2.81")
	out := watchOnce(t, fmt.Sprintf(`{"schema":"lostname.config/v0",
 "probe":{"canary":%q,"canary_v6":"[::1]:1","timeout_seconds":1},"parity":{"timeout_seconds":1},
 "watch":{"zones":[
  {"origin":"example.test","zone_file":%q,"providers":[{"name":"A","addrs":[%q]},{"name":"B","addrs":[%q]}]},
  {"origin":"other.test","zone_file":%q,"providers":[{"name":"A","addrs":["[::1]:1"]},{"name":"B","addrs":["[::1]:1"]}]}]}}`,
		a, writeZone(t, src1), a, a, writeZone(t, src2)))
	if !strings.Contains(out, "lostname_probe_intercepted 1") {
		t.Errorf("one intercepted path must raise the gauge:\n%s", out)
	}
}

// Red team 2, W2: the reference is silent while B serves wrong data, so the run fails on the zone check, yet no
// comparison between the two happened: the mismatch count must be absent, not 0.
func TestSilentReferenceLeavesMismatchesAbsent(t *testing.T) {
	t.Parallel() // independent servers and temp dirs; seconds of probe and query timeouts each
	src := rt2zone("example.test", "192.0.2.80")
	b := serveZone(t, "example.test", rt2zone("example.test", "192.0.2.99"))
	out := watchOnce(t, fmt.Sprintf(`{"schema":"lostname.config/v0",
 "probe":{"canary":"127.0.0.1:1","canary_v6":"[::1]:1","timeout_seconds":1},"parity":{"timeout_seconds":1},
 "watch":{"zones":[{"origin":"example.test","zone_file":%q,
   "providers":[{"name":"A","addrs":["127.0.0.1:1"]},{"name":"B","addrs":[%q]}]}]}}`, writeZone(t, src), b))
	if !strings.Contains(out, `check="parity",lostname_check_verdict="fail"} 1`) {
		t.Fatalf("the setup must give a parity run with a verdict (fail):\n%s", out)
	}
	if strings.Contains(out, "lostname_parity_mismatches{") {
		t.Errorf("a silent reference must leave the mismatch count absent:\n%s", out)
	}
}

// Red team 2, W6.
func TestMetricsHandlerMethods(t *testing.T) {
	h := metricsHandler(watch.NewSnapshot())
	for method, want := range map[string]int{"GET": 200, "HEAD": 200, "DELETE": 405, "POST": 405} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(method, "/metrics", nil))
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", method, rec.Code, want)
		}
	}
}
