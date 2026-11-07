package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/zone"
)

// watch --once against two in-process providers: a round with a verdict emits the result series; a round where one
// provider is unreachable emits its verdict as no_verdict and leaves the parity result series out.
func TestWatchOnce(t *testing.T) {
	t.Parallel() // independent servers and temp dirs; seconds of probe and query timeouts each
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
		"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\nwww IN A 192.0.2.80\n"
	z, err := zone.Read(strings.NewReader(src), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	a, b := authtest.Start(t, z, authtest.None), authtest.Start(t, z, authtest.None)
	dir := t.TempDir()
	zp := filepath.Join(dir, "z.zone")
	if err := os.WriteFile(zp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	config := func(bAddr string) string {
		p := filepath.Join(dir, "c.json")
		c := fmt.Sprintf(`{"schema":"lostname.config/v0",
 "probe":{"canary":"127.0.0.1:1","canary_v6":"[::1]:1","timeout_seconds":1},
 "parity":{"timeout_seconds":1},
 "watch":{"zones":[{"origin":"example.test","zone_file":%q,
   "providers":[{"name":"A","addrs":[%q]},{"name":"B","addrs":[%q]}]}]}}`, zp, a.Addr, bAddr)
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var out, errb bytes.Buffer
	if code := run([]string{"watch", "--config", config(b.Addr), "--once"}, &out, &errb); code != exitPass {
		t.Fatalf("exit %d: %s\n%s", code, errb.String(), out.String())
	}
	for _, want := range []string{
		`lostname_check_verdict{zone="example.test.",check="parity",lostname_check_verdict="pass"} 1`,
		`lostname_parity_mismatches{zone="example.test.",provider_a="A",provider_b="B"} 0`,
		`lostname_parity_servers_answering{zone="example.test.",provider="B"} 1`,
		`lostname_lint_findings{zone="example.test.",severity="blocker"} 0`,
		"lostname_probe_intercepted 0",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %s in\n%s", want, out.String())
		}
	}
	out.Reset()
	if code := run([]string{"watch", "--config", config("127.0.0.1:1"), "--once"}, &out, &errb); code != exitNoVerdict {
		t.Fatalf("an unreachable provider: exit %d, want %d", code, exitNoVerdict)
	}
	if strings.Contains(out.String(), "lostname_parity_mismatches{") ||
		!strings.Contains(out.String(), `check="parity",lostname_check_verdict="no_verdict"} 1`) {
		t.Fatalf("no_verdict must leave the parity result series out:\n%s", out.String())
	}
}

// watch --once with events over HTTP: the round's verdicts arrive as structured CloudEvents from lostname/<instance>.
func TestWatchOnceSendsEvents(t *testing.T) {
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
		"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\n"
	dir := t.TempDir()
	zp := filepath.Join(dir, "z.zone")
	if err := os.WriteFile(zp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e map[string]any
		if r.Header.Get("Content-Type") == "application/cloudevents+json" && json.NewDecoder(r.Body).Decode(&e) == nil {
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
		}
	}))
	defer srv.Close()
	p := filepath.Join(dir, "c.json")
	c := fmt.Sprintf(`{"schema":"lostname.config/v0","watch":{"zones":[{"origin":"example.test","zone_file":%q}],
 "events":["http"],"events_endpoint":%q,"instance":"edge-1"}}`, zp, srv.URL)
	if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"watch", "--config", p, "--once"}, &out, &errb); code != exitPass {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	mu.Lock()
	defer mu.Unlock()
	// The first round: the verdict, then the resync event with the whole state (decision of 2026-11-06).
	if len(got) != 2 || got[0]["type"] != "be.lostname.check.verdict.changed.v0" || got[0]["source"] != "lostname/edge-1" ||
		got[0]["subject"] != "example.test." || got[0]["specversion"] != "1.0" || got[1]["type"] != "be.lostname.watch.resync.v0" {
		t.Fatalf("want a verdict event and a resync from lostname/edge-1, got %v (stderr %s)", got, errb.String())
	}
}

// watch --once with traces on: the round's traces go to /v1/traces once, next to the metrics on /v1/metrics.
func TestWatchOnceSendsTraces(t *testing.T) {
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
		"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\n"
	dir := t.TempDir()
	zp := filepath.Join(dir, "z.zone")
	if err := os.WriteFile(zp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	paths := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()
	}))
	defer srv.Close()
	p := filepath.Join(dir, "c.json")
	c := fmt.Sprintf(`{"schema":"lostname.config/v0","watch":{"zones":[{"origin":"example.test","zone_file":%q}],
 "otlp_endpoint":%q,"traces":true}}`, zp, srv.URL)
	if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"watch", "--config", p, "--once"}, &out, &errb); code != exitPass {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if paths["/v1/traces"] != 1 || paths["/v1/metrics"] != 1 {
		t.Fatalf("want one traces and one metrics request, got %v (stderr %s)", paths, errb.String())
	}
}

// The zone label's salt is a secret of at least 16 bytes: a short or missing file is refused, not used.
func TestWatchZoneIDSaltRefused(t *testing.T) {
	dir := t.TempDir()
	salt := filepath.Join(dir, "salt")
	if err := os.WriteFile(salt, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{salt, filepath.Join(dir, "missing")} {
		p := filepath.Join(dir, "c.json")
		c := fmt.Sprintf(`{"schema":"lostname.config/v0","watch":{"zones":[{"origin":"example.test","zone_file":"x"}],
 "zone_id":{"salt_file":%q}}}`, f)
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := run([]string{"watch", "--config", p, "--once"}, &out, &errb); code != exitUsage {
			t.Errorf("salt %s: exit %d, want %d", f, code, exitUsage)
		}
	}
}

// The loop's runtime messages are structured: a failed event delivery is one slog line with its transport.
func TestWatchLogsAreStructured(t *testing.T) {
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
		"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\n"
	dir := t.TempDir()
	zp := filepath.Join(dir, "z.zone")
	if err := os.WriteFile(zp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := filepath.Join(dir, "c.json")
	c := fmt.Sprintf(`{"schema":"lostname.config/v0","watch":{"zones":[{"origin":"example.test","zone_file":%q}],
 "events":["http"],"events_endpoint":%q}}`, zp, srv.URL)
	if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	run([]string{"watch", "--config", p, "--once"}, &out, &errb)
	if !strings.Contains(errb.String(), `level=WARN msg="event delivery failed" cmd=watch transport=http`) {
		t.Errorf("want a structured warning for the failed delivery, got:\n%s", errb.String())
	}
}
