package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/evidence"
	"lostname.be/lostname/internal/parity"
	"lostname.be/lostname/internal/zone"
)

// A parity run with --evidence leaves one bundle that verifies, holds the zone file, the report and every exchange
// the run made, and names itself on stderr.
func TestParityEvidenceBundle(t *testing.T) {
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.53\n"
	z, err := zone.Read(strings.NewReader(src), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	a, b := authtest.Start(t, z, authtest.None), authtest.Start(t, z, authtest.None)
	dir := t.TempDir()
	zp, cfg, ev := filepath.Join(dir, "z.zone"), filepath.Join(dir, "c.json"), filepath.Join(dir, "evidence")
	conf := `{"schema":"lostname.config/v0","probe":{"canary":"127.0.0.1:1","canary_v6":"[::1]:1","timeout_seconds":1}}`
	if os.WriteFile(zp, []byte(src), 0o600) != nil || os.WriteFile(cfg, []byte(conf), 0o600) != nil {
		t.Fatal("write fixtures")
	}
	var out, errb bytes.Buffer
	code := run([]string{"parity", "--config", cfg, "--zone", zp, "--origin", "example.test", "--provider", "A=" + a.Addr,
		"--provider", "B=" + b.Addr, "--evidence", ev}, &out, &errb)
	if code != exitPass {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	entries, err := os.ReadDir(ev)
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), "-parity-example.test") {
		t.Fatalf("want one bundle, got %v %v", entries, err)
	}
	bundle := filepath.Join(ev, entries[0].Name())
	if !strings.Contains(errb.String(), "evidence: "+bundle) {
		t.Errorf("the bundle's path must be on stderr, got %q", errb.String())
	}
	if err := evidence.Verify(bundle); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"inputs/zone-z.zone", "parity.json", "versions.json", "MANIFEST.sha256"} {
		if _, err := os.Stat(filepath.Join(bundle, filepath.FromSlash(f))); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	snaps, _ := filepath.Glob(filepath.Join(bundle, "snapshots", "*.json"))
	if len(snaps) != 4 { // two servers, UDP and TCP each
		t.Fatalf("want 4 snapshot files (2 servers x 2 transports), got %v", snaps)
	}
	var ex []parity.Exchange
	data, _ := os.ReadFile(snaps[0])
	if err := json.Unmarshal(data, &ex); err != nil || len(ex) == 0 || ex[0].Time == "" || ex[0].Server == "" {
		t.Fatalf("a snapshot must list timed exchanges: %v %+v", err, ex)
	}
}
