package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/zone"
)

func doctorConfig(t *testing.T, canary, extra string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.json")
	c := fmt.Sprintf(`{"schema":"lostname.config/v0","probe":{"canary":%q,"canary_v6":"[::1]:1","timeout_seconds":1}%s}`,
		canary, extra)
	if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDoctor(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"doctor", "--config", doctorConfig(t, "127.0.0.1:1", "")}, &out, &errb); code != exitPass ||
		!strings.Contains(out.String(), "doctor: ready") {
		t.Fatalf("clean path, no watch: exit %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	missing := `,"watch":{"zones":[{"origin":"example.test","zone_file":"` + filepath.ToSlash(filepath.Join(t.TempDir(),
		"missing.zone")) + `"}]}`
	if code := run([]string{"doctor", "--config", doctorConfig(t, "127.0.0.1:1", missing)}, &out, &errb); code != exitFindings ||
		!strings.Contains(out.String(), "FAIL watch zone example.test") {
		t.Errorf("a missing zone file: exit %d, want %d\n%s", code, exitFindings, out.String())
	}
	out.Reset()
	z, err := zone.Read(strings.NewReader("$ORIGIN example.test.\n@ 3600 IN SOA ns1 h 1 7200 900 1209600 300\n@ 3600 IN NS ns1\n"),
		"t", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	answering := authtest.Start(t, z, authtest.None) // a "canary" that answers: an intercepting path
	if code := run([]string{"doctor", "--config", doctorConfig(t, answering.Addr, "")}, &out, &errb); code != exitNoVerdict ||
		!strings.Contains(out.String(), "IPv4 path intercepted") {
		t.Errorf("an answering canary: exit %d, want %d\n%s", code, exitNoVerdict, out.String())
	}
}
