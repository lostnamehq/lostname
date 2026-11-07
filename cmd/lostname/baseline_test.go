package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AU-2: with a baseline, lint reports and judges only what got worse.
func TestLintBaseline(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "lint", "testdata", "broken.example.test.zone"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	zp, base := filepath.Join(dir, "z.zone"), filepath.Join(dir, "base.json")
	write := func(p string, b []byte) {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lint := func(args ...string) (int, []byte) {
		var out, errb bytes.Buffer
		code := run(append([]string{"lint", "--zone", zp, "--origin", "example.test"}, args...), &out, &errb)
		return code, append(out.Bytes(), errb.Bytes()...)
	}
	write(zp, src)
	code, out := lint("--json")
	if code != exitFindings {
		t.Fatalf("the broken zone must fail on its own, exit %d", code)
	}
	write(base, out)

	// The same zone against its own report: nothing is worse, so it passes.
	code, out = lint("--baseline", base, "--json")
	var r LintReport
	if err := json.Unmarshal(out, &r); err != nil || code != exitPass || len(r.Findings) != 0 || r.Baseline == nil ||
		r.Baseline.Worse != 0 || r.Baseline.Fixed != 0 {
		t.Fatalf("unchanged zone: exit %d, %+v, %v", code, r, err)
	}
	mustValidate(t, "lint-report.schema.json", out)

	// One new blocker (api: CNAME next to a TXT) and one fixed (www's TXT removed, so its CNAME stands alone): only
	// the new blocker is reported.
	changed := strings.Replace(string(src), "www       IN TXT   \"v=verify\"\n", "", 1) +
		"api       IN CNAME api.provider.invalid.\napi       IN TXT   \"x\"\n"
	write(zp, []byte(changed))
	code, out = lint("--baseline", base, "--json")
	r = LintReport{}
	if err := json.Unmarshal(out, &r); err != nil || code != exitFindings || len(r.Findings) != 1 ||
		r.Findings[0].Name != "api.example.test." || r.Baseline.Worse != 1 || r.Baseline.Fixed != 1 {
		t.Fatalf("changed zone: exit %d, %+v, %v", code, r, err)
	}

	// Refused: a report of another zone, and a report that is itself a difference.
	var other LintReport
	_ = json.Unmarshal(mustRead(t, base), &other)
	other.Origin = "other.test."
	b, _ := json.Marshal(other)
	write(filepath.Join(dir, "other.json"), b)
	if code, msg := lint("--baseline", filepath.Join(dir, "other.json")); code != exitUsage ||
		!strings.Contains(string(msg), "not example.test.") {
		t.Errorf("another zone's report: exit %d, %s", code, msg)
	}
	write(filepath.Join(dir, "diff.json"), out)
	if code, msg := lint("--baseline", filepath.Join(dir, "diff.json")); code != exitUsage ||
		!strings.Contains(string(msg), "itself made against a baseline") {
		t.Errorf("a difference as baseline: exit %d, %s", code, msg)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
