package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestLintToATarget(t *testing.T) {
	ir := filepath.Join("..", "..", "internal", "zone", "testdata", "print-ir-v5.7.0.json")
	out := runCLI(t, "lint", "--dnscontrol-ir", ir, "--origin", "example.test", "--to", "HETZNER_V2", "--json")
	mustValidate(t, "lint-report.schema.json", out)
	var r LintReport
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	rules := map[string]bool{}
	for _, f := range r.Findings {
		rules[f.Rule] = true
	}
	// A config leaves the apex SOA and NS to the provider: no L-00 or L-15; the ALIAS cannot move to Hetzner.
	if rules["L-00"] || rules["L-15"] || !rules["L-03"] || r.Verdict != "fail" ||
		!strings.HasPrefix(r.Source, "dnscontrol-ir:") {
		t.Fatalf("got %s from %s with rules %v", r.Verdict, r.Source, rules)
	}
	// Every --to verdict names the matrix it rests on and its date, so an old matrix is visible (customer review).
	if r.Target == nil || r.Target.Provider != "HETZNER_V2" || r.Target.Matrix != "DNSControl v5.7.0" ||
		r.Target.Released != "2026-10-21" || len(r.Target.Commit) != 40 {
		t.Fatalf("target %+v", r.Target)
	}
	var o, e bytes.Buffer
	run([]string{"lint", "--dnscontrol-ir", ir, "--origin", "example.test", "--to", "HETZNER_V2"}, &o, &e)
	if !strings.Contains(o.String(), "per the DNSControl v5.7.0 provider matrix of 2026-10-21") {
		t.Errorf("the text verdict must name the matrix and its date:\n%s", o.String())
	}
	for _, args := range [][]string{
		{"lint", "--zone", "x.zone", "--dnscontrol-ir", ir, "--origin", "example.test"},
		{"lint", "--dnscontrol-ir", ir, "--origin", "example.test", "--to", "NO_SUCH_PROVIDER"},
	} {
		var o, e bytes.Buffer
		if code := run(args, &o, &e); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args[1:], code, exitUsage)
		}
	}
}
