package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files from the current output")

// Golden files (plan v0.1): the exact output of every offline command for one fixed zone, so any change to an output
// is a reviewed diff, not a surprise. Regenerate with `go test ./cmd/lostname -run Golden -update` and read the diff.
func TestGoldenOutputs(t *testing.T) {
	zone := filepath.Join("testdata", "golden", "input.zone")
	for name, args := range map[string][]string{
		"config.json":  {"config"},
		"lint.txt":     {"lint", "--zone", zone, "--origin", "example.test"},
		"lint.json":    {"lint", "--zone", zone, "--origin", "example.test", "--json"},
		"lint.sarif":   {"lint", "--zone", zone, "--origin", "example.test", "--sarif"},
		"lint-to.json": {"lint", "--zone", zone, "--origin", "example.test", "--to", "HETZNER_V2", "--json"},
		"mail.txt":     {"mail", "--zone", zone, "--origin", "example.test"},
		"mail.json":    {"mail", "--zone", zone, "--origin", "example.test", "--json"},
	} {
		var out, errb bytes.Buffer
		run(args, &out, &errb)
		got := strings.ReplaceAll(out.String(), filepath.ToSlash(zone), "INPUT")
		got = strings.ReplaceAll(got, strings.ReplaceAll(zone, `\`, `\\`), "INPUT") // the path inside JSON on Windows
		got = strings.ReplaceAll(got, zone, "INPUT")
		path := filepath.Join("testdata", "golden", name)
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run with -update to create it)", name, err)
		}
		if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
			t.Errorf("%s differs from its golden file; if the change is meant, run with -update and review the diff:\n%s",
				name, got)
		}
	}
}
