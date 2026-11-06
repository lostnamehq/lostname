package lint

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lostname.be/lostname/internal/zone"
)

func load(t *testing.T, file string) *zone.Zone {
	t.Helper()
	z, err := zone.ReadFile(filepath.Join("testdata", file), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestBrokenZoneFindsEachRule(t *testing.T) {
	fs := Run(load(t, "broken.example.test.zone"))
	got := map[string]int{}
	for _, f := range fs {
		got[f.Rule]++
		t.Logf("%s %s %s: %s", f.Rule, f.Severity, f.Name, f.Message)
	}
	// L-18 fires twice: the DNAME, and the MX that points at a CNAME.
	want := map[string]int{"L-07": 1, "L-08": 1, "L-09": 1, "L-13": 1, "L-14": 1, "L-15": 1, "L-18": 2}
	for rule, n := range want {
		if got[rule] != n {
			t.Errorf("%s: got %d finding(s), want %d", rule, got[rule], n)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected rules: %v", got)
	}
	if !Fails(fs, false) {
		t.Error("blockers must fail lint")
	}
}

// M8: an input that is not a zone must not pass vacuously.
func TestNotAZoneIsABlocker(t *testing.T) {
	for _, c := range []struct{ name, text string }{
		{"empty", "$ORIGIN example.test.\n"},
		{"no SOA", "$ORIGIN example.test.\n@ 3600 IN NS ns1.example.test.\n"},
		{"no NS", "$ORIGIN example.test.\n@ 3600 IN SOA ns1.example.test. h.example.test. 1 7200 900 1209600 300\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			z, err := zone.Read(strings.NewReader(c.text), "test", "example.test")
			if err != nil {
				t.Fatal(err)
			}
			fs := Run(z)
			if !Fails(fs, false) || fs[0].Rule != "L-00" {
				t.Fatalf("want an L-00 blocker, got %+v", fs)
			}
		})
	}
}

func TestCleanZonePasses(t *testing.T) {
	if fs := Run(load(t, "clean.example.test.zone")); len(fs) != 0 {
		t.Fatalf("clean zone gave findings: %+v", fs)
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	a, b := Run(load(t, "broken.example.test.zone")), Run(load(t, "broken.example.test.zone"))
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("finding %d differs between runs", i)
		}
	}
}

// Decision 0008: lint makes no network calls. Our lint and zone packages must not import the network packages.
func TestNoNetworkImports(t *testing.T) {
	for _, dir := range []string{".", "../zone"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no Go files in %s: %v", dir, err)
		}
		for _, name := range files {
			f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if path == "net" || path == "net/http" || path == "net/netip" {
					t.Errorf("%s imports %s", name, path)
				}
			}
		}
	}
}
