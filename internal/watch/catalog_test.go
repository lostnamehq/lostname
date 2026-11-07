package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"lostname.be/lostname/internal/config"
)

// A catalog's members are checked like listed zones; a member without a zone file has no verdict and does not stop
// the others; an explicitly listed zone keeps its own settings; a catalog that is not version 2 has no verdict.
func TestCatalogMembersAreWatched(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	member := func(origin string) string {
		return "$ORIGIN " + origin + ".\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
			"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\n"
	}
	write("one.test.zone", member("one.test"))
	write("listed.test.zone", member("listed.test"))
	// two.test has no zone file.
	cat := write("catalog.zone", "$ORIGIN catalog.invalid.\n$TTL 0\n@ IN SOA invalid. invalid. 1 3600 600 86400 0\n"+
		"@ IN NS invalid.\nversion IN TXT \"2\"\na.zones IN PTR one.test.\nb.zones IN PTR two.test.\n"+
		"c.zones IN PTR listed.test.\n")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Watch.Zones = []config.WatchZone{{Origin: "listed.test", ZoneFile: filepath.Join(dir, "listed.test.zone")}}
	// The catalog's members share an exit objective; the listed zone has none, so it must get no exit check.
	cfg.Watch.Catalogs = []config.WatchCatalog{{CatalogFile: cat, Origin: "catalog.invalid", ZoneDir: dir,
		Exit: &config.WatchExit{Model: "T0", Lock: "none", Target: 1 << 30}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewSnapshot()
	Round(cfg, s, time.Now)
	got := map[[2]string]string{}
	for _, r := range s.Results() {
		got[[2]string{r.Zone, r.Check}] = r.Verdict
	}
	for k, want := range map[[2]string]string{
		{"catalog.invalid.", "catalog"}: "pass",
		{"one.test.", "lint"}:           "pass",
		{"two.test.", "lint"}:           "no_verdict",
		{"listed.test.", "lint"}:        "pass",
		{"one.test.", "exit"}:           "pass",
		{"two.test.", "exit"}:           "no_verdict",
	} {
		if got[k] != want {
			t.Errorf("%v: %q, want %q (all: %v)", k, got[k], want, got)
		}
	}
	if len(got) != 6 || got[[2]string{"listed.test.", "exit"}] != "" {
		t.Errorf("want 6 checks, and none of the catalog's settings on the listed zone; got %v", got)
	}

	write("catalog.zone", "$ORIGIN catalog.invalid.\n$TTL 0\n@ IN SOA invalid. invalid. 1 3600 600 86400 0\n"+
		"@ IN NS invalid.\nversion IN TXT \"1\"\na.zones IN PTR one.test.\n")
	s = NewSnapshot()
	Round(cfg, s, time.Now)
	for _, r := range s.Results() {
		if r.Check == "catalog" && r.Verdict != "no_verdict" {
			t.Errorf("a version 1 catalog: %s, want no_verdict", r.Verdict)
		}
		if r.Zone == "one.test." {
			t.Errorf("a catalog that cannot be read lists no members, yet one.test. was checked")
		}
	}
}
