package evidence

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBundleRoundTrip(t *testing.T) {
	root := t.TempDir()
	in := filepath.Join(t.TempDir(), "example.test.zone")
	if err := os.WriteFile(in, []byte("$ORIGIN example.test.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := New(root, "lint", "example.test.", time.Date(2026, 11, 6, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddInput("zone", in); err != nil {
		t.Fatal(err)
	}
	if err := b.AddJSON("findings.json", map[string]int{"blocker": 0}); err != nil {
		t.Fatal(err)
	}
	b.Add("snapshots/192.0.2.1-udp.json", []byte("[]\n"))
	dir, err := b.Close("test", map[string]any{"capabilities": "none"})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(dir) != "20261106T130000Z-lint-example.test" {
		t.Fatalf("bundle name %s", filepath.Base(dir))
	}
	if err := Verify(dir); err != nil {
		t.Fatalf("a fresh bundle must verify: %v", err)
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Fatalf("only the finished bundle may be left in the root, got %d entries", len(entries))
	}

	// Tampering: a changed file, and an added file, both fail verification.
	if err := os.WriteFile(filepath.Join(dir, "findings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if Verify(dir) == nil {
		t.Error("a changed file must fail verification")
	}
	// Red team 2, C7: a second bundle in the same second gets its own name; the first is never overwritten.
	b2, err := New(root, "lint", "example.test.", time.Date(2026, 11, 6, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	b2.Add("findings.json", []byte("{}\n"))
	dir2, err := b2.Close("test", nil)
	if err != nil || filepath.Base(dir2) != "20261106T130000Z-lint-example.test-2" {
		t.Fatalf("second bundle: %s, %v", dir2, err)
	}
}

// Red team 2, P4/C6, C8, C9.
func TestBundlePaths(t *testing.T) {
	root := t.TempDir()
	b, _ := New(root, "lint", "example.test.", time.Now())
	b.Add("inputs/zone-x.zone", []byte("a"))
	b.Add("inputs/zone-x.zone", []byte("b"))
	if _, err := b.Close("test", nil); err == nil {
		t.Error("two files for one path must fail the bundle")
	}
	b, _ = New(root, "lint", "example.test.", time.Now())
	b.Add("inputs/zone-example..test.zone", []byte("a"))
	if _, err := b.Close("test", nil); err != nil {
		t.Errorf("a name with '..' inside a segment is a plain name: %v", err)
	}
	for _, bad := range []string{"../x", "a/../b", "/x", `a\b`, "c:x", "a//b", "./a"} {
		if !badPath(bad) {
			t.Errorf("%q must be refused", bad)
		}
	}
	dir := t.TempDir()
	outside := filepath.Join(filepath.Dir(dir), "outside.json")
	if err := os.WriteFile(outside, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outside)
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST.sha256"),
		[]byte("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a  ../outside.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if Verify(dir) == nil {
		t.Error("a manifest that points outside the bundle must fail")
	}
}

func TestUnlistedFileFailsVerification(t *testing.T) {
	root := t.TempDir()
	b, _ := New(root, "parity", "example.test.", time.Now())
	b.Add("parity.json", []byte("{}\n"))
	dir, err := b.Close("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if Verify(dir) == nil {
		t.Error("a file not in the manifest must fail verification")
	}
}
