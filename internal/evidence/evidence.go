// Package evidence writes an evidence bundle (model section 6): what was asked, of whom, over which path, with which
// answer and when, beside the inputs and the report, all covered by a SHA-256 manifest. A bundle is unsigned in v0.1.
//
// The bundle appears whole or not at all: it is built in a temporary directory next to its final place and renamed
// at the end. It holds no credentials (a TSIG key never enters it) and nothing outside the owner's zone, but it does
// show the zone's internal names: sharing it is the owner's choice.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Bundle is a bundle being written.
type Bundle struct {
	final, tmp string
	files      map[string][]byte
	err        error // the first Add that would have overwritten a file
}

// New starts a bundle for command on origin under root, named <UTC stamp>-<command>-<origin>, with -2, -3 ... when
// a bundle of the same second exists (red team 2, C7): an earlier bundle is never overwritten, and a second run in
// the same second still gets its evidence.
func New(root, command, origin string, now time.Time) (*Bundle, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	name := now.UTC().Format("20060102T150405Z") + "-" + command
	if o := strings.TrimSuffix(strings.ToLower(origin), "."); o != "" {
		name += "-" + o
	}
	final := filepath.Join(root, name)
	for i := 2; ; i++ {
		if _, err := os.Stat(final); err != nil {
			break
		}
		if i > 99 {
			return nil, fmt.Errorf("evidence: too many bundles named %s in one second", name)
		}
		final = filepath.Join(root, fmt.Sprintf("%s-%d", name, i))
	}
	tmp, err := os.MkdirTemp(root, "."+name+".partial-")
	if err != nil {
		return nil, err
	}
	return &Bundle{final: final, tmp: tmp, files: map[string][]byte{}}, nil
}

// Add stores a file at rel (slash-separated, inside the bundle). Adding the same path twice is an error at Close
// (red team 2, P4/C6: two inputs with one base name once left the checked zone out of its own evidence).
func (b *Bundle) Add(rel string, data []byte) {
	if _, dup := b.files[rel]; dup && b.err == nil {
		b.err = fmt.Errorf("evidence: two files for %s", rel)
	}
	b.files[rel] = append([]byte(nil), data...)
}

// AddJSON stores v as indented JSON.
func (b *Bundle) AddJSON(rel string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b.Add(rel, append(data, '\n'))
	return nil
}

// AddInput copies an input file into inputs/ as <role>-<base name>, for example inputs/zone-example.test.zone.
func (b *Bundle) AddInput(role, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	b.Add("inputs/"+role+"-"+filepath.Base(path), data)
	return nil
}

// badPath says whether rel is not a plain relative path inside the bundle (red team 2, C8, C9: judged by segments,
// so "example..test.zone" is fine and "../x" is not).
func badPath(rel string) bool {
	if rel == "" || strings.ContainsAny(rel, `\:`) || strings.HasPrefix(rel, "/") {
		return true
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// Close writes versions.json, every file, and MANIFEST.sha256 (sha256sum format, sorted by path), syncs them, and
// moves the bundle into place. It returns the bundle's path. On failure nothing is left at the final path.
func (b *Bundle) Close(toolVersion string, extra map[string]any) (string, error) {
	if b.err != nil {
		return "", b.abort(b.err)
	}
	versions := map[string]any{"lostname": toolVersion, "go": runtime.Version(), "os": runtime.GOOS + "/" + runtime.GOARCH}
	for k, v := range extra {
		versions[k] = v
	}
	if err := b.AddJSON("versions.json", versions); err != nil {
		return "", b.abort(err)
	}
	names := make([]string, 0, len(b.files))
	for n := range b.files {
		names = append(names, n)
	}
	sort.Strings(names)
	var manifest strings.Builder
	for _, n := range names {
		if badPath(n) {
			return "", b.abort(fmt.Errorf("evidence: bad path %q", n))
		}
		sum := sha256.Sum256(b.files[n])
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(sum[:]), n)
		if err := writeSynced(filepath.Join(b.tmp, filepath.FromSlash(n)), b.files[n]); err != nil {
			return "", b.abort(err)
		}
	}
	if err := writeSynced(filepath.Join(b.tmp, "MANIFEST.sha256"), []byte(manifest.String())); err != nil {
		return "", b.abort(err)
	}
	if err := os.Rename(b.tmp, b.final); err != nil {
		return "", b.abort(err)
	}
	return b.final, nil
}

func (b *Bundle) abort(err error) error {
	_ = os.RemoveAll(b.tmp)
	return err
}

func writeSynced(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Verify checks a bundle against its manifest: every listed file present with its hash, and no file unlisted.
func Verify(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, "MANIFEST.sha256"))
	if err != nil {
		return err
	}
	listed := map[string]bool{"MANIFEST.sha256": true}
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || badPath(name) {
			return fmt.Errorf("evidence: bad manifest line %q", line)
		}
		content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			return fmt.Errorf("evidence: %s listed but unreadable: %v", name, err)
		}
		got := sha256.Sum256(content)
		if hex.EncodeToString(got[:]) != sum {
			return fmt.Errorf("evidence: %s does not match the manifest", name)
		}
		listed[name] = true
	}
	if !listed["versions.json"] {
		return fmt.Errorf("evidence: the manifest does not list versions.json")
	}
	return filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if !listed[filepath.ToSlash(rel)] {
			return fmt.Errorf("evidence: %s is in the bundle but not in the manifest", rel)
		}
		return nil
	})
}
