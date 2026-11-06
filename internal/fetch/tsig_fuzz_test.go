package fetch

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadTSIGFile: the key-file reader must never panic, and must never accept a line without three fields.
func FuzzReadTSIGFile(f *testing.F) {
	f.Add("hmac-sha256 transfer.example.test c2VjcmV0\n")
	f.Add("# only a comment\n")
	f.Add("hmac-sha256 onlytwo\n")
	f.Fuzz(func(t *testing.T, text string) {
		p := filepath.Join(t.TempDir(), "key")
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Skip()
		}
		k, err := ReadTSIGFile(p)
		if err == nil && (k.Name == "" || k.Algorithm == "" || k.Secret == "") {
			t.Fatalf("accepted an incomplete key: %+v", k)
		}
	})
}
