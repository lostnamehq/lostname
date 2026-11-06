package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lostname.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreValid(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Sim.Locks["domain-shield"].Window != 86400 {
		t.Fatal("defaults not loaded")
	}
}

func TestOverrideAppliesOnTop(t *testing.T) {
	c, err := Load(write(t, `{"schema":"lostname.config/v0","parity":{"timeout_seconds":7}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Parity.Timeout != 7 || c.Parity.EDNSBuffer != 1232 {
		t.Fatalf("override must change only what it names: %+v", c.Parity)
	}
}

func TestStrictReading(t *testing.T) {
	cases := map[string]string{
		"unknown key":     `{"schema":"lostname.config/v0","parity":{"timeuot_seconds":7}}`,
		"wrong schema":    `{"schema":"lostname.config/v9"}`,
		"zero timeout":    `{"schema":"lostname.config/v0","fetch":{"timeout_seconds":0}}`,
		"bad model":       `{"schema":"lostname.config/v0","parity":{"model":"T9"}}`,
		"bad severity":    `{"schema":"lostname.config/v0","lint":{"severity":{"L-07":"fatal"}}}`,
		"lock no source":  `{"schema":"lostname.config/v0","sim":{"locks":{"x":{"latency_seconds":1}}}}`,
		"trailing object": `{"schema":"lostname.config/v0"} {}`,
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "lostname.json") {
			t.Errorf("%s: error does not name the file: %v", name, err)
		}
	}
}
