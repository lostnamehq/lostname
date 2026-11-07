package lint

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"lostname.be/lostname/internal/config"
)

// The config refuses rule ids it does not know (red team 2, P3a); its list must be exactly the rules lint emits.
func TestConfigKnowsEveryRule(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	emitted := map[string]bool{}
	for _, f := range files {
		if matched, _ := filepath.Match("*_test.go", f); matched {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range regexp.MustCompile(`"(L-\d\d)"`).FindAllStringSubmatch(string(src), -1) {
			emitted[m[1]] = true
		}
	}
	for r := range emitted {
		if !config.KnownRules[r] {
			t.Errorf("lint emits %s, config.KnownRules lacks it", r)
		}
	}
	for r := range config.KnownRules {
		if !emitted[r] {
			t.Errorf("config.KnownRules has %s, lint never emits it", r)
		}
	}
}
