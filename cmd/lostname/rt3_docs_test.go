package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// RT3: model.md section 7 lists every command run() dispatches, with flags that exist.
func TestRT3ModelCommandTable(t *testing.T) {
	b, _ := os.ReadFile("../../docs/model.md")
	doc := string(b)
	sec := doc[strings.Index(doc, "## 7. Commands"):strings.Index(doc, "## 8. Threats")]
	for _, c := range []string{"lint", "parity", "fetch", "mail", "watch", "config"} {
		if !strings.Contains(sec, "`"+c) {
			t.Errorf("model.md section 7 has no row for shipped command %q", c)
		}
	}
	for _, f := range []string{"../../docs/model.md", "../../README.md"} {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "parity --providers") {
			t.Errorf("%s documents parity --providers A,B; the flag is --provider NAME=ADDR (repeat)", f)
		}
	}
}

// RT3: every M-rule lostname mail emits is described in a public doc (docs/*.md).
func TestRT3MailRulesDocumented(t *testing.T) {
	src, _ := os.ReadFile("../../internal/records/records.go")
	files, _ := filepath.Glob("../../docs/*.md")
	var docs string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		docs += string(b)
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`"(M-\d\d)"`).FindAllStringSubmatch(string(src), -1) {
		if !seen[m[1]] && !strings.Contains(docs, m[1]) {
			t.Errorf("mail rule %s is emitted but not described in docs/", m[1])
		}
		seen[m[1]] = true
	}
}
