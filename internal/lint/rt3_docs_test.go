package lint

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"

	"lostname.be/lostname/internal/config"
)

// RT3: every rule lint emits has a row in model.md section 3 (SARIF help points readers there).
func TestRT3ModelRuleTableHasEveryShippedRule(t *testing.T) {
	b, err := os.ReadFile("../../docs/model.md")
	if err != nil {
		t.Fatal(err)
	}
	sec := string(b)
	sec = sec[strings.Index(sec, "## 3. Lint rules"):strings.Index(sec, "## 4. Parity")]
	rows := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\| (L-\d\d) \|`).FindAllStringSubmatch(sec, -1) {
		rows[m[1]] = true
	}
	var missing []string
	for r := range config.KnownRules {
		if !rows[r] {
			missing = append(missing, r)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("lint emits rules with no row in model.md section 3: %v", missing)
	}
}

// RT3: ROADMAP's v0.1 lint line "names exactly the lint rules it ships" (changelog roadmap-v010).
func TestRT3RoadmapNamesShippedRules(t *testing.T) {
	b, err := os.ReadFile("../../ROADMAP.md")
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "- **`lint`**") {
			line = l
		}
	}
	named := map[string]bool{}
	for _, m := range regexp.MustCompile(`L-(\d\d)(?: to L-(\d\d))?`).FindAllStringSubmatch(line, -1) {
		lo := m[1]
		hi := lo
		if m[2] != "" {
			hi = m[2]
		}
		for i := atoi(lo); i <= atoi(hi); i++ {
			named[rid(i)] = true
		}
	}
	for r := range config.KnownRules {
		if !named[r] {
			t.Errorf("ROADMAP v0.1 lint line does not name shipped rule %s", r)
		}
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
func rid(i int) string { return "L-" + string(rune('0'+i/10)) + string(rune('0'+i%10)) }

// RT3 and decision 0008: lint makes no network calls. Direct imports are guarded by TestNoNetworkImports. In the
// transitive graph, net comes with miekg/dns (address types) and net/http only through golang.org/x/net/publicsuffix,
// which imports net/http/cookiejar for an interface; no other path may bring an HTTP client in.
func TestRT3LintGraphHasNoHTTP(t *testing.T) {
	for _, pkg := range []string{".", "../records", "../zone"} {
		out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", pkg).Output()
		if err != nil {
			t.Skip("go list:", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || strings.HasPrefix(f[0], "net/") || f[0] == "net" {
				continue // the standard library's own internals
			}
			for _, imp := range f[1:] {
				switch {
				case imp == "net/http/cookiejar" && f[0] == "golang.org/x/net/publicsuffix":
				case imp == "net/http" || strings.HasPrefix(imp, "net/http/"):
					t.Errorf("%s: %s imports %s: an HTTP path into lint's graph", pkg, f[0], imp)
				}
			}
		}
	}
}
