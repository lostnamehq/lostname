package watch

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func obsDoc(t *testing.T) string {
	b, err := os.ReadFile("../../docs/observability.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// RT3: the stated series budget per zone (two providers, no exit block) equals what families() emits.
func TestRT3SeriesBudgetMatches(t *testing.T) {
	m := regexp.MustCompile(`two checks .lint. and .parity.: (\d+) series`).FindStringSubmatch(obsDoc(t))
	if m == nil {
		t.Fatal("no series budget in observability.md")
	}
	want, _ := strconv.Atoi(m[1])
	s := NewSnapshot()
	now := time.Unix(1e9, 0)
	s.Record(CheckResult{Zone: "z.", Check: "lint", Verdict: "pass", Finished: now,
		LintFindings: map[string]int{"blocker": 0, "risk": 0, "note": 0}})
	s.Record(CheckResult{Zone: "z.", Check: "parity", Verdict: "pass", Finished: now,
		Mismatches: map[[2]string]int{{"A", "B"}: 0}, Answering: map[string]int{"A": 2, "B": 2},
		Expected: map[string]int{"A": 2, "B": 2}, DNSSEC: map[string]string{"A": "secure", "B": "secure"},
		SigExpiry: map[string]int64{"A": 1, "B": 1}})
	got := 0
	for _, f := range s.families() {
		got += len(f.samples)
	}
	if got != want {
		t.Errorf("observability.md says %d series per zone; families() emits %d", want, got)
	}
}

// RT3: the checks named in the doc are the checks Round runs (lint, parity, exit).
func TestRT3CheckNamesMatch(t *testing.T) {
	doc := obsDoc(t)
	if strings.Contains(doc, "`dnssec`)") {
		t.Errorf("observability.md lists a `dnssec` check; Round runs only lint, parity and exit")
	}
	if !strings.Contains(doc, "lostname.check.exit") {
		t.Errorf("traces section names root spans lint and parity only; the exit check emits lostname.check.exit too")
	}
}

// RT3: the doc must not promise lostname.zone.id (keyed hash of the zone) while nothing implements it: either code
// implements it, or the doc says it is not built.
func TestRT3ZoneIDImplemented(t *testing.T) {
	doc := obsDoc(t)
	if !strings.Contains(doc, "lostname.zone.id") || strings.Contains(doc, "It is not built yet") {
		return
	}
	for _, f := range []string{"../config/config.go", "events.go", "metrics.go", "otlp.go", "traces.go"} {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "zone.id") || strings.Contains(string(b), "zone_id") {
			return
		}
	}
	t.Errorf("observability.md documents lostname.zone.id (HMAC zone label, event subject); no code implements it")
}
