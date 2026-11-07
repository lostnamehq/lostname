package watch

import (
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, s *Snapshot) string {
	t.Helper()
	var b strings.Builder
	if err := s.WriteOpenMetrics(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// The contract's central rule: a no_verdict run leaves its result series out (absent, never zero), while the verdict,
// the duration and the last success time stay.
func TestNoVerdictIsAbsentNotZero(t *testing.T) {
	s := NewSnapshot()
	t0 := time.Unix(1_800_000_000, 0)
	s.Record(CheckResult{Zone: "example.test.", Check: "parity", Verdict: "pass", Duration: 2 * time.Second, Finished: t0,
		Mismatches: map[[2]string]int{{"A", "B"}: 0}, Answering: map[string]int{"A": 2, "B": 2},
		Expected: map[string]int{"A": 2, "B": 2}})
	s.Record(CheckResult{Zone: "example.test.", Check: "lint", Verdict: "fail", Duration: time.Second, Finished: t0,
		LintFindings: map[string]int{"blocker": 1}})
	s.SetIntercepted(false)
	out := scrape(t, s)
	for _, want := range []string{
		`lostname_parity_mismatches{zone="example.test.",provider_a="A",provider_b="B"} 0`,
		`lostname_lint_findings{zone="example.test.",severity="blocker"} 1`,
		`lostname_lint_findings{zone="example.test.",severity="note"} 0`,
		`lostname_check_verdict{zone="example.test.",check="lint",lostname_check_verdict="fail"} 1`,
		`lostname_check_last_success_timestamp_seconds{zone="example.test.",check="parity"} 1800000000`,
		"# UNIT lostname_check_duration_seconds seconds",
		"lostname_probe_intercepted 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if !strings.HasSuffix(out, "# EOF\n") {
		t.Error("OpenMetrics ends with # EOF")
	}

	// The next parity run is blind: its result series go, its verdict says so, the last success stays. The result
	// carries zero-filled series, as the runner's does, so only the absence rule can keep them out.
	s.Record(CheckResult{Zone: "example.test.", Check: "parity", Verdict: "no_verdict", Duration: 3 * time.Second,
		Finished: t0.Add(time.Minute), Mismatches: map[[2]string]int{{"A", "B"}: 0},
		Answering: map[string]int{"A": 0, "B": 0}, Expected: map[string]int{"A": 2, "B": 2}})
	out = scrape(t, s)
	for _, gone := range []string{"lostname_parity_mismatches{", "lostname_parity_servers_answering{"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s must be absent after no_verdict, got\n%s", gone, out)
		}
	}
	for _, want := range []string{
		`lostname_check_verdict{zone="example.test.",check="parity",lostname_check_verdict="no_verdict"} 1`,
		`lostname_check_duration_seconds{zone="example.test.",check="parity"} 3`,
		`lostname_check_last_success_timestamp_seconds{zone="example.test.",check="parity"} 1800000000`,
		`lostname_lint_findings{zone="example.test.",severity="blocker"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s after no_verdict", want)
		}
	}
	if scrape(t, s) != out {
		t.Error("two scrapes of the same snapshot must be byte-identical")
	}
}

// Red team 2, W5: only backslash, quote and line feed are escaped, and values that differ stay different.
func TestLabelEscaping(t *testing.T) {
	s := NewSnapshot()
	s.Record(CheckResult{Zone: "example.test.", Check: "parity", Verdict: "pass", Finished: time.Unix(0, 0),
		Expected:  map[string]int{"tab\there": 1, "nbsp\u00a0x": 1, "nl\nx": 1, "nl x": 1, `q"b\s`: 1},
		Answering: map[string]int{}})
	out := scrape(t, s)
	for _, want := range []string{`provider="tab` + "\t" + `here"`, `provider="nbsp` + "\u00a0" + `x"`,
		`provider="nl\nx"`, `provider="nl x"`, `provider="q\"b\\s"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}
