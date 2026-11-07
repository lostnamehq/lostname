// Package watch runs Lostname's checks on an interval and exposes their results as metrics (docs/observability.md,
// decision 0007): an OpenMetrics endpoint now, OTLP push next. A missing measurement is never zero: when a check
// ends in no_verdict, its result series are left out, and only its verdict and duration are emitted.
package watch

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Verdicts a check can end in; the stateset lostname_check_verdict has one series per state.
var Verdicts = []string{"pass", "fail", "no_verdict"}

// CheckResult is the outcome of one run of one check on one zone.
type CheckResult struct {
	Zone     string
	Check    string // lint or parity
	Verdict  string // pass, fail or no_verdict
	Duration time.Duration
	Finished time.Time
	// Result series, emitted only when Verdict is not no_verdict.
	LintFindings map[string]int // severity -> count
	Mismatches   map[[2]string]int
	Answering    map[string]int    // provider -> nameserver addresses that answered authoritatively
	Expected     map[string]int    // provider -> addresses given
	DNSSEC       map[string]string // provider -> secure, insecure, bogus or indeterminate
	SigExpiry    map[string]int64  // provider -> seconds until its earliest valid RRSIG expires
	Findings     []Finding         // for the events; empty without a verdict
	Trace        *Trace            // when watch.traces is on
	Probed       bool              // parity: the interception probe ran this round (clean or not)
	ExitTime     int               // exit check: seconds from the first change until caches drain
	ExitModel    string            // exit check: T0, T1 or T2
	ExitTarget   int               // exit check: the objective, seconds (config, so emitted with or without a verdict)
}

// DNSSECStates are the states of lostname_dnssec_status.
var DNSSECStates = []string{"secure", "insecure", "bogus", "indeterminate"}

// Snapshot is the latest result of every check on every zone, plus the interception probe.
type Snapshot struct {
	mu          sync.Mutex
	results     map[[2]string]CheckResult // (zone, check) -> latest
	lastSuccess map[[2]string]time.Time   // (zone, check) -> last run that ended with a verdict
	intercepted *bool                     // unknown until a parity run has probed
	zoneKey     []byte                    // the keyed-hash zone label's key; nil for raw zone names
}

// SetZoneKey switches on the keyed-hash zone label: every result recorded after it carries the zone's id, never its
// name (see zoneid.go).
func (s *Snapshot) SetZoneKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zoneKey = append([]byte(nil), key...)
}

func NewSnapshot() *Snapshot {
	return &Snapshot{results: map[[2]string]CheckResult{}, lastSuccess: map[[2]string]time.Time{}}
}

// Record stores a result. A no_verdict run replaces the result series (they become absent) but keeps the last
// success time, so "silence" alerts see when a verdict last arrived.
func (s *Snapshot) Record(r CheckResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.zoneKey != nil {
		r = anonymise(s.zoneKey, r)
	}
	k := [2]string{r.Zone, r.Check}
	s.results[k] = r
	if r.Verdict != "no_verdict" {
		s.lastSuccess[k] = r.Finished
	}
}

// Results returns the latest result of every check on every zone.
func (s *Snapshot) Results() []CheckResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CheckResult, 0, len(s.results))
	for _, r := range s.results {
		out = append(out, r)
	}
	return out
}

// SetIntercepted records the last interception probe result.
func (s *Snapshot) SetIntercepted(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.intercepted = &v
}

type family struct {
	name, typ, unit, help string
	samples               []sample
}

type sample struct {
	labels [][2]string
	value  float64
}

// families builds every metric family from the snapshot, in a stable order. OpenMetrics and OTLP both write from
// it, so the two ways out always carry the same data (docs/observability.md, "Two ways out, same data").
func (s *Snapshot) families() []family {
	s.mu.Lock()
	defer s.mu.Unlock()
	verdict := family{name: "lostname_check_verdict", typ: "stateset", help: "the last verdict of each check"}
	success := family{name: "lostname_check_last_success_timestamp_seconds", typ: "gauge", unit: "seconds",
		help: "when the check last finished with a verdict"}
	duration := family{name: "lostname_check_duration_seconds", typ: "gauge", unit: "seconds",
		help: "duration of the last run"}
	findings := family{name: "lostname_lint_findings", typ: "gauge", help: "findings of the last lint run"}
	mismatches := family{name: "lostname_parity_mismatches", typ: "gauge",
		help: "RRsets that differ between two providers in the last parity run"}
	answering := family{name: "lostname_parity_servers_answering", typ: "gauge",
		help: "nameserver addresses that answered authoritatively (AA), over UDP and TCP"}
	expected := family{name: "lostname_parity_servers_expected", typ: "gauge",
		help: "nameserver addresses given for the provider"}
	dnssec := family{name: "lostname_dnssec_status", typ: "stateset",
		help: "validation result of the zone's chain, per provider"}
	expiry := family{name: "lostname_dnssec_signature_expiry_seconds", typ: "gauge", unit: "seconds",
		help: "time until the earliest RRSIG expiration seen at that provider"}
	exitTime := family{name: "lostname_exit_time_seconds", typ: "gauge", unit: "seconds",
		help: "exit time under the zone's exit model and registry lock, caches drained; modelled, not measured"}
	exitTarget := family{name: "lostname_exit_target_seconds", typ: "gauge", unit: "seconds",
		help: "the zone's exit-time objective"}
	exitReady := family{name: "lostname_exit_ready", typ: "gauge",
		help: "1 when the modelled exit fits the objective and the standby is in parity: the SLI of exit readiness"}
	intercepted := family{name: "lostname_probe_intercepted", typ: "gauge",
		help: "1 when the interception probe got an answer; every verdict over that path is then no_verdict"}

	keys := make([][2]string, 0, len(s.results))
	for k := range s.results {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"\x00"+keys[i][1] < keys[j][0]+"\x00"+keys[j][1] })
	for _, k := range keys {
		r := s.results[k]
		zc := [][2]string{{"zone", r.Zone}, {"check", r.Check}}
		for _, v := range Verdicts {
			verdict.add(append(clone(zc), [2]string{"lostname_check_verdict", v}), b2f(r.Verdict == v))
		}
		duration.add(zc, r.Duration.Seconds())
		if t, ok := s.lastSuccess[k]; ok {
			success.add(zc, float64(t.Unix()))
		}
		if r.Check == "exit" {
			exitTarget.add([][2]string{{"zone", r.Zone}}, float64(r.ExitTarget))
		}
		if r.Verdict == "no_verdict" {
			continue // a missing measurement is never zero: the result series are left out
		}
		if r.Check == "exit" {
			if r.ExitModel != "" {
				exitTime.add([][2]string{{"zone", r.Zone}, {"model", r.ExitModel}, {"basis", "modelled"}},
					float64(r.ExitTime))
			}
			// basis says where the number comes from: "modelled" (the simulator) until rehearsals measure exits.
			exitReady.add([][2]string{{"zone", r.Zone}, {"basis", "modelled"}}, b2f(r.Verdict == "pass"))
		}
		for _, sev := range []string{"blocker", "risk", "note"} {
			if r.LintFindings != nil {
				findings.add([][2]string{{"zone", r.Zone}, {"severity", sev}}, float64(r.LintFindings[sev]))
			}
		}
		for _, pair := range sortedPairs(r.Mismatches) {
			mismatches.add([][2]string{{"zone", r.Zone}, {"provider_a", pair[0]}, {"provider_b", pair[1]}},
				float64(r.Mismatches[pair]))
		}
		for _, p := range sortedKeys(r.Expected) {
			answering.add([][2]string{{"zone", r.Zone}, {"provider", p}}, float64(r.Answering[p]))
			expected.add([][2]string{{"zone", r.Zone}, {"provider", p}}, float64(r.Expected[p]))
		}
		for _, p := range sortedStateKeys(r.DNSSEC) {
			for _, st := range DNSSECStates {
				dnssec.add([][2]string{{"zone", r.Zone}, {"provider", p}, {"lostname_dnssec_status", st}},
					b2f(r.DNSSEC[p] == st))
			}
			if e, ok := r.SigExpiry[p]; ok {
				expiry.add([][2]string{{"zone", r.Zone}, {"provider", p}}, float64(e))
			}
		}
	}
	if s.intercepted != nil {
		intercepted.add(nil, b2f(*s.intercepted))
	}
	return []family{verdict, success, duration, findings, mismatches, answering, expected, dnssec, expiry, exitTime,
		exitTarget, exitReady, intercepted}
}

// WriteOpenMetrics writes the snapshot in the OpenMetrics 1.0 text format, families and samples in a stable order.
func (s *Snapshot) WriteOpenMetrics(w io.Writer) error {
	var b strings.Builder
	for _, f := range s.families() {
		if len(f.samples) == 0 {
			continue
		}
		fmt.Fprintf(&b, "# TYPE %s %s\n", f.name, f.typ)
		if f.unit != "" {
			fmt.Fprintf(&b, "# UNIT %s %s\n", f.name, f.unit)
		}
		fmt.Fprintf(&b, "# HELP %s %s\n", f.name, f.help)
		for _, smp := range f.samples {
			b.WriteString(f.name)
			if len(smp.labels) > 0 {
				b.WriteByte('{')
				for i, l := range smp.labels {
					if i > 0 {
						b.WriteByte(',')
					}
					fmt.Fprintf(&b, `%s="%s"`, l[0], escape(l[1]))
				}
				b.WriteByte('}')
			}
			b.WriteByte(' ')
			b.WriteString(strconv.FormatFloat(smp.value, 'f', -1, 64))
			b.WriteByte('\n')
		}
	}
	b.WriteString("# EOF\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func (f *family) add(labels [][2]string, v float64) {
	f.samples = append(f.samples, sample{labels: labels, value: v})
}

func clone(l [][2]string) [][2]string { return append([][2]string(nil), l...) }

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// escape is OpenMetrics label-value escaping and nothing else (red team 2, W5): backslash, double quote and line feed
// become \\, \" and \n; every other character, UTF-8 included, stays as it is, so the value equals what OTLP carries.
func escape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStateKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedPairs(m map[[2]string]int) [][2]string {
	out := make([][2]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0]+"\x00"+out[i][1] < out[j][0]+"\x00"+out[j][1] })
	return out
}
