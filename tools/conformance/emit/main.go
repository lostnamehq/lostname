// Command emit pushes the conformance fixture (docs/observability.md, "Conformance") to an OTLP/HTTP endpoint with
// Lostname's own OTLP code: zone seen.test. with a verdict on every check, and zone blind.test., whose parity run
// ended in no_verdict. A stack conforms when queries return exactly the expected values for seen.test. and nothing
// for blind.test.'s result series (absent, never zero).
//
// Usage: emit http://collector:4318
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"lostname.be/lostname/internal/watch"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: emit OTLP_ENDPOINT")
		os.Exit(3)
	}
	now := time.Now()
	s := watch.NewSnapshot()
	s.Record(watch.CheckResult{Zone: "seen.test.", Check: "lint", Verdict: "fail", Duration: 2 * time.Second,
		Finished: now, LintFindings: map[string]int{"blocker": 1, "risk": 2, "note": 3}})
	s.Record(watch.CheckResult{Zone: "seen.test.", Check: "parity", Verdict: "fail", Duration: 5 * time.Second,
		Finished: now, Mismatches: map[[2]string]int{{"A", "B"}: 2},
		Answering: map[string]int{"A": 2, "B": 1}, Expected: map[string]int{"A": 2, "B": 2},
		DNSSEC: map[string]string{"A": "secure", "B": "bogus"}, SigExpiry: map[string]int64{"A": 86400}})
	// The blind zone: a parity run without a verdict. Its result series carry zero-filled values, as the runner's
	// do, so only the absence rule keeps them out of the push.
	s.Record(watch.CheckResult{Zone: "blind.test.", Check: "parity", Verdict: "no_verdict", Duration: 7 * time.Second,
		Finished: now, Mismatches: map[[2]string]int{{"A", "B"}: 0}, Answering: map[string]int{"A": 0, "B": 0},
		Expected: map[string]int{"A": 2, "B": 2}, DNSSEC: map[string]string{"A": "indeterminate"}})
	s.SetIntercepted(false)
	if err := s.Push(&http.Client{Timeout: 30 * time.Second}, os.Args[1], "conformance",
		map[string]string{"site": "lab"}); err != nil {
		fmt.Fprintln(os.Stderr, "emit:", err)
		os.Exit(1)
	}
	fmt.Println("emit: pushed the fixture to", os.Args[1])
}
