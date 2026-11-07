package parity

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/authtest"
)

func gapsWith(r Report, text string) int {
	n := 0
	for _, g := range r.Gaps {
		if strings.Contains(g.Reason, text) {
			n++
		}
	}
	return n
}

// A spent budget or a reached deadline stops asking, and the questions left are gaps: no verdict, never a partial
// pass. The report counts the queries per server.
func TestBudgetAndDeadlineGiveNoVerdict(t *testing.T) {
	z := zoneOf(t, base)
	a, b := authtest.Start(t, z, authtest.None), authtest.Start(t, z, authtest.None)
	ps := []Provider{{"A", []string{a.Addr}}, {"B", []string{b.Addr}}}

	o := opts(t, "T0", quiet(t))
	full := mustRun(t, z, ps, o)
	if full.Verdict != "pass" || full.Queries[a.Addr] == 0 || full.Queries[b.Addr] == 0 {
		t.Fatalf("without limits: %s, queries %v", full.Verdict, full.Queries)
	}

	o.MaxQueries = 3
	r := mustRun(t, z, ps, o)
	if r.Verdict != "no_verdict" || gapsWith(r, "query budget") == 0 || r.Queries[a.Addr] > 3 {
		t.Errorf("budget 3: %s, %d budget gaps, queries %v", r.Verdict, gapsWith(r, "query budget"), r.Queries)
	}

	o.MaxQueries, o.Deadline = 0, time.Nanosecond
	r = mustRun(t, z, ps, o)
	if r.Verdict != "no_verdict" || gapsWith(r, "deadline") == 0 {
		t.Errorf("deadline 1 ns: %s, %d deadline gaps", r.Verdict, gapsWith(r, "deadline"))
	}
}

// Pacing spaces the queries to one server: n queries take at least (n-1) times the pace.
func TestPaceSpacesQueries(t *testing.T) {
	z := zoneOf(t, base)
	a, b := authtest.Start(t, z, authtest.None), authtest.Start(t, z, authtest.None)
	o := opts(t, "T0", quiet(t))
	o.Pace = 15 * time.Millisecond
	start := time.Now()
	r := mustRun(t, z, []Provider{{"A", []string{a.Addr}}, {"B", []string{b.Addr}}}, o)
	if n := r.Queries[a.Addr]; time.Since(start) < time.Duration(n-1)*o.Pace {
		t.Errorf("%d queries to A in %s with a pace of %s", n, time.Since(start), o.Pace)
	}
}

// A server that answered and then refuses is labelled as possibly rate limiting, not just as refusing.
func TestRateLimitIsLabelled(t *testing.T) {
	z := zoneOf(t, base)
	a := authtest.Start(t, z, authtest.None)
	up := authtest.Start(t, z, authtest.None)
	var n atomic.Int32
	b := proxy(t, up.Addr, func(req, resp *dns.Msg, _ string) *dns.Msg {
		if n.Add(1) > 6 {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			return m
		}
		return resp
	})
	r := runRT(t, z, opts(t, "T0", quiet(t)), a.Addr, b)
	if r.Verdict != "no_verdict" || gapsWith(r, "possibly rate limited") == 0 {
		t.Errorf("B throttles after 6 queries: %s, %d rate-limit gaps", r.Verdict, gapsWith(r, "possibly rate limited"))
	}
}
