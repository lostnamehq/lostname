package watch

// Red team 3 on the watch features: each test asserts the contract and fails on the code as it was.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/config"
	"lostname.be/lostname/internal/zone"
)

const rt3Src = "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
	"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\nwww IN A 192.0.2.80\n"

func rt3Zone(t *testing.T, src string) *zone.Zone {
	t.Helper()
	z, err := zone.Read(strings.NewReader(src), "t", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func rt3Cfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Probe.Canary, cfg.Probe.CanaryV6, cfg.Probe.Timeout, cfg.Parity.Timeout = "127.0.0.1:1", "[::1]:1", 1, 1
	return cfg
}

// W3-1: LostnameChecksSilent is built on series that vanish when watch itself stops (scrape target down, or no more
// OTLP pushes): time() - <absent> is empty, so the alert whose action is "check that watch is running" cannot fire
// when watch is not running. A rule on absent()/absent_over_time() (or up) is needed.
func TestRT3SilentAlertFiresWhenWatchStops(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "alerts", "lostname.rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`absent(_over_time)?\(\s*lostname_|up\{[^}]*\}\s*==\s*0`).Match(b) {
		t.Errorf("no rule fires when the lostname series disappear altogether (watch stopped); " +
			"LostnameChecksSilent only ages a timestamp that is then absent")
	}
}

// W3-2: an interception episode is one event. A round in which the probe did not run (zone file unreadable, so
// parity never probed) is not "the path is clean again"; the gauge knows that (probed flag), the tracker does not
// and opens a second episode.
func TestRT3InterceptionEpisodeSurvivesAnUnprobedRound(t *testing.T) {
	z := rt3Zone(t, rt3Src)
	a := authtest.Start(t, z, authtest.None)
	zp := filepath.Join(t.TempDir(), "z.zone")
	if err := os.WriteFile(zp, []byte(rt3Src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := rt3Cfg(t)
	cfg.Probe.Canary = a.Addr // the canary answers: the path is intercepted
	cfg.Watch.Zones = []config.WatchZone{{Origin: "example.test", ZoneFile: zp, Providers: []config.WatchProvider{
		{Name: "A", Addrs: []string{a.Addr}}, {Name: "B", Addrs: []string{a.Addr}}}}}
	s, tr := NewSnapshot(), NewTracker("t", nil)
	n := 0
	round := func() {
		caught := Round(cfg, s, time.Now) // first: Observe takes this round's results (arguments evaluate left to right)
		for _, e := range tr.Observe(s.Results(), caught, "run", time.Now()) {
			if e.Type == TypeIntercepted {
				n++
			}
		}
	}
	round()
	if n != 1 {
		t.Fatalf("setup: %d interception events in round 1, want 1", n)
	}
	cfg.Watch.Zones[0].ZoneFile = zp + ".missing" // round 2: nothing probes
	round()
	cfg.Watch.Zones[0].ZoneFile = zp // round 3: still intercepted
	round()
	if n != 1 {
		t.Errorf("one episode, %d interception events: an unprobed round ended the episode", n)
	}
}

// W3-3: exit readiness under T2 requires the standby in parity under T2 (apex NS must match), but parity runs under
// parity.model (T0 by default), which tolerates a differing apex NS. The zone reads "ready" for a multi-signer exit
// whose standby is not in T2 parity.
func TestRT3ExitReadinessUsesTheExitModelsParity(t *testing.T) {
	bSrc := strings.Replace(rt3Src, "@ IN NS ns2\n", "@ IN NS ns3\nns3 IN A 203.0.113.53\n", 1)
	a := authtest.Start(t, rt3Zone(t, rt3Src), authtest.None)
	b := authtest.Start(t, rt3Zone(t, bSrc), authtest.None)
	zp := filepath.Join(t.TempDir(), "z.zone")
	if err := os.WriteFile(zp, []byte(rt3Src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := rt3Cfg(t)
	cfg.Watch.Zones = []config.WatchZone{{Origin: "example.test", ZoneFile: zp,
		Providers: []config.WatchProvider{{Name: "A", Addrs: []string{a.Addr}}, {Name: "B", Addrs: []string{b.Addr}}},
		Exit:      &config.WatchExit{Model: "T2", Lock: "none", Target: 1 << 40}}}
	if os.Getenv("RT3_CTRL") != "" {
		cfg.Parity.Model = "T2"
	}
	if err := cfg.Validate(); err != nil {
		return // refusing parity.model != exit.model is an acceptable fix
	}
	s := NewSnapshot()
	Round(cfg, s, time.Now)
	for _, r := range s.Results() {
		if r.Check == "exit" && r.Verdict == "pass" {
			t.Errorf("exit T2 ready although B's apex NS differs (parity ran as %s)", cfg.Parity.Model)
		}
	}
}

// W3-4: T0 is the unsigned-to-unsigned exit. On a zone that carries DNSKEYs it skips the DS removal, so following it
// makes the zone bogus; readiness must not pass on it.
func TestRT3T0OnASignedZoneIsNotReady(t *testing.T) {
	cfg, z, wz := exitSetup(t, "T0", "none", 1<<30)
	if r := exitResult(cfg, z, wz, "pass", time.Now); r.Verdict == "pass" {
		t.Errorf("T0 exit for a signed zone (DNSKEY at the apex) reads ready: exit %d s", r.ExitTime)
	}
}

// W3-5: the default client follows redirects. A 303 turns the POST into a GET without the event; the target's 200
// is counted as delivered. (A 307/308 re-posts the event body to whatever host the redirect names.)
func TestRT3EventRedirectIsNotDelivery(t *testing.T) {
	var gotBody []byte
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
	}))
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/elsewhere", http.StatusSeeOther)
	}))
	defer first.Close()
	ev := []Event{{ID: "1", Source: "lostname/t", Type: TypeVerdictChanged, Time: time.Now(), Data: map[string]any{}}}
	if err := SendHTTP(&http.Client{Timeout: 5 * time.Second}, first.URL, ev); err == nil {
		t.Errorf("a redirect was reported as delivered (the other host got %d body bytes)", len(gotBody))
	}
	first.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/elsewhere", http.StatusTemporaryRedirect)
	})
	gotBody = nil
	_ = SendHTTP(&http.Client{Timeout: 5 * time.Second}, first.URL, ev)
	if len(gotBody) > 0 {
		t.Errorf("307: the event was re-posted to another host: %s", gotBody)
	}
}

// W3-6: endpoint URLs may carry credentials (user:pass@); the delivery errors print the raw endpoint to stderr.
func TestRT3DeliveryErrorsHideCredentials(t *testing.T) {
	ev := []Event{{ID: "1", Source: "lostname/t", Type: TypeVerdictChanged, Time: time.Now(), Data: map[string]any{}}}
	c := &http.Client{Timeout: time.Second}
	ep := "http://user:s3cret@127.0.0.1:1"
	errs := []error{SendHTTP(c, ep, ev), PushLogs(c, ep, "v", nil, ev),
		PushTraces(c, ep, "v", nil, []CheckResult{{Zone: "z.", Check: "lint", Trace: NewTrace(time.Now())}}),
		NewSnapshot().Push(c, ep, "v", nil)}
	for i, err := range errs {
		if err != nil && strings.Contains(err.Error(), "s3cret") {
			t.Errorf("transport %d: the password is in the error: %v", i, err)
		}
	}
}

// W3-9: "Joined to the events": over OTLP logs the join is the log record's traceId/spanId (OTLP data model); a
// traceparent string attribute is not correlated by any backend.
func TestRT3OTLPLogRecordCarriesTraceContext(t *testing.T) {
	tr := NewTrace(time.Now())
	ev := Event{ID: "1", Source: "lostname/t", Type: TypeVerdictChanged, Time: time.Now(), Data: map[string]any{},
		Ext: map[string]string{"traceparent": tr.Traceparent()}}
	b, err := OTLPLogsJSON([]Event{ev}, "v", nil)
	if err != nil {
		t.Fatal(err)
	}
	var req struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					TraceID string `json:"traceId"`
					SpanID  string `json:"spanId"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	lr := req.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if lr.TraceID != tr.TraceID || lr.SpanID != tr.SpanID {
		t.Errorf("log record traceId %q spanId %q, want the check's %s/%s", lr.TraceID, lr.SpanID, tr.TraceID, tr.SpanID)
	}
}

// W3-10: "for 2 runs" at a 1 h interval: the condition is first true at run N and still true at run N+1 one hour
// later, so "for: 2h" fires only at run N+2 (three runs).
func TestRT3StandbyAlertIsTwoRuns(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "alerts", "lostname.rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)alert: LostnameStandbyNotInParity.*?for: (\S+)`).FindSubmatch(b)
	if m == nil || string(m[1]) != "1h" {
		t.Errorf("LostnameStandbyNotInParity for: %s; two runs at 3600 s is for: 1h", m[1])
	}
}
