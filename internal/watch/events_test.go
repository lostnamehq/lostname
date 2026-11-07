package watch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lostname.be/lostname/internal/config"
)

func types(evs []Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, fmt.Sprintf("%s %v %v", e.Type, e.Data["rule"], e.Data["to"]))
	}
	return out
}

func newTestTracker() *Tracker {
	n := 0
	t := NewTracker("test1", map[string]string{"site": "brussels", "risk_id": "R-7"})
	t.newID = func() string { n++; return fmt.Sprintf("id-%d", n) }
	return t
}

func TestEventsFollowTheRounds(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	l08 := Finding{Rule: "L-08", Severity: "blocker", Name: "www.example.test.", Type: "CNAME", Ref: "RFC 1034 3.6.2"}
	l15 := Finding{Rule: "L-15", Severity: "risk", Name: "example.test.", Type: "NS", Ref: "RFC 1034 4.1"}
	lint := func(verdict string, fs ...Finding) []CheckResult {
		return []CheckResult{{Zone: "example.test.", Check: "lint", Verdict: verdict, Findings: fs}}
	}
	tr := newTestTracker()
	steps := []struct {
		name    string
		results []CheckResult
		want    []string
	}{
		{"first round: the verdict from nothing, every finding opens", lint("fail", l08),
			[]string{TypeVerdictChanged + " <nil> fail", TypeFindingOpened + " L-08 <nil>"}},
		{"the same round again: nothing", lint("fail", l08), nil},
		{"one finding fixed, another appears", lint("fail", l15),
			[]string{TypeFindingOpened + " L-15 <nil>", TypeFindingClosed + " L-08 <nil>"}},
		// A round without a verdict knows nothing about the findings: none closes.
		{"no verdict", lint("no_verdict"), []string{TypeVerdictChanged + " <nil> no_verdict"}},
		{"back, same finding: only the verdict", lint("fail", l15), []string{TypeVerdictChanged + " <nil> fail"}},
		{"all fixed", lint("pass"), []string{TypeVerdictChanged + " <nil> pass", TypeFindingClosed + " L-15 <nil>"}},
	}
	for _, st := range steps {
		got := types(tr.Observe(st.results, nil, "run", now))
		if strings.Join(got, "\n") != strings.Join(st.want, "\n") {
			t.Errorf("%s:\n got %q\nwant %q", st.name, got, st.want)
		}
	}
}

func TestInterceptionEventOncePerEpisode(t *testing.T) {
	tr := newTestTracker()
	hit := &Interception{Probe: "203.0.113.1:53", Protocols: []string{"udp", "tcp"}}
	// A round is (probe answer, whether a probe ran): only a probe that ran clean ends the episode.
	count := func(p *Interception, probed bool) int {
		n := 0
		rs := []CheckResult{{Zone: "z.", Check: "parity", Verdict: "no_verdict", Probed: probed}}
		for _, e := range tr.Observe(rs, p, "run", time.Now()) {
			if e.Type == TypeIntercepted {
				n++
			}
		}
		return n
	}
	for i, tc := range []struct {
		probe  *Interception
		probed bool
		want   int
	}{{hit, true, 1}, {hit, true, 0}, {nil, false, 0}, {hit, true, 0}, {nil, true, 0}, {hit, true, 1}} {
		if got := count(tc.probe, tc.probed); got != tc.want {
			t.Errorf("round %d: %d interception events, want %d", i, got, tc.want)
		}
	}
}

func TestEventJSONIsStructuredCloudEvent(t *testing.T) {
	tr := newTestTracker()
	evs := tr.Observe([]CheckResult{{Zone: "example.test.", Check: "parity", Verdict: "fail",
		Findings: []Finding{{Rule: "rrset-differs", Severity: "fail", Name: "www.example.test.", Type: "A",
			Provider: "B"}}}}, nil, "run-1", time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC))
	b, err := json.Marshal(evs[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"specversion": "1.0", "id": "id-2", "source": "lostname/test1",
		"type": TypeFindingOpened, "subject": "example.test.", "time": "2026-11-06T12:00:00Z",
		"datacontenttype": "application/json", "site": "brussels", "riskids": "R-7", "severity": "fail"} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
	d := m["data"].(map[string]any)
	if d["provider"] != "B" || d["rule"] != "rrset-differs" || d["run_id"] != "run-1" {
		t.Errorf("data %v", d)
	}
}

// The contract: events carry no record data beyond the owner name and type. A lint message can quote record data
// (here the CAA value), so it must not reach an event.
func TestEventsCarryNoRecordData(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "z.zone")
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
		"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\n@ IN CAA 0 issue \"secret-ca.example\"\n"
	if err := os.WriteFile(zp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Watch.Zones = []config.WatchZone{{Origin: "example.test", ZoneFile: zp}}
	s := NewSnapshot()
	Round(cfg, s, time.Now)
	evs := newTestTracker().Observe(s.Results(), nil, "run", time.Now())
	b, _ := json.Marshal(evs)
	logs, _ := OTLPLogsJSON(evs, "test", nil)
	if !strings.Contains(string(b), TypeFindingOpened) {
		t.Fatalf("the CAA without accounturi should open a finding: %s", b)
	}
	for _, out := range [][]byte{b, logs} {
		if strings.Contains(string(out), "secret-ca") {
			t.Errorf("record data in the events: %s", out)
		}
	}
}

func TestEventTransports(t *testing.T) {
	var gotCT, gotPath []string
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotCT, gotPath, bodies = append(gotCT, r.Header.Get("Content-Type")), append(gotPath, r.URL.Path),
			append(bodies, string(b))
	}))
	defer srv.Close()
	evs := newTestTracker().Observe([]CheckResult{{Zone: "a.test.", Check: "lint", Verdict: "pass"},
		{Zone: "b.test.", Check: "lint", Verdict: "pass"}}, nil, "run", time.Now())
	if err := SendHTTP(srv.Client(), srv.URL+"/ce", evs); err != nil {
		t.Fatal(err)
	}
	if err := PushLogs(srv.Client(), srv.URL, "test", map[string]string{"tenant": "t1"}, evs); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 3 || gotCT[0] != "application/cloudevents+json" || gotPath[2] != "/v1/logs" {
		t.Fatalf("one POST per event, then one logs request: %q %q", gotCT, gotPath)
	}
	for _, want := range []string{`"cloudevents.event_type"`, `"cloudevents.site"`, `"tenant"`} {
		if !strings.Contains(bodies[2], want) {
			t.Errorf("logs request lacks %s: %s", want, bodies[2])
		}
	}
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer refuse.Close()
	if err := SendHTTP(refuse.Client(), refuse.URL, evs); err == nil || !strings.Contains(err.Error(), "0 of 2 delivered") {
		t.Errorf("a refused delivery must say how many arrived: %v", err)
	}
}

// A finding fixed while watch was down is closed after the restart, because the state survives it; zones that left
// the config are pruned; a state file of another instance is refused.
func TestStateSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	l08 := Finding{Rule: "L-08", Severity: "blocker", Name: "www.example.test.", Type: "CNAME", Ref: "RFC 1034 3.6.2"}
	first := newTestTracker()
	first.Observe([]CheckResult{{Zone: "example.test.", Check: "lint", Verdict: "fail", Findings: []Finding{l08}},
		{Zone: "gone.test.", Check: "lint", Verdict: "pass"}}, nil, "r1", time.Now())
	first.Prune([]CheckResult{{Zone: "example.test.", Check: "lint"}})
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	// Restart: a new tracker, the old state, and the finding fixed in the meantime.
	second := newTestTracker()
	if err := second.Load(path); err != nil {
		t.Fatal(err)
	}
	got := types(second.Observe([]CheckResult{{Zone: "example.test.", Check: "lint", Verdict: "pass"}}, nil, "r2",
		time.Now()))
	want := []string{TypeVerdictChanged + " <nil> pass", TypeFindingClosed + " L-08 <nil>"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("after the restart: got %q, want %q", got, want)
	}
	rs := second.Resync("r2", time.Now())
	b, _ := json.Marshal(rs)
	if rs.Type != TypeResync || strings.Contains(string(b), "gone.test") || !strings.Contains(string(b), `"open_findings":[]`) {
		t.Errorf("resync %s", b)
	}
	other := NewTracker("another-instance", nil)
	if err := other.Load(path); err == nil {
		t.Error("a state file of another instance must be refused")
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newTestTracker().Load(path); err == nil {
		t.Error("a corrupt state file must be refused")
	}
}
