package watch

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/config"
	"lostname.be/lostname/internal/zone"
)

type tracesDoc struct {
	ResourceSpans []struct {
		ScopeSpans []struct {
			Spans []struct {
				TraceID      string `json:"traceId"`
				SpanID       string `json:"spanId"`
				ParentSpanID string `json:"parentSpanId"`
				Name         string `json:"name"`
				Attributes   []struct {
					Key   string         `json:"key"`
					Value map[string]any `json:"value"`
				} `json:"attributes"`
				Status map[string]any `json:"status"`
			} `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

func tracedRound(t *testing.T, traces bool) (*Snapshot, string) {
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
		"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\nwww IN A 192.0.2.80\n"
	z, err := zone.Read(strings.NewReader(src), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	a, b := authtest.Start(t, z, authtest.None), authtest.Start(t, z, authtest.None)
	zp := filepath.Join(t.TempDir(), "z.zone")
	if err := os.WriteFile(zp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Probe.Canary, cfg.Probe.CanaryV6, cfg.Probe.Timeout, cfg.Parity.Timeout = "127.0.0.1:1", "[::1]:1", 1, 1
	cfg.Watch.Traces = traces
	cfg.Watch.Zones = []config.WatchZone{{Origin: "example.test", ZoneFile: zp, Providers: []config.WatchProvider{
		{Name: "A", Addrs: []string{a.Addr}}, {Name: "B", Addrs: []string{b.Addr}}}}}
	s := NewSnapshot()
	Round(cfg, s, time.Now)
	return s, a.Addr
}

func TestTraceHasASpanPerQuery(t *testing.T) {
	s, addrA := tracedRound(t, true)
	var parity CheckResult
	for _, r := range s.Results() {
		if r.Trace == nil {
			t.Fatalf("%s: traces are on, the result has none", r.Check)
		}
		if r.Check == "parity" {
			parity = r
		}
	}
	if parity.Verdict != "pass" || len(parity.Trace.Exchanges) == 0 {
		t.Fatalf("parity: verdict %s, %d exchanges", parity.Verdict, len(parity.Trace.Exchanges))
	}
	b, n, err := OTLPTracesJSON([]CheckResult{parity}, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(parity.Trace.Exchanges)+1 {
		t.Fatalf("%d spans for %d queries: want one root plus one per query", n, len(parity.Trace.Exchanges))
	}
	var doc tracesDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	sp := doc.ResourceSpans[0].ScopeSpans[0].Spans
	root := sp[0]
	if root.Name != "lostname.check.parity" || len(root.TraceID) != 32 || len(root.SpanID) != 16 || root.ParentSpanID != "" {
		t.Fatalf("root span %+v", root)
	}
	host, _, _ := net.SplitHostPort(addrA)
	sawServer := false
	for _, c := range sp[1:] {
		if c.TraceID != root.TraceID || c.ParentSpanID != root.SpanID || c.Name != "dns.query" {
			t.Fatalf("child span not under the root: %+v", c)
		}
		for _, a := range c.Attributes {
			if a.Key == "server.address" && a.Value["stringValue"] == host {
				sawServer = true
			}
		}
	}
	if !sawServer {
		t.Errorf("no span names server %s", host)
	}
	// No answer data in a span: the A record's address must not appear.
	if strings.Contains(string(b), "192.0.2.80") {
		t.Errorf("answer data in the trace: %s", b)
	}
	// Events of this check point at its trace.
	evs := newTestTracker().Observe([]CheckResult{parity}, nil, "run", time.Now())
	if len(evs) == 0 || evs[0].Ext["traceparent"] != "00-"+root.TraceID+"-"+root.SpanID+"-01" {
		t.Errorf("event traceparent %q, want the root span of trace %s", evs[0].Ext["traceparent"], root.TraceID)
	}
}

func TestNoTracesWhenOff(t *testing.T) {
	s, _ := tracedRound(t, false)
	for _, r := range s.Results() {
		if r.Trace != nil {
			t.Errorf("%s: traces are off, yet the result carries one", r.Check)
		}
	}
}

// A check without a verdict is an error of the run; a fail verdict is a result.
func TestTraceStatusFollowsTheVerdict(t *testing.T) {
	for verdict, wantErr := range map[string]bool{"no_verdict": true, "fail": false, "pass": false} {
		r := CheckResult{Zone: "example.test.", Check: "lint", Verdict: verdict, Trace: NewTrace(time.Now())}
		r.Trace.End = time.Now()
		sp := spans(r)
		if got := sp[0].Status != nil; got != wantErr {
			t.Errorf("%s: error status %v, want %v", verdict, got, wantErr)
		}
	}
}
