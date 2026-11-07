package watch

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lostname.be/lostname/internal/parity"
)

// With the keyed-hash zone label on, the zone's name reaches no output: not OpenMetrics, not OTLP metrics, logs or
// traces, not the CloudEvents. Owner names are relative to the zone.
func TestZoneNameNeverLeavesWatch(t *testing.T) {
	key := []byte("0123456789abcdef-test-salt")
	now := time.Now()
	tr := NewTrace(now)
	tr.End = now
	tr.Exchanges = []parity.Exchange{{Time: now.UTC().Format(time.RFC3339Nano), Started: now,
		Server: "192.0.2.53:53", Transport: "udp", Name: "www.secret-client.test.", Type: "A", Rcode: "NOERROR"}}
	s := NewSnapshot()
	s.SetZoneKey(key)
	s.Record(CheckResult{Zone: "secret-client.test.", Check: "lint", Verdict: "fail", Finished: now,
		LintFindings: map[string]int{"blocker": 1, "risk": 0, "note": 0},
		Findings:     []Finding{{Rule: "L-08", Severity: "blocker", Name: "www.secret-client.test.", Type: "CNAME"}}})
	s.Record(CheckResult{Zone: "secret-client.test.", Check: "parity", Verdict: "pass", Finished: now, Probed: true,
		Mismatches: map[[2]string]int{{"A", "B"}: 0}, Answering: map[string]int{"A": 1, "B": 1},
		Expected: map[string]int{"A": 1, "B": 1}, Trace: tr,
		Findings: []Finding{{Rule: "ttl-differs", Severity: "risk", Name: "secret-client.test.", Type: "SOA", Provider: "B"}}})

	var om bytes.Buffer
	_ = s.WriteOpenMetrics(&om)
	metrics, _ := s.OTLPJSON(now, "v", nil)
	evs := NewTracker("t", nil).Observe(s.Results(), nil, "run", now)
	events, _ := json.Marshal(evs)
	logs, _ := OTLPLogsJSON(evs, "v", nil)
	traces, _, _ := OTLPTracesJSON(s.Results(), "v", nil)
	id := ZoneID(key, "secret-client.test")
	for name, out := range map[string][]byte{"openmetrics": om.Bytes(), "otlp metrics": metrics, "events": events,
		"otlp logs": logs, "traces": traces} {
		if strings.Contains(string(out), "secret-client") {
			t.Errorf("%s carries the zone name", name)
		}
		if !strings.Contains(string(out), id) {
			t.Errorf("%s does not carry the zone id %s", name, id)
		}
	}
	if !strings.Contains(string(events), `"name":"www"`) || !strings.Contains(string(events), `"name":"@"`) {
		t.Errorf("owner names must be relative to the zone: %s", events)
	}
	if !strings.Contains(string(traces), `"www"`) {
		t.Errorf("query names in spans must be relative to the zone: %s", traces)
	}
}

func TestZoneIDIsKeyedAndStable(t *testing.T) {
	a, b := []byte("key-one-0123456789"), []byte("key-two-0123456789")
	if ZoneID(a, "Example.TEST") != ZoneID(a, "example.test.") {
		t.Error("the id must not depend on case or the trailing dot")
	}
	if ZoneID(a, "example.test") == ZoneID(b, "example.test") || ZoneID(a, "example.test") == ZoneID(a, "other.test") {
		t.Error("the id must depend on the key and on the zone")
	}
	if id := ZoneID(a, "example.test"); len(id) != 33 || id[0] != 'z' {
		t.Errorf("id %q: want z and 32 hex digits", id)
	}
	for name, want := range map[string]string{"example.test.": "@", "www.example.test.": "www",
		"a.b.example.test.": "a.b", "example.org.": "(outside the zone)", "badexample.test.": "(outside the zone)"} {
		if got := relative(name, "example.test."); got != want {
			t.Errorf("relative(%s) = %q, want %q", name, got, want)
		}
	}
}
