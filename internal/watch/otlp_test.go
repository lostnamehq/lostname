package watch

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOTLPCarriesTheSameData(t *testing.T) {
	s := NewSnapshot()
	t0 := time.Unix(1_800_000_000, 0)
	s.Record(CheckResult{Zone: "example.test.", Check: "lint", Verdict: "pass", Duration: time.Second, Finished: t0,
		LintFindings: map[string]int{"note": 1}})
	s.Record(CheckResult{Zone: "example.test.", Check: "parity", Verdict: "no_verdict", Duration: time.Second,
		Finished: t0, Mismatches: map[[2]string]int{{"A", "B"}: 0}, Expected: map[string]int{"A": 1, "B": 1}})
	s.SetIntercepted(false)

	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/metrics" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "wrong path or type", http.StatusBadRequest)
			return
		}
		got, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	if err := s.Push(srv.Client(), srv.URL, "test", map[string]string{"site": "lab"}); err != nil {
		t.Fatal(err)
	}
	var req struct {
		ResourceMetrics []struct {
			Resource struct {
				Attributes []otlpAttr `json:"attributes"`
			} `json:"resource"`
			ScopeMetrics []struct {
				Metrics []otlpMetric `json:"metrics"`
			} `json:"scopeMetrics"`
		} `json:"resourceMetrics"`
	}
	if err := json.Unmarshal(got, &req); err != nil {
		t.Fatal(err)
	}
	points, names := 0, map[string]string{}
	for _, m := range req.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		names[m.Name] = m.Unit
		points += len(m.Gauge.DataPoints)
	}
	var om strings.Builder
	_ = s.WriteOpenMetrics(&om)
	samples := 0
	for _, line := range strings.Split(om.String(), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			samples++
		}
	}
	if points != samples {
		t.Errorf("OTLP has %d data points, OpenMetrics %d samples: the two ways out must carry the same data", points, samples)
	}
	if u, ok := names["lostname.check.duration"]; !ok || u != "s" {
		t.Errorf("want lostname.check.duration with unit s, got %v", names)
	}
	if _, ok := names["lostname.parity.mismatches"]; ok {
		t.Error("a no_verdict parity run must send no mismatch data point")
	}
	if _, ok := names["lostname.lint.findings"]; !ok {
		t.Error("the lint run had a verdict: its findings must be sent")
	}
	attrs := req.ResourceMetrics[0].Resource.Attributes
	if len(attrs) != 2 || attrs[0].Key != "service.name" || attrs[1].Key != "site" {
		t.Errorf("resource attributes: %+v", attrs)
	}
}
