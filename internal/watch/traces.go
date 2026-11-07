package watch

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lostname.be/lostname/internal/parity"
)

// Traces (docs/model.md OB-1, docs/observability.md "Traces"): each check run is one OpenTelemetry trace, a root
// span for the check and a child span per DNS query, sent as OTLP/HTTP JSON to /v1/traces. Spans carry the question,
// the server, the transport and the response code, never answer data.

// Trace is one check run's trace.
type Trace struct {
	TraceID, SpanID string // hex, 32 and 16 characters
	Start, End      time.Time
	Exchanges       []parity.Exchange // the queries, in order; empty for lint
}

// NewTrace starts a trace at start.
func NewTrace(start time.Time) *Trace {
	return &Trace{TraceID: hexID(16), SpanID: hexID(8), Start: start}
}

func hexID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Traceparent is the W3C trace context of the check's root span, for the events of that check.
func (t *Trace) Traceparent() string { return "00-" + t.TraceID + "-" + t.SpanID + "-01" }

type otlpAnyAttr struct {
	Key   string         `json:"key"`
	Value map[string]any `json:"value"`
}

func sAttr(k, v string) otlpAnyAttr { return otlpAnyAttr{k, map[string]any{"stringValue": v}} }
func iAttr(k string, v int64) otlpAnyAttr {
	return otlpAnyAttr{k, map[string]any{"intValue": strconv.FormatInt(v, 10)}}
}
func bAttr(k string, v bool) otlpAnyAttr { return otlpAnyAttr{k, map[string]any{"boolValue": v}} }

type otlpSpan struct {
	TraceID      string         `json:"traceId"`
	SpanID       string         `json:"spanId"`
	ParentSpanID string         `json:"parentSpanId,omitempty"`
	Name         string         `json:"name"`
	Kind         int            `json:"kind"` // 1 internal, 3 client
	Start        string         `json:"startTimeUnixNano"`
	End          string         `json:"endTimeUnixNano"`
	Attributes   []otlpAnyAttr  `json:"attributes"`
	Status       map[string]any `json:"status,omitempty"`
}

func nanos(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }

// spans renders one check result's trace: the root span, then one client span per query.
func spans(r CheckResult) []otlpSpan {
	t := r.Trace
	root := otlpSpan{TraceID: t.TraceID, SpanID: t.SpanID, Name: "lostname.check." + r.Check, Kind: 1,
		Start: nanos(t.Start), End: nanos(t.End), Attributes: []otlpAnyAttr{sAttr("lostname.zone", r.Zone),
			sAttr("lostname.check", r.Check), sAttr("lostname.check.verdict", r.Verdict),
			iAttr("lostname.dns.queries", int64(len(t.Exchanges)))}}
	if r.Verdict == "no_verdict" {
		// The check could not measure: an error of the run. A fail verdict is a result, not an error.
		root.Status = map[string]any{"code": 2, "message": "no verdict"}
	}
	out := []otlpSpan{root}
	for _, e := range t.Exchanges {
		end, err := time.Parse(time.RFC3339Nano, e.Time)
		if err != nil || e.Started.IsZero() {
			continue
		}
		sp := otlpSpan{TraceID: t.TraceID, SpanID: hexID(8), ParentSpanID: t.SpanID, Name: "dns.query", Kind: 3,
			Start: nanos(e.Started), End: nanos(end), Attributes: []otlpAnyAttr{
				sAttr("dns.question.name", e.Name), sAttr("dns.question.type", e.Type),
				sAttr("network.transport", e.Transport)}}
		if host, port, err := net.SplitHostPort(e.Server); err == nil {
			sp.Attributes = append(sp.Attributes, sAttr("server.address", host))
			if p, err := strconv.Atoi(port); err == nil {
				sp.Attributes = append(sp.Attributes, iAttr("server.port", int64(p)))
			}
		}
		if e.Error != "" {
			sp.Attributes = append(sp.Attributes, sAttr("error.type", errorType(e.Error)))
			sp.Status = map[string]any{"code": 2, "message": "no answer"}
		} else {
			sp.Attributes = append(sp.Attributes, sAttr("dns.response_code", strings.ToLower(e.Rcode)),
				bAttr("lostname.dns.aa", e.AA), bAttr("lostname.dns.tc", e.TC))
		}
		out = append(out, sp)
	}
	return out
}

// errorType is a bounded error class: a timeout, a refused connection, or other.
func errorType(msg string) string {
	switch m := strings.ToLower(msg); {
	case strings.Contains(m, "timeout"):
		return "timeout"
	case strings.Contains(m, "refused"):
		return "connection_refused"
	default:
		return "other"
	}
}

// OTLPTracesJSON renders the traces of the given results as an OTLP ExportTraceServiceRequest; results without a
// trace are skipped.
func OTLPTracesJSON(results []CheckResult, version string, resource map[string]string) ([]byte, int, error) {
	var all []otlpSpan
	for _, r := range results {
		if r.Trace != nil {
			all = append(all, spans(r)...)
		}
	}
	attrs := []otlpAttr{{Key: "service.name", Value: map[string]string{"stringValue": "lostname"}}}
	for _, k := range []string{"site", "tenant", "entity_id", "risk_id"} {
		if v := resource[k]; v != "" {
			attrs = append(attrs, otlpAttr{Key: k, Value: map[string]string{"stringValue": v}})
		}
	}
	b, err := json.Marshal(map[string]any{"resourceSpans": []any{map[string]any{
		"resource": map[string]any{"attributes": attrs},
		"scopeSpans": []any{map[string]any{
			"scope": map[string]string{"name": "lostname", "version": version},
			"spans": all,
		}},
	}}})
	return b, len(all), err
}

// PushTraces sends the traces of the given results to endpoint's /v1/traces; nothing is sent when none has one.
func PushTraces(client *http.Client, endpoint, version string, resource map[string]string, results []CheckResult) error {
	body, n, err := OTLPTracesJSON(results, version, resource)
	if err != nil || n == 0 {
		return err
	}
	resp, err := noRedirects(client).Post(strings.TrimSuffix(endpoint, "/")+"/v1/traces", "application/json",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("OTLP traces to %s: %v (%d spans dropped)", redact(endpoint), err, n)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("OTLP traces to %s: HTTP %d (%d spans dropped)", redact(endpoint), resp.StatusCode, n)
	}
	return nil
}
