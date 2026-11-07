package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// OTLP push, OTLP/HTTP with JSON encoding (the protocol's stable JSON mapping), metrics only so far. Names use dots,
// and the unit is a field instead of a suffix: an OpenTelemetry Collector translating to Prometheus gives back the
// OpenMetrics names exactly (lostname.check.duration with unit "s" becomes lostname_check_duration_seconds).
// The stateset is a gauge with one data point per state, as OpenMetrics has it.

type otlpAttr struct {
	Key   string            `json:"key"`
	Value map[string]string `json:"value"`
}

type otlpPoint struct {
	Attributes   []otlpAttr `json:"attributes,omitempty"`
	TimeUnixNano string     `json:"timeUnixNano"`
	AsDouble     float64    `json:"asDouble"`
}

type otlpMetric struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Unit        string `json:"unit,omitempty"`
	Gauge       struct {
		DataPoints []otlpPoint `json:"dataPoints"`
	} `json:"gauge"`
}

// otlpName turns an OpenMetrics family name into the OTLP name and unit.
func otlpName(f family) (string, string) {
	name, unit := f.name, ""
	if f.unit == "seconds" {
		name, unit = strings.TrimSuffix(name, "_seconds"), "s"
	}
	return strings.ReplaceAll(name, "_", "."), unit
}

// OTLPJSON renders the snapshot as an OTLP ExportMetricsServiceRequest in JSON. resource holds resource attributes
// (service.name is always lostname; the optional correlation attributes site, tenant, entity_id, risk_id go here).
// A family without samples is left out entirely: absent, never zero.
func (s *Snapshot) OTLPJSON(now time.Time, version string, resource map[string]string) ([]byte, error) {
	ts := strconv.FormatInt(now.UnixNano(), 10)
	var metrics []otlpMetric
	for _, f := range s.families() {
		if len(f.samples) == 0 {
			continue
		}
		m := otlpMetric{Description: f.help}
		m.Name, m.Unit = otlpName(f)
		for _, smp := range f.samples {
			p := otlpPoint{TimeUnixNano: ts, AsDouble: smp.value}
			for _, l := range smp.labels {
				key := l[0]
				if strings.HasPrefix(key, "lostname_") {
					key = strings.ReplaceAll(key, "_", ".") // stateset labels: lostname.check.verdict, lostname.dnssec.status
				}
				p.Attributes = append(p.Attributes, otlpAttr{Key: key, Value: map[string]string{"stringValue": l[1]}})
			}
			m.Gauge.DataPoints = append(m.Gauge.DataPoints, p)
		}
		metrics = append(metrics, m)
	}
	attrs := []otlpAttr{{Key: "service.name", Value: map[string]string{"stringValue": "lostname"}}}
	for _, k := range []string{"site", "tenant", "entity_id", "risk_id"} {
		if v := resource[k]; v != "" {
			attrs = append(attrs, otlpAttr{Key: k, Value: map[string]string{"stringValue": v}})
		}
	}
	req := map[string]any{"resourceMetrics": []any{map[string]any{
		"resource": map[string]any{"attributes": attrs},
		"scopeMetrics": []any{map[string]any{
			"scope":   map[string]string{"name": "lostname", "version": version},
			"metrics": metrics,
		}},
	}}}
	return json.Marshal(req)
}

// Push sends the snapshot to an OTLP/HTTP endpoint (for example http://collector:4318); it posts to /v1/metrics.
func (s *Snapshot) Push(client *http.Client, endpoint, version string, resource map[string]string) error {
	body, err := s.OTLPJSON(time.Now(), version, resource)
	if err != nil {
		return err
	}
	resp, err := noRedirects(client).Post(strings.TrimSuffix(endpoint, "/")+"/v1/metrics", "application/json",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("OTLP push to %s: %v", redact(endpoint), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("OTLP push to %s: HTTP %d", redact(endpoint), resp.StatusCode)
	}
	return nil
}
