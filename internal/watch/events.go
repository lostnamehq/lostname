package watch

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Events (docs/observability.md, "Events"): CloudEvents 1.0 in JSON, derived by comparing one round with the one
// before. A check without a verdict says nothing about its findings, so it neither opens nor closes any: a missing
// measurement is not a fixed finding. Events carry no record data beyond the owner name and type, which is why a
// finding's message (it can quote record data) stays out.

// Event types, versioned in the name.
const (
	TypeVerdictChanged = "be.lostname.check.verdict.changed.v0"
	TypeFindingOpened  = "be.lostname.finding.opened.v0"
	TypeFindingClosed  = "be.lostname.finding.closed.v0"
	TypeIntercepted    = "be.lostname.probe.intercepted.v0"
)

// Finding is one lint or parity finding as events see it: no message, no record data. Provider is empty for lint.
type Finding struct {
	Rule     string // lint rule (L-08) or parity kind (rrset-differs)
	Severity string
	Name     string
	Type     string
	Provider string
	Ref      string
}

func (f Finding) key() string { return f.Rule + "|" + f.Name + "|" + f.Type + "|" + f.Provider }

// Interception is the probe address that answered and the protocols it answered over.
type Interception struct {
	Probe     string
	Protocols []string
}

// Event is one CloudEvent; Ext holds the optional extension attributes, written at the top level.
type Event struct {
	ID      string
	Source  string
	Type    string
	Subject string
	Time    time.Time
	Data    map[string]any
	Ext     map[string]string
}

// MarshalJSON writes the structured-mode JSON form (CloudEvents JSON format 1.0).
func (e Event) MarshalJSON() ([]byte, error) {
	m := map[string]any{"specversion": "1.0", "id": e.ID, "source": e.Source, "type": e.Type,
		"time": e.Time.UTC().Format(time.RFC3339Nano), "datacontenttype": "application/json", "data": e.Data}
	if e.Subject != "" {
		m["subject"] = e.Subject
	}
	for k, v := range e.Ext {
		m[k] = v
	}
	return json.Marshal(m)
}

// extensionOf maps the watch.resource keys to CloudEvents extension names (lower-case letters and digits only).
var extensionOf = map[string]string{"site": "site", "tenant": "tenant", "entity_id": "entityid", "risk_id": "riskids"}

// Tracker remembers the previous round and turns the next one into events.
type Tracker struct {
	source      string
	ext         map[string]string
	verdicts    map[[2]string]string
	findings    map[[2]string]map[string]Finding
	intercepted bool
	newID       func() string
}

// NewTracker returns a tracker for one watch instance; resource holds the optional correlation attributes.
func NewTracker(instance string, resource map[string]string) *Tracker {
	ext := map[string]string{}
	for k, v := range resource {
		if name, ok := extensionOf[k]; ok && v != "" {
			ext[name] = v
		}
	}
	return &Tracker{source: "lostname/" + instance, ext: ext, verdicts: map[[2]string]string{},
		findings: map[[2]string]map[string]Finding{}, newID: randomID}
}

// RunID names one round; the events of that round carry it.
func RunID() string { return randomID() }

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Observe compares one round's results (and its interception probe, nil when the path was clean or not probed) with
// the previous round and returns the events, in a stable order. The first round opens every finding it sees and
// reports each verdict with an empty "from".
func (t *Tracker) Observe(results []CheckResult, probe *Interception, runID string, now time.Time) []Event {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Zone != results[j].Zone {
			return results[i].Zone < results[j].Zone
		}
		return results[i].Check < results[j].Check
	})
	var out []Event
	for _, r := range results {
		evs := t.observeCheck(r, runID, now)
		for i := range evs {
			if r.Trace != nil {
				evs[i].Ext["traceparent"] = r.Trace.Traceparent() // joins the event to the check's queries
			}
		}
		out = append(out, evs...)
	}
	// One event when the path becomes intercepted, not one per round while it stays so. The episode ends only when a
	// probe ran and the path was clean (red team 3, W3-2): a round in which nothing probed says nothing about it.
	probed := false
	for _, r := range results {
		probed = probed || r.Probed
	}
	if probe != nil && !t.intercepted {
		out = append(out, t.event(TypeIntercepted, "", now, map[string]any{"probe": probe.Probe,
			"protocols": probe.Protocols, "run_id": runID}, ""))
	}
	if probe != nil {
		t.intercepted = true
	} else if probed {
		t.intercepted = false
	}
	return out
}

// observeCheck returns the events of one check's result and remembers it.
func (t *Tracker) observeCheck(r CheckResult, runID string, now time.Time) []Event {
	var out []Event
	k := [2]string{r.Zone, r.Check}
	if from, seen := t.verdicts[k]; !seen || from != r.Verdict {
		out = append(out, t.event(TypeVerdictChanged, r.Zone, now, map[string]any{"zone": r.Zone,
			"check": r.Check, "from": from, "to": r.Verdict, "run_id": runID}, ""))
	}
	t.verdicts[k] = r.Verdict
	if r.Verdict == "no_verdict" {
		return out
	}
	prev, cur := t.findings[k], map[string]Finding{}
	for _, f := range r.Findings {
		cur[f.key()] = f
	}
	for _, key := range sortedFindingKeys(cur) {
		if _, was := prev[key]; !was {
			f := cur[key]
			d := map[string]any{"zone": r.Zone, "check": r.Check, "rule": f.Rule, "severity": f.Severity,
				"name": f.Name, "type": f.Type, "ref": f.Ref, "run_id": runID}
			if f.Provider != "" {
				d["provider"] = f.Provider
			}
			out = append(out, t.event(TypeFindingOpened, r.Zone, now, d, f.Severity))
		}
	}
	for _, key := range sortedFindingKeys(prev) {
		if _, is := cur[key]; !is {
			f := prev[key]
			d := map[string]any{"zone": r.Zone, "check": r.Check, "rule": f.Rule, "name": f.Name,
				"type": f.Type, "run_id": runID}
			if f.Provider != "" {
				d["provider"] = f.Provider
			}
			out = append(out, t.event(TypeFindingClosed, r.Zone, now, d, ""))
		}
	}
	t.findings[k] = cur
	return out
}

func (t *Tracker) event(typ, subject string, now time.Time, data map[string]any, severity string) Event {
	ext := map[string]string{}
	for k, v := range t.ext {
		ext[k] = v
	}
	if severity != "" {
		ext["severity"] = severity
	}
	return Event{ID: t.newID(), Source: t.source, Type: typ, Subject: subject, Time: now, Data: data, Ext: ext}
}

func sortedFindingKeys(m map[string]Finding) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// SendHTTP posts each event in CloudEvents structured mode (application/cloudevents+json) to endpoint. It stops at
// the first failure and says how many were delivered; the events are not kept for a retry.
func SendHTTP(client *http.Client, endpoint string, events []Event) error {
	client = noRedirects(client)
	for i, e := range events {
		body, err := json.Marshal(e)
		if err != nil {
			return err
		}
		resp, err := client.Post(endpoint, "application/cloudevents+json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("events to %s: %v (%d of %d delivered, the rest dropped)", redact(endpoint), err, i,
				len(events))
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("events to %s: HTTP %d (%d of %d delivered, the rest dropped)", redact(endpoint),
				resp.StatusCode, i, len(events))
		}
	}
	return nil
}

// OTLPLogsJSON renders events as an OTLP ExportLogsServiceRequest: one log record per event, the CloudEvents
// attributes as cloudevents.event_* attributes (OpenTelemetry semantic conventions), the data as the body.
func OTLPLogsJSON(events []Event, version string, resource map[string]string) ([]byte, error) {
	str := func(v string) map[string]any { return map[string]any{"stringValue": v} }
	var records []any
	for _, e := range events {
		data, err := json.Marshal(e.Data)
		if err != nil {
			return nil, err
		}
		attrs := []any{
			map[string]any{"key": "cloudevents.event_id", "value": str(e.ID)},
			map[string]any{"key": "cloudevents.event_source", "value": str(e.Source)},
			map[string]any{"key": "cloudevents.event_spec_version", "value": str("1.0")},
			map[string]any{"key": "cloudevents.event_type", "value": str(e.Type)},
		}
		if e.Subject != "" {
			attrs = append(attrs, map[string]any{"key": "cloudevents.event_subject", "value": str(e.Subject)})
		}
		for _, k := range sortedExt(e.Ext) {
			attrs = append(attrs, map[string]any{"key": "cloudevents." + k, "value": str(e.Ext[k])})
		}
		rec := map[string]any{"timeUnixNano": strconv.FormatInt(e.Time.UnixNano(), 10),
			"eventName": e.Type, "body": str(string(data)), "attributes": attrs}
		// Red team 3, W3-9: backends join logs to traces on the record's traceId and spanId (OTLP data model).
		if f := strings.Split(e.Ext["traceparent"], "-"); len(f) == 4 && len(f[1]) == 32 && len(f[2]) == 16 {
			rec["traceId"], rec["spanId"] = f[1], f[2]
		}
		records = append(records, rec)
	}
	attrs := []otlpAttr{{Key: "service.name", Value: map[string]string{"stringValue": "lostname"}}}
	for _, k := range []string{"site", "tenant", "entity_id", "risk_id"} {
		if v := resource[k]; v != "" {
			attrs = append(attrs, otlpAttr{Key: k, Value: map[string]string{"stringValue": v}})
		}
	}
	return json.Marshal(map[string]any{"resourceLogs": []any{map[string]any{
		"resource": map[string]any{"attributes": attrs},
		"scopeLogs": []any{map[string]any{
			"scope":      map[string]string{"name": "lostname", "version": version},
			"logRecords": records,
		}},
	}}})
}

func sortedExt(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// PushLogs sends events as OTLP logs to endpoint's /v1/logs.
func PushLogs(client *http.Client, endpoint, version string, resource map[string]string, events []Event) error {
	body, err := OTLPLogsJSON(events, version, resource)
	if err != nil {
		return err
	}
	resp, err := noRedirects(client).Post(strings.TrimSuffix(endpoint, "/")+"/v1/logs", "application/json",
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("OTLP logs to %s: %v (%d events dropped)", redact(endpoint), err, len(events))
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("OTLP logs to %s: HTTP %d (%d events dropped)", redact(endpoint), resp.StatusCode, len(events))
	}
	return nil
}

// noRedirects returns a copy of client that never follows a redirect (red team 3, W3-5): a 303 would turn the POST
// into a GET without the data and count as delivered, and a 307 would post the data to whatever host it names. The
// 3xx comes back as the response and counts as a failed delivery.
func noRedirects(client *http.Client) *http.Client {
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// redact hides a password in an endpoint URL before it reaches a message (red team 3, W3-6).
func redact(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil {
		return u.Redacted()
	}
	return "(an endpoint that is not a URL)"
}

// TypeResync is the event a watch sends after its first round: every verdict and open finding it knows, so a
// consumer that missed events (a restart, an outage of its own) can replace its state (decision of 2026-11-06).
const TypeResync = "be.lostname.watch.resync.v0"

// Resync returns the resync event for the tracker's current state, in a stable order.
func (t *Tracker) Resync(runID string, now time.Time) Event {
	verdicts, open := []map[string]any{}, []map[string]any{}
	keys := make([][2]string, 0, len(t.verdicts))
	for k := range t.verdicts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+"\x00"+keys[i][1] < keys[j][0]+"\x00"+keys[j][1] })
	for _, k := range keys {
		verdicts = append(verdicts, map[string]any{"zone": k[0], "check": k[1], "verdict": t.verdicts[k]})
		for _, fk := range sortedFindingKeys(t.findings[k]) {
			f := t.findings[k][fk]
			d := map[string]any{"zone": k[0], "check": k[1], "rule": f.Rule, "severity": f.Severity, "name": f.Name,
				"type": f.Type, "ref": f.Ref}
			if f.Provider != "" {
				d["provider"] = f.Provider
			}
			open = append(open, d)
		}
	}
	return t.event(TypeResync, "", now, map[string]any{"verdicts": verdicts, "open_findings": open,
		"intercepted": t.intercepted, "run_id": runID}, "")
}

// trackerState is the tracker's state on disk: owner names, rule ids and verdicts, never record data.
type trackerState struct {
	Schema      string         `json:"schema"`
	Source      string         `json:"source"`
	Verdicts    [][3]string    `json:"verdicts"` // zone, check, verdict
	Findings    []stateFinding `json:"findings"`
	Intercepted bool           `json:"intercepted"`
}

type stateFinding struct {
	Zone  string `json:"zone"`
	Check string `json:"check"`
	Finding
}

const stateSchema = "lostname.watch-state/v0"

// Save writes the tracker's state to path atomically: a temporary file in the same directory, synced, then renamed
// over the old one, so a crash leaves the old state or the new one, never half of either.
func (t *Tracker) Save(path string) error {
	st := trackerState{Schema: stateSchema, Source: t.source, Verdicts: [][3]string{}, Findings: []stateFinding{},
		Intercepted: t.intercepted}
	for k, v := range t.verdicts {
		st.Verdicts = append(st.Verdicts, [3]string{k[0], k[1], v})
		for _, f := range t.findings[k] {
			st.Findings = append(st.Findings, stateFinding{Zone: k[0], Check: k[1], Finding: f})
		}
	}
	sort.Slice(st.Verdicts, func(i, j int) bool {
		return strings.Join(st.Verdicts[i][:], "\x00") < strings.Join(st.Verdicts[j][:], "\x00")
	})
	sort.Slice(st.Findings, func(i, j int) bool {
		a, b := st.Findings[i], st.Findings[j]
		return a.Zone+"\x00"+a.Check+"\x00"+a.key() < b.Zone+"\x00"+b.Check+"\x00"+b.key()
	})
	body, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".lostname-state-*")
	if err != nil {
		return fmt.Errorf("watch state %s: %v", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(body, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("watch state %s: %v", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("watch state %s: %v", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("watch state %s: %v", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("watch state %s: %v", path, err)
	}
	return nil
}

// Load restores the tracker's state from path. A missing file is a first start. A file of another schema or another
// source (another watch.instance) is refused: its findings are not this watch's.
func (t *Tracker) Load(path string) error {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("watch state %s: %v", path, err)
	}
	var st trackerState
	if err := json.Unmarshal(body, &st); err != nil || st.Schema != stateSchema {
		return fmt.Errorf("watch state %s: not a %s file", path, stateSchema)
	}
	if st.Source != t.source {
		return fmt.Errorf("watch state %s: written by %s, not %s: give each instance its own state file", path,
			st.Source, t.source)
	}
	for _, v := range st.Verdicts {
		t.verdicts[[2]string{v[0], v[1]}] = v[2]
	}
	for _, f := range st.Findings {
		k := [2]string{f.Zone, f.Check}
		if t.findings[k] == nil {
			t.findings[k] = map[string]Finding{}
		}
		t.findings[k][f.Finding.key()] = f.Finding
	}
	t.intercepted = st.Intercepted
	return nil
}

// Prune forgets the checks that are not in results (a zone that left the config): they get no events, and they
// leave the state file.
func (t *Tracker) Prune(results []CheckResult) {
	keep := map[[2]string]bool{}
	for _, r := range results {
		keep[[2]string{r.Zone, r.Check}] = true
	}
	for k := range t.verdicts {
		if !keep[k] {
			delete(t.verdicts, k)
			delete(t.findings, k)
		}
	}
}
