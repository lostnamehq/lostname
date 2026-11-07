// Package config holds every deployment setting Lostname uses: timeouts, TTL assumptions, the safety margin, registry
// lock latencies, the interception probe, EDNS size and lint severities. Nothing of this is hardcoded elsewhere.
//
// The defaults are embedded (defaults.json) and documented by docs/schemas/config.schema.json. A user file
// overrides any subset. Reading is strict: an unknown key, a wrong schema version or an invalid value is an error,
// never silently ignored. Standards facts (RFC registries such as signing algorithms or CAA tags) are not config:
// they live in the code next to the rule that cites them.
package config

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Schema is the config schema version this build reads.
const Schema = "lostname.config/v0"

//go:embed defaults.json
var defaults []byte

// TTLs are cache lifetimes (seconds) assumed when the zone's own are not measured.
type TTLs struct {
	DS       int `json:"ds_seconds"`
	Negative int `json:"negative_seconds"`
	NSParent int `json:"ns_parent_seconds"`
	DNSKEY   int `json:"dnskey_seconds"`
}

// Lock is a registry lock profile.
type Lock struct {
	Latency int    `json:"latency_seconds"`
	Window  int    `json:"window_seconds"`
	Source  string `json:"source"` // where the numbers come from
}

// Config is the whole configuration.
type Config struct {
	Schema string `json:"schema"`
	Sim    struct {
		TTLs   TTLs            `json:"ttls"`
		Margin int             `json:"margin_seconds"`
		Locks  map[string]Lock `json:"locks"`
	} `json:"sim"`
	Probe struct {
		Canary   string `json:"canary"`    // IPv4 probe address
		CanaryV6 string `json:"canary_v6"` // IPv6 probe address (M9)
		Timeout  int    `json:"timeout_seconds"`
	} `json:"probe"`
	Parity struct {
		Timeout    int    `json:"timeout_seconds"`
		EDNSBuffer int    `json:"edns_buffer_bytes"`
		NXProbe    string `json:"nx_probe_label"`
		Model      string `json:"model"`
		MinSigLife int    `json:"min_signature_life_seconds"` // a valid RRSIG expiring sooner is a risk
		Deadline   int    `json:"deadline_seconds"`           // the whole run; questions after it are gaps
		MaxQueries int    `json:"max_queries_per_server"`     // per server address; questions after it are gaps
		Pace       int    `json:"pace_milliseconds"`          // the least time between two queries to one server
	} `json:"parity"`
	Fetch struct {
		Timeout    int `json:"timeout_seconds"`  // per network read or write
		Deadline   int `json:"deadline_seconds"` // the whole transfer
		MaxRecords int `json:"max_records"`      // a transfer that grows past this is refused, not truncated
	} `json:"fetch"`
	Lint struct {
		Disabled []string          `json:"disabled_rules"`
		Severity map[string]string `json:"severity"` // rule id -> blocker, risk or note
	} `json:"lint"`
	Watch struct {
		Listen   string            `json:"listen"`           // host:port for /metrics
		Interval int               `json:"interval_seconds"` // between rounds
		Zones    []WatchZone       `json:"zones"`
		Catalogs []WatchCatalog    `json:"catalogs"`        // catalog zones (RFC 9432): their members, with shared providers
		OTLP     string            `json:"otlp_endpoint"`   // OTLP/HTTP base URL, e.g. http://collector:4318; "" for none
		Resource map[string]string `json:"resource"`        // optional correlation attributes: site, tenant, entity_id, risk_id
		Events   []string          `json:"events"`          // event transports: "http" (CloudEvents), "otlp" (logs); none by default
		EventsTo string            `json:"events_endpoint"` // URL for CloudEvents over HTTP
		Instance string            `json:"instance"`        // the events' source is lostname/<instance>; "" for the host name
		Traces   bool              `json:"traces"`          // send each check as a trace to otlp_endpoint
		State    string            `json:"state_file"`      // the event tracker's state across restarts; "" for none
		ZoneID   struct {
			SaltFile string `json:"salt_file"` // the key of the keyed-hash zone label; "" for raw zone names
		} `json:"zone_id"`
	} `json:"watch"`
}

// WatchZone is one zone `watch` checks every round: lint on its zone file, and parity when it has two or more
// providers.
type WatchZone struct {
	Origin    string          `json:"origin"`
	ZoneFile  string          `json:"zone_file"`
	Providers []WatchProvider `json:"providers"`
	Parent    []string        `json:"parent"` // the parent's servers, for a signed zone's DS chain
	Exit      *WatchExit      `json:"exit"`   // exit readiness (OB-2); nil for none
}

// WatchExit is a zone's exit-readiness objective: the exit under Model and the registry lock Lock must take at most
// Target seconds, caches drained.
type WatchExit struct {
	Model  string `json:"model"`          // T0, T1 or T2
	Lock   string `json:"lock"`           // a profile in sim.locks
	Target int    `json:"target_seconds"` // the objective
}

// WatchCatalog is a catalog zone (RFC 9432) whose members watch checks, each like a WatchZone with the catalog's
// providers, parent and exit objective. The catalog is read again every round, so members come and go with it.
type WatchCatalog struct {
	CatalogFile string          `json:"catalog_file"` // the catalog zone as a zone file
	Origin      string          `json:"origin"`       // the catalog zone's name
	ZoneDir     string          `json:"zone_dir"`     // the member zone files: <zone_dir>/<member>.zone, no trailing dot
	Providers   []WatchProvider `json:"providers"`
	Parent      []string        `json:"parent"`
	Exit        *WatchExit      `json:"exit"`
}

// WatchProvider names a provider and its authoritative servers (host:port).
type WatchProvider struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

// Load returns the defaults with the file at path applied on top ("" for defaults only).
func Load(path string) (*Config, error) {
	var c Config
	if err := decode(defaults, &c); err != nil {
		return nil, fmt.Errorf("embedded defaults: %w", err)
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := decode(b, &c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if err := c.Validate(); err != nil {
		if path == "" {
			path = "embedded defaults"
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func decode(b []byte, c *Config) error {
	// Red team 2, P3c: encoding/json matches keys case-insensitively, so "LINT" would quietly override "lint".
	var raw any
	if err := json.Unmarshal(b, &raw); err == nil {
		if err := exactKeys(raw, reflect.TypeOf(Config{}), ""); err != nil {
			return err
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(c); err != nil {
		return err
	}
	if d.More() {
		return fmt.Errorf("trailing data after the configuration object")
	}
	return nil
}

// exactKeys refuses a JSON key that matches a field only when case is ignored.
func exactKeys(v any, t reflect.Type, at string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := v.(map[string]any)
		if !ok {
			return nil // the decoder reports the type mismatch
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			fields[name] = t.Field(i).Type
		}
		for k, sub := range obj {
			ft, ok := fields[k]
			if !ok {
				return fmt.Errorf("%s%s: unknown key (keys are case-sensitive)", at, k)
			}
			if err := exactKeys(sub, ft, at+k+"."); err != nil {
				return err
			}
		}
	case reflect.Map:
		if obj, ok := v.(map[string]any); ok {
			for k, sub := range obj {
				if err := exactKeys(sub, t.Elem(), at+k+"."); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		if arr, ok := v.([]any); ok {
			for i, sub := range arr {
				if err := exactKeys(sub, t.Elem(), fmt.Sprintf("%s%d.", at, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Validate refuses values that would make a check meaningless.
func (c *Config) Validate() error {
	if c.Schema != Schema {
		return fmt.Errorf("schema %q, this build reads %q", c.Schema, Schema)
	}
	t := c.Sim.TTLs
	for name, v := range map[string]int{"sim.ttls.ds_seconds": t.DS, "sim.ttls.negative_seconds": t.Negative,
		"sim.ttls.ns_parent_seconds": t.NSParent, "sim.ttls.dnskey_seconds": t.DNSKEY,
		"probe.timeout_seconds": c.Probe.Timeout, "parity.timeout_seconds": c.Parity.Timeout,
		"parity.min_signature_life_seconds": c.Parity.MinSigLife,
		"fetch.timeout_seconds":             c.Fetch.Timeout, "fetch.deadline_seconds": c.Fetch.Deadline,
		"fetch.max_records": c.Fetch.MaxRecords, "watch.interval_seconds": c.Watch.Interval,
		"parity.deadline_seconds": c.Parity.Deadline, "parity.max_queries_per_server": c.Parity.MaxQueries} {
		if v <= 0 {
			return fmt.Errorf("%s must be positive, got %d", name, v)
		}
	}
	if c.Parity.Pace < 0 || c.Parity.Pace > 60000 {
		return fmt.Errorf("parity.pace_milliseconds %d: want 0 to 60000", c.Parity.Pace)
	}
	if c.Sim.Margin < 0 {
		return fmt.Errorf("sim.margin_seconds must not be negative")
	}
	for name, l := range c.Sim.Locks {
		if l.Latency < 0 || l.Window < 0 || l.Source == "" {
			return fmt.Errorf("sim.locks.%s: latency and window must not be negative, and source must say where they come from", name)
		}
	}
	for _, p := range []struct {
		key, addr string
		v6        bool
	}{{"probe.canary", c.Probe.Canary, false}, {"probe.canary_v6", c.Probe.CanaryV6, true}} {
		host, port, err := net.SplitHostPort(p.addr)
		ip := net.ParseIP(host)
		n, perr := strconv.Atoi(port) // red team 2, P3b: a port the probe cannot dial reads as "not intercepted"
		if err != nil || ip == nil || (ip.To4() == nil) != p.v6 || perr != nil || n < 1 || n > 65535 {
			family := "an IPv4 address"
			if p.v6 {
				family = "an IPv6 address in brackets"
			}
			return fmt.Errorf("%s %q: want %s and a port, in space where no DNS server can exist", p.key, p.addr, family)
		}
	}
	if c.Parity.EDNSBuffer < 512 || c.Parity.EDNSBuffer > 4096 {
		return fmt.Errorf("parity.edns_buffer_bytes %d: want 512 to 4096", c.Parity.EDNSBuffer)
	}
	if c.Parity.NXProbe == "" {
		return fmt.Errorf("parity.nx_probe_label must not be empty")
	}
	switch c.Parity.Model {
	case "T0", "T1", "T2":
	default:
		return fmt.Errorf("parity.model %q: want T0, T1 or T2", c.Parity.Model)
	}
	if _, _, err := net.SplitHostPort(c.Watch.Listen); err != nil {
		return fmt.Errorf("watch.listen %q: want host:port: %v", c.Watch.Listen, err)
	}
	if c.Watch.OTLP != "" {
		if u, err := url.Parse(c.Watch.OTLP); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("watch.otlp_endpoint %q: want an http or https URL such as http://collector:4318", c.Watch.OTLP)
		}
	}
	for k := range c.Watch.Resource {
		switch k {
		case "site", "tenant", "entity_id", "risk_id":
		default:
			return fmt.Errorf("watch.resource.%s: only site, tenant, entity_id and risk_id (docs/observability.md)", k)
		}
	}
	seen := map[string]bool{}
	for _, t := range c.Watch.Events {
		switch {
		case seen[t]:
			return fmt.Errorf("watch.events lists %q twice", t)
		case t == "http" && c.Watch.EventsTo == "":
			return fmt.Errorf("watch.events has http: set watch.events_endpoint to the URL that receives the CloudEvents")
		case t == "otlp" && c.Watch.OTLP == "":
			return fmt.Errorf("watch.events has otlp: set watch.otlp_endpoint, where the events go as OTLP logs")
		case t != "http" && t != "otlp":
			return fmt.Errorf("watch.events: %q is not a transport; want http or otlp", t)
		}
		seen[t] = true
	}
	if c.Watch.State != "" && len(c.Watch.Events) == 0 {
		return fmt.Errorf("watch.state_file keeps the events consistent across restarts: set watch.events too, or leave it empty")
	}
	if c.Watch.Traces && c.Watch.OTLP == "" {
		return fmt.Errorf("watch.traces is on: set watch.otlp_endpoint, where the traces go")
	}
	if c.Watch.EventsTo != "" {
		if u, err := url.Parse(c.Watch.EventsTo); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("watch.events_endpoint %q: want an http or https URL", c.Watch.EventsTo)
		}
	}
	if c.Watch.Instance != "" && !instanceName.MatchString(c.Watch.Instance) {
		return fmt.Errorf("watch.instance %q: want 1 to 64 letters, digits, dots, hyphens or underscores", c.Watch.Instance)
	}
	type entry struct {
		where string
		z     WatchZone
	}
	var entries []entry
	for i, z := range c.Watch.Zones {
		entries = append(entries, entry{fmt.Sprintf("watch.zones[%d]", i), z})
	}
	for i, k := range c.Watch.Catalogs { // the same rules for what a catalog's members share
		if k.ZoneDir == "" {
			return fmt.Errorf("watch.catalogs[%d]: zone_dir is required: the member zone files are <zone_dir>/<member>.zone", i)
		}
		entries = append(entries, entry{fmt.Sprintf("watch.catalogs[%d]", i), WatchZone{Origin: k.Origin,
			ZoneFile: k.CatalogFile, Providers: k.Providers, Parent: k.Parent, Exit: k.Exit}})
	}
	origins := map[string]string{}
	for _, en := range entries {
		z := en.z
		if z.Origin == "" || z.ZoneFile == "" {
			return fmt.Errorf("%s: origin and its file are required", en.where)
		}
		if e := z.Exit; e != nil {
			switch e.Model {
			case "T0", "T1", "T2":
			default:
				return fmt.Errorf("%s.exit.model %q: want T0, T1 or T2", en.where, e.Model)
			}
			if _, ok := c.Sim.Locks[e.Lock]; !ok {
				return fmt.Errorf("%s.exit.lock %q: name a profile in sim.locks (none for no lock)", en.where, e.Lock)
			}
			if e.Target <= 0 {
				return fmt.Errorf("%s.exit.target_seconds must be positive", en.where)
			}
		}
		key := strings.TrimSuffix(strings.ToLower(z.Origin), ".")
		if j, dup := origins[key]; dup { // red team 2, W3: the later entry would hide the earlier one's verdict
			return fmt.Errorf("%s (%s) repeats %s: list each zone once", en.where, z.Origin, j)
		}
		origins[key] = en.where
		if len(z.Providers) == 1 {
			return fmt.Errorf("%s (%s): parity needs two or more providers; give none for lint only", en.where, z.Origin)
		}
		names := map[string]bool{}
		for _, p := range z.Providers {
			if names[p.Name] { // red team 3, W3-7: parity refuses it, so the zone would never get a verdict
				return fmt.Errorf("%s (%s): provider %q is listed twice", en.where, z.Origin, p.Name)
			}
			names[p.Name] = true
			for _, a := range p.Addrs { // red team 3, W3-8: an address parity cannot dial is no verdict forever
				host, port, err := net.SplitHostPort(a)
				n, perr := strconv.Atoi(port)
				if err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
					return fmt.Errorf("%s (%s): provider %s address %q: want host:port, such as "+
						"192.0.2.53:53 or [2001:db8::53]:53", en.where, z.Origin, p.Name, a)
				}
			}
			if p.Name == "" || len(p.Addrs) == 0 {
				return fmt.Errorf("%s (%s): every provider needs a name and addresses", en.where, z.Origin)
			}
			if !providerName.MatchString(p.Name) { // red team 2, W5: provider names become metric labels
				return fmt.Errorf("%s (%s): provider name %q: use 1 to 63 of A-Z a-z 0-9 . _ -", en.where,
					z.Origin, p.Name)
			}
		}
	}
	// Red team 2, P3a: L-00 decides whether the input is a zone at all, so it can be neither disabled nor
	// downgraded; and a rule id that does not exist is a mistake, never silently nothing.
	for _, rule := range c.Lint.Disabled {
		if !KnownRules[rule] {
			return fmt.Errorf("lint.disabled_rules: %q is not a lint rule", rule)
		}
		if rule == "L-00" {
			return fmt.Errorf("lint.disabled_rules: L-00 (is this a zone at all) cannot be disabled")
		}
	}
	for rule, sev := range c.Lint.Severity {
		switch sev {
		case "blocker", "risk", "note":
		default:
			return fmt.Errorf("lint.severity.%s %q: want blocker, risk or note", rule, sev)
		}
		if !KnownRules[rule] {
			return fmt.Errorf("lint.severity: %q is not a lint rule", rule)
		}
		if rule == "L-00" && sev != "blocker" {
			return fmt.Errorf("lint.severity.L-00: L-00 (is this a zone at all) stays a blocker")
		}
	}
	return nil
}

// Seconds converts a configured number of seconds to a duration.
func Seconds(n int) time.Duration { return time.Duration(n) * time.Second }

// JSON returns the effective configuration, for `lostname config` and for committing it as code.
func (c *Config) JSON() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }

// KnownRules are the lint rule ids the config may name. internal/lint's test keeps this list equal to the rules lint
// emits (config cannot import lint).
var KnownRules = map[string]bool{"L-00": true, "L-01": true, "L-02": true, "L-03": true, "L-04": true, "L-07": true, "L-08": true,
	"L-09": true, "L-10": true, "L-11": true, "L-12": true, "L-13": true, "L-14": true, "L-15": true, "L-16": true, "L-18": true, "L-20": true,
	"L-21": true, "L-22": true}

var providerName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)

// instanceName is a watch.instance: it becomes part of the events' source.
var instanceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
