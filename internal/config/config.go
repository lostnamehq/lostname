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
	"os"
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
		Canary  string `json:"canary"`
		Timeout int    `json:"timeout_seconds"`
	} `json:"probe"`
	Parity struct {
		Timeout    int    `json:"timeout_seconds"`
		EDNSBuffer int    `json:"edns_buffer_bytes"`
		NXProbe    string `json:"nx_probe_label"`
		Model      string `json:"model"`
	} `json:"parity"`
	Fetch struct {
		Timeout int `json:"timeout_seconds"`
	} `json:"fetch"`
	Lint struct {
		Disabled []string          `json:"disabled_rules"`
		Severity map[string]string `json:"severity"` // rule id -> blocker, risk or note
	} `json:"lint"`
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

// Validate refuses values that would make a check meaningless.
func (c *Config) Validate() error {
	if c.Schema != Schema {
		return fmt.Errorf("schema %q, this build reads %q", c.Schema, Schema)
	}
	t := c.Sim.TTLs
	for name, v := range map[string]int{"sim.ttls.ds_seconds": t.DS, "sim.ttls.negative_seconds": t.Negative,
		"sim.ttls.ns_parent_seconds": t.NSParent, "sim.ttls.dnskey_seconds": t.DNSKEY,
		"probe.timeout_seconds": c.Probe.Timeout, "parity.timeout_seconds": c.Parity.Timeout,
		"fetch.timeout_seconds": c.Fetch.Timeout} {
		if v <= 0 {
			return fmt.Errorf("%s must be positive, got %d", name, v)
		}
	}
	if c.Sim.Margin < 0 {
		return fmt.Errorf("sim.margin_seconds must not be negative")
	}
	for name, l := range c.Sim.Locks {
		if l.Latency < 0 || l.Window < 0 || l.Source == "" {
			return fmt.Errorf("sim.locks.%s: latency and window must not be negative, and source must say where they come from", name)
		}
	}
	if _, _, err := net.SplitHostPort(c.Probe.Canary); err != nil {
		return fmt.Errorf("probe.canary %q: want host:port: %v", c.Probe.Canary, err)
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
	for rule, sev := range c.Lint.Severity {
		switch sev {
		case "blocker", "risk", "note":
		default:
			return fmt.Errorf("lint.severity.%s %q: want blocker, risk or note", rule, sev)
		}
	}
	return nil
}

// Seconds converts a configured number of seconds to a duration.
func Seconds(n int) time.Duration { return time.Duration(n) * time.Second }

// JSON returns the effective configuration, for `lostname config` and for committing it as code.
func (c *Config) JSON() ([]byte, error) { return json.MarshalIndent(c, "", "  ") }
