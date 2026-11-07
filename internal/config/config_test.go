package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lostname.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreValid(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Sim.Locks["domain-shield"].Window != 86400 {
		t.Fatal("defaults not loaded")
	}
}

func TestOverrideAppliesOnTop(t *testing.T) {
	c, err := Load(write(t, `{"schema":"lostname.config/v0","parity":{"timeout_seconds":7}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Parity.Timeout != 7 || c.Parity.EDNSBuffer != 1232 {
		t.Fatalf("override must change only what it names: %+v", c.Parity)
	}
}

func TestStrictReading(t *testing.T) {
	cases := map[string]string{
		"unknown key":     `{"schema":"lostname.config/v0","parity":{"timeuot_seconds":7}}`,
		"wrong schema":    `{"schema":"lostname.config/v9"}`,
		"zero timeout":    `{"schema":"lostname.config/v0","fetch":{"timeout_seconds":0}}`,
		"bad model":       `{"schema":"lostname.config/v0","parity":{"model":"T9"}}`,
		"bad severity":    `{"schema":"lostname.config/v0","lint":{"severity":{"L-07":"fatal"}}}`,
		"lock no source":  `{"schema":"lostname.config/v0","sim":{"locks":{"x":{"latency_seconds":1}}}}`,
		"trailing object": `{"schema":"lostname.config/v0"} {}`,
		"v4 canary as v6": `{"schema":"lostname.config/v0","probe":{"canary":"[2001:db8::53]:53"}}`,
		"v6 canary as v4": `{"schema":"lostname.config/v0","probe":{"canary_v6":"203.0.113.1:53"}}`,
		"canary hostname": `{"schema":"lostname.config/v0","probe":{"canary":"probe.example:53"}}`,
		"zero record cap": `{"schema":"lostname.config/v0","fetch":{"max_records":0}}`,
		// Red team 2, P3.
		"L-00 disabled":     `{"schema":"lostname.config/v0","lint":{"disabled_rules":["L-00"]}}`,
		"L-00 downgraded":   `{"schema":"lostname.config/v0","lint":{"severity":{"L-00":"note"}}}`,
		"unknown rule":      `{"schema":"lostname.config/v0","lint":{"disabled_rules":["L-8"]}}`,
		"unknown severity":  `{"schema":"lostname.config/v0","lint":{"severity":{"L-99":"risk"}}}`,
		"canary port text":  `{"schema":"lostname.config/v0","probe":{"canary":"203.0.113.1:nope"}}`,
		"canary port 0":     `{"schema":"lostname.config/v0","probe":{"canary_v6":"[2001:db8::53]:0"}}`,
		"canary port 99999": `{"schema":"lostname.config/v0","probe":{"canary":"203.0.113.1:99999"}}`,
		"zone twice":        `{"schema":"lostname.config/v0","watch":{"zones":[{"origin":"a.test","zone_file":"x"},{"origin":"A.TEST.","zone_file":"y"}]}}`,
		"provider label":    `{"schema":"lostname.config/v0","watch":{"zones":[{"origin":"a.test","zone_file":"x","providers":[{"name":"a b","addrs":["192.0.2.1:53"]},{"name":"c","addrs":["192.0.2.2:53"]}]}]}}`,
		"key case":          `{"schema":"lostname.config/v0","LINT":{"Disabled_Rules":["L-07"]}}`,
		"events no url":     `{"schema":"lostname.config/v0","watch":{"events":["http"]}}`,
		"events no otlp":    `{"schema":"lostname.config/v0","watch":{"events":["otlp"]}}`,
		"events unknown":    `{"schema":"lostname.config/v0","watch":{"events":["nats"],"events_endpoint":"http://x"}}`,
		"events twice":      `{"schema":"lostname.config/v0","watch":{"events":["http","http"],"events_endpoint":"http://x"}}`,
		"events url scheme": `{"schema":"lostname.config/v0","watch":{"events":["http"],"events_endpoint":"file:///tmp/x"}}`,
		"instance slash":    `{"schema":"lostname.config/v0","watch":{"instance":"a/b"}}`,
		"traces no otlp":    `{"schema":"lostname.config/v0","watch":{"traces":true}}`,
		"exit model":        `{"schema":"lostname.config/v0","watch":{"zones":[{"origin":"a.test","zone_file":"x","exit":{"model":"T9","lock":"none","target_seconds":1}}]}}`,
		"exit lock":         `{"schema":"lostname.config/v0","watch":{"zones":[{"origin":"a.test","zone_file":"x","exit":{"model":"T1","lock":"nope","target_seconds":1}}]}}`,
		"exit target":       `{"schema":"lostname.config/v0","watch":{"zones":[{"origin":"a.test","zone_file":"x","exit":{"model":"T1","lock":"none","target_seconds":0}}]}}`,
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "lostname.json") {
			t.Errorf("%s: error does not name the file: %v", name, err)
		}
	}
}
