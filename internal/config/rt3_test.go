package config

import (
	"strings"
	"testing"
)

// W3-7: parity refuses duplicate provider names, so a config that repeats one passes Validate and then yields
// no_verdict on every round, forever. Reading is strict: an invalid value is an error at load time.
func TestRT3DuplicateProviderNameRefused(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c.Watch.Zones = []WatchZone{{Origin: "example.test", ZoneFile: "z", Providers: []WatchProvider{
		{Name: "A", Addrs: []string{"192.0.2.1:53"}}, {Name: "A", Addrs: []string{"192.0.2.2:53"}}}}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "A") {
		t.Errorf("duplicate provider name accepted: %v", err)
	}
}

// W3-8: provider addresses become server.address span attributes and parity dial targets; "not-an-addr" passes
// Validate and makes every round no_verdict.
func TestRT3ProviderAddrValidated(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	c.Watch.Zones = []WatchZone{{Origin: "example.test", ZoneFile: "z", Providers: []WatchProvider{
		{Name: "A", Addrs: []string{"192.0.2.1:53"}}, {Name: "B", Addrs: []string{"ns.example.net"}}}}}
	if err := c.Validate(); err == nil {
		t.Errorf("provider address without a port accepted")
	}
}
