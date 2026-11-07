package watch

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"lostname.be/lostname/internal/config"
	"lostname.be/lostname/internal/sim"
	"lostname.be/lostname/internal/zone"
)

const signedSrc = "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
	"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\n" +
	"@ 300 IN DNSKEY 257 3 13 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n"

func exitSetup(t *testing.T, model, lock string, target int) (*config.Config, *zone.Zone, config.WatchZone) {
	t.Helper()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	z, err := zone.Read(strings.NewReader(signedSrc), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	return cfg, z, config.WatchZone{Origin: "example.test", Exit: &config.WatchExit{Model: model, Lock: lock, Target: target}}
}

// The exit time is the simulator's: the same number sim.PreStage reports as the exit at the current TTLs, with the
// zone's own DNSKEY TTL (300 s here, not the config's 3600 s).
func TestExitTimeIsTheSimulators(t *testing.T) {
	for _, model := range []string{"T0", "T1", "T2"} {
		for _, lock := range []string{"none", "domain-shield"} {
			cfg, z, wz := exitSetup(t, model, lock, 1<<30)
			r := exitResult(cfg, z, wz, "pass", time.Now)
			l := cfg.Sim.Locks[lock]
			adv, err := sim.PreStage(model, sim.TTLs{DS: cfg.Sim.TTLs.DS, Neg: cfg.Sim.TTLs.Negative,
				NSParent: cfg.Sim.TTLs.NSParent, DNSKEY: 300, Margin: cfg.Sim.Margin}, 300,
				sim.Lock{Name: lock, Latency: l.Latency, Window: l.Window})
			if err != nil {
				t.Fatal(err)
			}
			// The test zone is signed: T0 (unsigned to unsigned) is never ready on it (red team 3, W3-4).
			if r.ExitTime != adv.ExitBefore || (r.Verdict == "pass") == (model == "T0") {
				t.Errorf("%s/%s: exit time %d s (%s), the simulator says %d s", model, lock, r.ExitTime, r.Verdict,
					adv.ExitBefore)
			}
		}
	}
	cfg, z, wz := exitSetup(t, "T1", "none", 1<<30)
	none := exitResult(cfg, z, wz, "", time.Now).ExitTime
	wz.Exit.Lock = "domain-shield"
	if shield := exitResult(cfg, z, wz, "", time.Now).ExitTime; shield <= none {
		t.Errorf("a registry lock must lengthen the exit: %d s with, %d s without", shield, none)
	}
}

func TestExitReadiness(t *testing.T) {
	cfg, z, wz := exitSetup(t, "T1", "none", 1<<30)
	time1 := exitResult(cfg, z, wz, "", time.Now).ExitTime
	for _, tc := range []struct {
		name, parity string
		target       int
		want         string
	}{
		{"within the target, no providers", "", time1, "pass"},
		{"one second over", "", time1 - 1, "fail"},
		{"within, standby in parity", "pass", time1, "pass"},
		{"within, standby not in parity", "fail", time1, "fail"},
		{"parity blind: readiness unknown", "no_verdict", time1, "no_verdict"},
	} {
		wz.Exit.Target = tc.target
		if r := exitResult(cfg, z, wz, tc.parity, time.Now); r.Verdict != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, r.Verdict, tc.want)
		}
	}
}

// The SLI series: ready and the time are measurements (absent without a verdict); the target is config (always).
func TestExitMetrics(t *testing.T) {
	cfg, z, wz := exitSetup(t, "T1", "none", 1<<30)
	s := NewSnapshot()
	s.Record(exitResult(cfg, z, wz, "pass", time.Now))
	var b bytes.Buffer
	_ = s.WriteOpenMetrics(&b)
	for _, want := range []string{`lostname_exit_ready{zone="example.test.",basis="modelled"} 1`,
		`lostname_exit_time_seconds{zone="example.test.",model="T1",basis="modelled"} `,
		`lostname_exit_target_seconds{zone="example.test."} 1073741824`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %s in\n%s", want, b.String())
		}
	}
	s.Record(exitResult(cfg, z, wz, "no_verdict", time.Now))
	b.Reset()
	_ = s.WriteOpenMetrics(&b)
	if strings.Contains(b.String(), "lostname_exit_ready{") || strings.Contains(b.String(), "lostname_exit_time_seconds{") ||
		!strings.Contains(b.String(), "lostname_exit_target_seconds{") {
		t.Errorf("without a verdict the SLI is absent, never 0, and the target stays:\n%s", b.String())
	}
}
