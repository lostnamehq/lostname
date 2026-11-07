package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/zone"
)

type sarifLog struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			ExecutionSuccessful bool `json:"executionSuccessful"`
			Notifications       []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			Level     string `json:"level"`
			Locations []struct {
				Physical struct {
					Artifact struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func decodeSARIF(t *testing.T, b []byte) sarifLog {
	t.Helper()
	var l sarifLog
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	if l.Version != "2.1.0" || !strings.Contains(l.Schema, "sarif-2.1.0") || len(l.Runs) != 1 ||
		l.Runs[0].Tool.Driver.Name != "lostname" || len(l.Runs[0].Invocations) != 1 {
		t.Fatalf("not a single-run SARIF 2.1.0 log from lostname: %s", b)
	}
	return l
}

// The SARIF results are the JSON findings, one for one, with the levels of the severity mapping; every rule a result
// names is declared; every result points at the zone file.
func TestLintSARIFMatchesTheFindings(t *testing.T) {
	zp := filepath.Join("..", "..", "internal", "lint", "testdata", "broken.example.test.zone")
	var rep LintReport
	if err := json.Unmarshal(runCLI(t, "lint", "--zone", zp, "--origin", "example.test", "--json"), &rep); err != nil {
		t.Fatal(err)
	}
	l := decodeSARIF(t, runCLI(t, "lint", "--zone", zp, "--origin", "example.test", "--sarif"))
	r := l.Runs[0]
	if len(r.Results) != len(rep.Findings) || len(r.Results) == 0 {
		t.Fatalf("%d SARIF results for %d findings", len(r.Results), len(rep.Findings))
	}
	rules := map[string]bool{}
	for _, x := range r.Tool.Driver.Rules {
		rules[x.ID] = true
	}
	want := map[string]string{"blocker": "error", "risk": "warning", "note": "note"}
	for i, res := range r.Results {
		f := rep.Findings[i]
		if res.RuleID != f.Rule || res.Level != want[string(f.Severity)] || !rules[res.RuleID] {
			t.Errorf("result %d: %s %s (rule declared %v), want %s %s", i, res.RuleID, res.Level, rules[res.RuleID],
				f.Rule, want[string(f.Severity)])
		}
		if len(res.Locations) != 1 || res.Locations[0].Physical.Artifact.URI != filepath.ToSlash(zp) ||
			res.Locations[0].Physical.Region.StartLine < 1 {
			t.Errorf("result %d: location %+v", i, res.Locations)
		}
	}
	if !r.Invocations[0].ExecutionSuccessful {
		t.Error("lint always reaches a verdict")
	}
}

// A parity run without a verdict says so in SARIF: the invocation is not successful and the gaps are its notices.
func TestParitySARIFReportsNoVerdict(t *testing.T) {
	t.Parallel() // independent servers and temp dirs; seconds of probe and query timeouts each
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.53\n"
	z, err := zone.Read(strings.NewReader(src), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	a := authtest.Start(t, z, authtest.None)
	dir := t.TempDir()
	zp, cfg := filepath.Join(dir, "z.zone"), filepath.Join(dir, "c.json")
	conf := `{"schema":"lostname.config/v0","probe":{"canary":"127.0.0.1:1","canary_v6":"[::1]:1","timeout_seconds":1},` +
		`"parity":{"timeout_seconds":1}}`
	if os.WriteFile(zp, []byte(src), 0o600) != nil || os.WriteFile(cfg, []byte(conf), 0o600) != nil {
		t.Fatal("write fixtures")
	}
	l := decodeSARIF(t, runCLI(t, "parity", "--config", cfg, "--zone", zp, "--origin", "example.test",
		"--provider", "A="+a.Addr, "--provider", "B=127.0.0.1:1", "--sarif"))
	inv := l.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful || len(inv.Notifications) == 0 ||
		!strings.HasPrefix(inv.Notifications[0].Message.Text, "no verdict:") {
		t.Fatalf("want an unsuccessful invocation with the gaps as notices, got %+v", inv)
	}
}

func TestJSONAndSARIFTogetherIsAUsageError(t *testing.T) {
	var out, errb strings.Builder
	zp := filepath.Join("..", "..", "internal", "lint", "testdata", "clean.example.test.zone")
	if code := run([]string{"lint", "--zone", zp, "--origin", "example.test", "--json", "--sarif"}, &out, &errb); code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
}
