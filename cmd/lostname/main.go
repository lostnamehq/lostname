// Command lostname: prove you can leave your DNS provider without losing your name.
//
// Exit codes (model section 7, decision 0008): 0 pass, 1 findings, 2 no verdict, 3 usage or input error.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"lostname.be/lostname/internal/config"
	"lostname.be/lostname/internal/fetch"
	"lostname.be/lostname/internal/lint"
	"lostname.be/lostname/internal/parity"
	"lostname.be/lostname/internal/zone"
)

const (
	exitPass      = 0
	exitFindings  = 1
	exitNoVerdict = 2
	exitUsage     = 3
)

// LintReport is the JSON output of `lostname lint`. It contains no timestamps, so equal inputs give byte-equal
// output that can be diffed in tests.
type LintReport struct {
	Schema   string         `json:"schema"`
	Origin   string         `json:"origin"`
	Source   string         `json:"source"`
	Records  int            `json:"records"`
	Verdict  string         `json:"verdict"` // "pass" or "fail"
	Counts   map[string]int `json:"counts"`
	Findings []lint.Finding `json:"findings"`
}

const usage = `usage (every command takes --config FILE; see lostname config):
  lostname config [--config FILE]                                    print the effective configuration as JSON
  lostname lint  --zone FILE --origin NAME [--strict] [--json]      check a zone file, offline
  lostname fetch --axfr HOST:PORT --origin NAME [--tsig-file FILE]  transfer a zone, write it as a zone file
  lostname parity --zone FILE --origin NAME --provider A=ADDR[,ADDR] --provider B=ADDR[,ADDR] [--model T0|T1|T2] [--json]
                                                                    compare what the providers serve; the first is the reference`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "lint":
		return runLint(args[1:], stdout, stderr)
	case "fetch":
		return runFetch(args[1:], stdout, stderr)
	case "parity":
		return runParity(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "lostname: unknown command %q\n%s\n", args[0], usage)
		return exitUsage
	}
}

func runLint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("zone", "", "RFC 1035 zone file")
	origin := fs.String("origin", "", "zone origin, e.g. example.test")
	strict := fs.Bool("strict", false, "fail on risks as well as blockers")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	cfgPath := fs.String("config", "", "configuration file (JSON); defaults apply to anything it leaves out")
	if err := fs.Parse(args); err != nil || *file == "" || *origin == "" {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "lostname lint: config:", err)
		return exitUsage
	}
	z, err := zone.ReadFile(*file, *origin)
	if err != nil {
		fmt.Fprintln(stderr, "lostname lint:", err)
		return exitUsage
	}
	findings := lint.Apply(lint.Run(z), cfg.Lint.Disabled, cfg.Lint.Severity)
	rep := LintReport{Schema: "lostname.lint/v0", Origin: z.Origin, Source: z.Source, Records: len(z.Records),
		Verdict: "pass", Counts: map[string]int{"blocker": 0, "risk": 0, "note": 0}, Findings: findings}
	if rep.Findings == nil {
		rep.Findings = []lint.Finding{}
	}
	for _, f := range findings {
		rep.Counts[string(f.Severity)]++
	}
	code := exitPass
	if lint.Fails(findings, *strict) {
		rep.Verdict, code = "fail", exitFindings
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return code
	}
	for _, f := range findings {
		fmt.Fprintf(stdout, "%-5s %-7s %s %s: %s (%s)\n", f.Rule, f.Severity, f.Name, f.Type, f.Message, f.Ref)
	}
	fmt.Fprintf(stdout, "lint %s: %s, %d record(s), %d blocker(s), %d risk(s), %d note(s)\n", rep.Verdict, rep.Origin,
		rep.Records, rep.Counts["blocker"], rep.Counts["risk"], rep.Counts["note"])
	return code
}

// runFetch transfers a zone and writes it to stdout as a zone file, so lint can stay offline (decision 0008).
func runFetch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("axfr", "", "server to transfer from, host:port")
	origin := fs.String("origin", "", "zone origin")
	keyFile := fs.String("tsig-file", "", "file with one line: algorithm name secret")
	cfgPath := fs.String("config", "", "configuration file (JSON)")
	if err := fs.Parse(args); err != nil || *server == "" || *origin == "" {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "lostname fetch: config:", err)
		return exitUsage
	}
	o := fetch.Options{Timeout: config.Seconds(cfg.Fetch.Timeout), Canary: cfg.Probe.Canary,
		ProbeTimeout: config.Seconds(cfg.Probe.Timeout)}
	if *keyFile != "" {
		k, err := fetch.ReadTSIGFile(*keyFile)
		if err != nil {
			fmt.Fprintln(stderr, "lostname fetch:", err)
			return exitUsage
		}
		o.TSIG = k
	}
	z, err := fetch.AXFR(*server, *origin, o)
	if errors.Is(err, fetch.ErrNoVerdict) {
		fmt.Fprintln(stderr, "lostname fetch:", err)
		return exitNoVerdict
	}
	if err != nil {
		fmt.Fprintln(stderr, "lostname fetch:", err)
		return exitUsage
	}
	if err := z.WriteZoneFile(stdout); err != nil {
		fmt.Fprintln(stderr, "lostname fetch:", err)
		return exitUsage
	}
	return exitPass
}

// providerFlags collects repeated --provider NAME=ADDR[,ADDR] flags in the order given.
type providerFlags []parity.Provider

func (p *providerFlags) String() string { return fmt.Sprint(*p) }

func (p *providerFlags) Set(v string) error {
	name, addrs, ok := strings.Cut(v, "=")
	if !ok || name == "" || addrs == "" {
		return fmt.Errorf("want NAME=ADDR[,ADDR], got %q", v)
	}
	var list []string
	for _, a := range strings.Split(addrs, ",") {
		if a = strings.TrimSpace(a); a != "" {
			if !strings.Contains(a, "]:") && strings.Count(a, ":") != 1 {
				a = net.JoinHostPort(strings.Trim(a, "[]"), "53")
			}
			list = append(list, a)
		}
	}
	*p = append(*p, parity.Provider{Name: name, Addrs: list})
	return nil
}

// runParity compares what two or more providers serve for the zone in --zone.
func runParity(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("parity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("zone", "", "the zone as it should be served (RFC 1035 zone file)")
	origin := fs.String("origin", "", "zone origin")
	model := fs.String("model", "", "transition model: T0, T1 or T2 (decides whether apex NS may differ; default from config)")
	cfgPath := fs.String("config", "", "configuration file (JSON)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	var providers providerFlags
	fs.Var(&providers, "provider", "NAME=ADDR[,ADDR] (repeat; the first is the reference)")
	if err := fs.Parse(args); err != nil || *file == "" || *origin == "" || len(providers) < 2 {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	z, err := zone.ReadFile(*file, *origin)
	if err != nil {
		fmt.Fprintln(stderr, "lostname parity:", err)
		return exitUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "lostname parity: config:", err)
		return exitUsage
	}
	if *model != "" {
		cfg.Parity.Model = *model
		if err := cfg.Validate(); err != nil {
			fmt.Fprintln(stderr, "lostname parity: --model:", err)
			return exitUsage
		}
	}
	rep, err := parity.Run(z, providers, parity.Options{Model: cfg.Parity.Model,
		Timeout: config.Seconds(cfg.Parity.Timeout), EDNSBuffer: uint16(cfg.Parity.EDNSBuffer),
		NXProbe: cfg.Parity.NXProbe, Canary: cfg.Probe.Canary, ProbeTimeout: config.Seconds(cfg.Probe.Timeout)})
	if err != nil {
		fmt.Fprintln(stderr, "lostname parity:", err)
		return exitUsage
	}
	code, known := map[string]int{"pass": exitPass, "fail": exitFindings, "no_verdict": exitNoVerdict}[rep.Verdict]
	if !known { // fail closed: an unknown verdict is a tool error, never a pass
		fmt.Fprintf(stderr, "lostname parity: internal error: unknown verdict %q\n", rep.Verdict)
		return exitUsage
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return code
	}
	for _, f := range rep.Findings {
		fmt.Fprintf(stdout, "%-4s %-20s %s %s at %s: %s\n", f.Severity, f.Kind, f.Name, f.Type, f.Provider, f.Detail)
	}
	for i, g := range rep.Gaps {
		if i == 10 {
			fmt.Fprintf(stdout, "... %d more gap(s); use --json for all\n", len(rep.Gaps)-10)
			break
		}
		if g.Provider == "" { // a gap for the whole path, not one question
			fmt.Fprintf(stdout, "gap  %s\n", g.Reason)
			continue
		}
		fmt.Fprintf(stdout, "gap  %s %s %s %s %s: %s\n", g.Provider, g.Addr, g.Transport, g.Name, g.Type, g.Reason)
	}
	fmt.Fprintf(stdout, "parity %s: %s, model %s, %d question(s), %d finding(s), %d gap(s)\n", rep.Verdict, rep.Origin,
		rep.Model, rep.Questions, len(rep.Findings), len(rep.Gaps))
	return code
}

// runConfig prints the effective configuration (defaults plus --config), so it can be committed as code.
func runConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file (JSON)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "lostname config:", err)
		return exitUsage
	}
	b, err := cfg.JSON()
	if err != nil {
		fmt.Fprintln(stderr, "lostname config:", err)
		return exitUsage
	}
	fmt.Fprintln(stdout, string(b))
	return exitPass
}
