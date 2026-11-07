// Command lostname: prove you can leave your DNS provider without losing your name.
//
// Exit codes (model section 7, decision 0008): 0 pass, 1 findings, 2 no verdict, 3 usage or input error.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lostname.be/lostname/internal/config"
	"lostname.be/lostname/internal/evidence"
	"lostname.be/lostname/internal/fetch"
	"lostname.be/lostname/internal/lint"
	"lostname.be/lostname/internal/parity"
	"lostname.be/lostname/internal/sarif"
	"lostname.be/lostname/internal/target"
	"lostname.be/lostname/internal/watch"
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
	Baseline *BaselineCount `json:"baseline,omitempty"` // with --baseline: the findings are only what got worse
	Target   *TargetInfo    `json:"target,omitempty"`   // with --to: the provider and the matrix the verdict rests on
}

// TargetInfo names the provider data a --to verdict rests on, so a pass is never read without its source and age.
type TargetInfo struct {
	Provider string `json:"provider"`
	Matrix   string `json:"matrix"`   // e.g. DNSControl v5.7.0
	Commit   string `json:"commit"`   // the documentation commit the matrix was read from
	Released string `json:"released"` // the release date, YYYY-MM-DD
}

// BaselineCount summarises a comparison with --baseline.
type BaselineCount struct {
	Worse int `json:"worse"` // new findings, or findings whose severity rose; these are the report's findings
	Fixed int `json:"fixed"` // baseline findings that are gone
}

const usage = `usage (every command takes --config FILE; see lostname config):
  lostname config [--config FILE]                                    print the effective configuration as JSON
  lostname doctor [--config FILE]                                    preflight: config, interception probes, watch files
  lostname lint  --zone FILE|--dnscontrol-ir FILE --origin NAME [--to PROVIDER] [--current FILE] [--strict] [--baseline REPORT]
                 [--json|--sarif] [--evidence DIR]
                                                                    check a zone file, offline
  lostname mail  --zone FILE|--dnscontrol-ir FILE --origin NAME [--strict] [--json]
                                                                    read the zone's mail records (SPF, DMARC, DKIM, MTA-STS,
                                                                    TLS-RPT, BIMI, TLSA), offline
  lostname fetch --axfr HOST:PORT --origin NAME [--tsig-file FILE]  transfer a zone, write it as a zone file
  lostname parity --zone FILE --origin NAME --provider A=ADDR[,ADDR] --provider B=ADDR[,ADDR] [--parent ADDR[,ADDR]]
                  [--model T0|T1|T2] [--json|--sarif] [--evidence DIR]
                                                                    compare what the providers serve; the first is the reference
  lostname watch [--config FILE] [--once]                            run the configured checks on an interval; /metrics`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// SARIF levels for the two severity scales (docs/schemas: lint blocker corresponds to parity fail).
var (
	lintLevel   = map[lint.Severity]string{lint.Blocker: "error", lint.Risk: "warning", lint.Note: "note"}
	parityLevel = map[parity.Severity]string{parity.Fail: "error", parity.Risk: "warning", parity.Note: "note"}
)

func run(args []string, stdout, stderr io.Writer) int {
	stdout, stderr = safeWriter{stdout}, safeWriter{stderr}
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
	case "watch":
		return runWatch(args[1:], stdout, stderr)
	case "mail":
		return runMail(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "lostname: unknown command %q\n%s\n", args[0], usage)
		return exitUsage
	}
}

func runLint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("zone", "", "RFC 1035 zone file")
	irFile := fs.String("dnscontrol-ir", "", "the output of `dnscontrol print-ir` (instead of --zone)")
	to := fs.String("to", "", "the target provider, by its DNSControl name (e.g. HETZNER_V2): what will not survive the move")
	current := fs.String("current", "", "the zone as it is served now (a zone file, e.g. from fetch): checks the config's DNSSEC intent against it")
	origin := fs.String("origin", "", "zone origin, e.g. example.test")
	strict := fs.Bool("strict", false, "fail on risks as well as blockers")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	asSARIF := fs.Bool("sarif", false, "print the findings as SARIF 2.1.0, for code-scanning views")
	baseline := fs.String("baseline", "", "an earlier `lint --json` report of this zone: report and judge only what got worse")
	evidenceDir := fs.String("evidence", "", "write an evidence bundle (inputs, report, versions, manifest) under this directory")
	cfgPath := fs.String("config", "", "configuration file (JSON); defaults apply to anything it leaves out")
	if err := fs.Parse(args); err != nil || (*file == "") == (*irFile == "") || *origin == "" || (*asJSON && *asSARIF) {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "lostname lint: config:", err)
		return exitUsage
	}
	z, err := readLintInput(*file, *irFile, *origin)
	if err != nil {
		fmt.Fprintln(stderr, "lostname lint:", err)
		return exitUsage
	}
	all := lint.Run(z)
	if *irFile != "" {
		all = configChecks(all)
	}
	var tp *target.Provider
	if *to != "" {
		p, err := target.Lookup(*to)
		if err != nil {
			fmt.Fprintln(stderr, "lostname lint: --to:", err)
			return exitUsage
		}
		tp = &p
		all = append(all, lint.RunTarget(z, p)...)
	}
	if *irFile != "" {
		var cur *zone.Zone
		if *current != "" {
			if cur, err = zone.ReadFile(*current, *origin); err != nil {
				fmt.Fprintln(stderr, "lostname lint: --current:", err)
				return exitUsage
			}
		}
		all = append(all, lint.RunIntent(z, cur, tp)...)
	}
	findings := lint.Apply(lint.Sorted(all), cfg.Lint.Disabled, cfg.Lint.Severity)
	var count *BaselineCount
	if *baseline != "" {
		base, err := readBaseline(*baseline, z.Origin)
		if err != nil {
			fmt.Fprintln(stderr, "lostname lint: --baseline:", err)
			return exitUsage
		}
		worse, fixed := lint.Diff(base, findings)
		findings, count = worse, &BaselineCount{Worse: len(worse), Fixed: len(fixed)}
	}
	rep := LintReport{Schema: "lostname.lint/v0", Origin: z.Origin, Source: z.Source, Records: len(z.Records),
		Verdict: "pass", Counts: map[string]int{"blocker": 0, "risk": 0, "note": 0}, Findings: findings, Baseline: count}
	if rep.Findings == nil {
		rep.Findings = []lint.Finding{}
	}
	if *to != "" {
		src := target.From()
		rep.Target = &TargetInfo{Provider: tp.Name, Matrix: "DNSControl " + src.Tag, Commit: src.Commit,
			Released: src.Released}
	}
	for _, f := range findings {
		rep.Counts[string(f.Severity)]++
	}
	code := exitPass
	if lint.Fails(findings, *strict) {
		rep.Verdict, code = "fail", exitFindings
	}
	if *evidenceDir != "" {
		inputs := map[string]string{"zone": *file, "ir": *irFile, "baseline": *baseline, "current": *current}
		extra := map[string]any{}
		if *to != "" {
			extra["capabilities"] = target.From()
		}
		if err := writeEvidence(stderr, *evidenceDir, "lint", z.Origin, inputs, "findings.json", rep, nil, extra); err != nil {
			fmt.Fprintln(stderr, "lostname lint: --evidence:", err)
			return exitUsage
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return code
	}
	if *asSARIF {
		in := *file
		if in == "" {
			in = *irFile
		}
		var rs []sarif.Result
		for _, f := range findings {
			rs = append(rs, sarif.Result{RuleID: f.Rule, Level: lintLevel[f.Severity], URI: artifactURI(in),
				Message: f.Message + " (" + f.Ref + ")", Logical: strings.TrimSpace(f.Name + " " + f.Type)})
		}
		_ = sarif.Write(stdout, rs, nil, true, func(id string) string {
			return "Lostname lint rule " + id + " (model section 3)"
		})
		return code
	}
	for _, f := range findings {
		fmt.Fprintf(stdout, "%-5s %-7s %s %s: %s (%s)\n", f.Rule, f.Severity, f.Name, f.Type, f.Message, f.Ref)
	}
	fmt.Fprintf(stdout, "lint %s: %s, %d record(s), %d blocker(s), %d risk(s), %d note(s)", rep.Verdict, rep.Origin,
		rep.Records, rep.Counts["blocker"], rep.Counts["risk"], rep.Counts["note"])
	if count != nil {
		fmt.Fprintf(stdout, " against the baseline: %d worse, %d fixed", count.Worse, count.Fixed)
	}
	if rep.Target != nil {
		fmt.Fprintf(stdout, "; target %s per the %s provider matrix of %s", rep.Target.Provider, rep.Target.Matrix,
			rep.Target.Released)
	}
	fmt.Fprintln(stdout)
	return code
}

// runWatch runs the configured checks every watch.interval_seconds and serves the results on watch.listen at
// /metrics (OpenMetrics). With --once it runs one round, prints the metrics and exits with the worst verdict's code.
func runWatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file (JSON) with a watch section")
	once := fs.Bool("once", false, "run one round, print the metrics, and exit")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "lostname watch: config:", err)
		return exitUsage
	}
	if len(cfg.Watch.Zones) == 0 {
		fmt.Fprintln(stderr, "lostname watch: the config has no watch.zones: name at least one zone to check")
		return exitUsage
	}
	snap := watch.NewSnapshot()
	if f := cfg.Watch.ZoneID.SaltFile; f != "" {
		salt, err := os.ReadFile(f)
		if err != nil || len(salt) < 16 {
			fmt.Fprintf(stderr, "lostname watch: watch.zone_id.salt_file: want a readable file of at least 16 bytes "+
				"of secret salt (%v)\n", err)
			return exitUsage
		}
		snap.SetZoneKey(salt)
	}
	// Runtime messages of the long-running loop are structured (slog, text on stderr), so a log stack can parse them;
	// usage and configuration errors stay plain, for the person at the prompt.
	log := slog.New(slog.NewTextHandler(stderr, nil)).With("cmd", "watch")
	push := func() {
		if cfg.Watch.OTLP == "" {
			return
		}
		if err := snap.Push(&http.Client{Timeout: 30 * time.Second}, cfg.Watch.OTLP, sarif.ToolVersion(), cfg.Watch.Resource); err != nil {
			log.Warn("OTLP metrics push failed", "err", err)
		}
	}
	// Traces go once per round, right after it: unlike the metrics they are not re-sent.
	traces := func() {
		if !cfg.Watch.Traces {
			return
		}
		if err := watch.PushTraces(&http.Client{Timeout: 30 * time.Second}, cfg.Watch.OTLP, sarif.ToolVersion(),
			cfg.Watch.Resource, snap.Results()); err != nil {
			log.Warn("OTLP traces push failed", "err", err)
		}
	}
	events := eventSender(cfg, log)
	if *once {
		events(watch.Round(cfg, snap, time.Now), snap)
		traces()
		push()
		_ = snap.WriteOpenMetrics(stdout)
		return map[string]int{"pass": exitPass, "fail": exitFindings, "no_verdict": exitNoVerdict}[snap.Worst()]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", metricsHandler(snap))
	// Red team 2, W6: idle and slow connections are closed, so a client cannot hold the process's handles.
	srv := &http.Server{Addr: cfg.Watch.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		for {
			events(watch.Round(cfg, snap, time.Now), snap)
			log.Info("round done", "checks", len(snap.Results()), "worst", snap.Worst())
			traces()
			push()
			time.Sleep(config.Seconds(cfg.Watch.Interval))
		}
	}()
	// Red team 2 (lead): an OTLP-fed stack only sees a series within its lookback (5 minutes in Prometheus), so the
	// latest snapshot is sent again every 30 seconds, not only once per round. What is absent stays absent.
	go func() {
		for range time.Tick(30 * time.Second) {
			push()
		}
	}()
	fmt.Fprintf(stderr, "lostname watch: %d zone(s) every %d s; metrics on http://%s/metrics\n", len(cfg.Watch.Zones),
		cfg.Watch.Interval, cfg.Watch.Listen)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(stderr, "lostname watch:", err)
		return exitUsage
	}
	return exitPass
}

// eventSender returns the function that turns each round into events and sends them over the transports in
// watch.events; with none configured it does nothing. A failed delivery is reported on stderr and not retried.
func eventSender(cfg *config.Config, log *slog.Logger) func(*watch.Interception, *watch.Snapshot) {
	if len(cfg.Watch.Events) == 0 {
		return func(*watch.Interception, *watch.Snapshot) {}
	}
	instance := cfg.Watch.Instance
	if instance == "" {
		instance, _ = os.Hostname()
	}
	tr := watch.NewTracker(instance, cfg.Watch.Resource)
	if cfg.Watch.State != "" {
		if err := tr.Load(cfg.Watch.State); err != nil {
			// Not fatal: the resync event after the first round tells consumers the whole state anyway.
			log.Warn("state file not loaded; starting without it, the resync event follows the first round", "err", err)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	first := true
	return func(caught *watch.Interception, snap *watch.Snapshot) {
		results, run, now := snap.Results(), watch.RunID(), time.Now()
		evs := tr.Observe(results, caught, run, now)
		tr.Prune(results)
		if first { // decision of 2026-11-06: consumers can replace their state after any restart
			evs, first = append(evs, tr.Resync(run, now)), false
		}
		if cfg.Watch.State != "" {
			if err := tr.Save(cfg.Watch.State); err != nil {
				log.Warn("state file not saved", "err", err)
			}
		}
		if len(evs) == 0 {
			return
		}
		for _, t := range cfg.Watch.Events {
			var err error
			switch t {
			case "http":
				err = watch.SendHTTP(client, cfg.Watch.EventsTo, evs)
			case "otlp":
				err = watch.PushLogs(client, cfg.Watch.OTLP, sarif.ToolVersion(), cfg.Watch.Resource, evs)
			}
			if err != nil {
				log.Warn("event delivery failed", "transport", t, "events", len(evs), "err", err)
			}
		}
	}
}

// writeEvidence writes one evidence bundle and names it on stderr: the inputs, the report, every DNS exchange per
// server and transport, and versions; MANIFEST.sha256 covers them all.
func writeEvidence(stderr io.Writer, dir, command, origin string, inputs map[string]string, reportName string,
	report any, snaps map[string][]parity.Exchange, extra map[string]any) error {
	b, err := evidence.New(dir, command, origin, time.Now())
	if err != nil {
		return err
	}
	for role, in := range inputs {
		if in != "" {
			if err := b.AddInput(role, in); err != nil {
				return err
			}
		}
	}
	if err := b.AddJSON(reportName, report); err != nil {
		return err
	}
	safe := strings.NewReplacer(":", "_", "[", "", "]", "")
	for k, ex := range snaps {
		if err := b.AddJSON("snapshots/"+safe.Replace(k)+".json", ex); err != nil {
			return err
		}
	}
	path, err := b.Close(sarif.ToolVersion(), extra)
	if err != nil {
		return err
	}
	fmt.Fprintln(stderr, "evidence:", path)
	return nil
}

// artifactURI is the SARIF location of an input: relative to the working directory when it lies below it, as code
// scanning wants a path relative to the repository (red team 2, C10), else the path as given.
func artifactURI(path string) string {
	if wd, err := os.Getwd(); err == nil {
		if abs, err := filepath.Abs(path); err == nil {
			if rel, err := filepath.Rel(wd, abs); err == nil && !strings.HasPrefix(rel, "..") {
				return filepath.ToSlash(rel)
			}
		}
	}
	return filepath.ToSlash(path)
}

// metricsHandler serves the snapshot in OpenMetrics, to GET and HEAD only (red team 2, W6).
func metricsHandler(snap *watch.Snapshot) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
		_ = snap.WriteOpenMetrics(w)
	}
}

// readLintInput reads the zone from a zone file or from DNSControl's print-ir output.
func readLintInput(file, irFile, origin string) (*zone.Zone, error) {
	if file != "" {
		return zone.ReadFile(file, origin)
	}
	f, err := os.Open(irFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return zone.ReadDNSControlIR(f, irFile, origin)
}

// configChecks drops the zone-only findings that assume a complete zone: a DNSControl config leaves the apex SOA and
// NS to the provider (L-00, L-15), and L-01 judges a missing SOA against the target instead.
func configChecks(fs []lint.Finding) []lint.Finding {
	var out []lint.Finding
	for _, f := range fs {
		if f.Rule != "L-00" && f.Rule != "L-15" {
			out = append(out, f)
		}
	}
	return out
}

// readBaseline reads an earlier `lint --json` report and returns its findings. A report of another zone, of another
// schema, or itself made against a baseline (its findings are only a difference) is refused.
func readBaseline(path, origin string) ([]lint.Finding, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r LintReport
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return nil, fmt.Errorf("%s: not a lint --json report: %v", path, err)
	}
	switch {
	case r.Schema != "lostname.lint/v0":
		return nil, fmt.Errorf("%s: schema %q, want lostname.lint/v0", path, r.Schema)
	case r.Origin != origin:
		return nil, fmt.Errorf("%s is a report for %s, not %s", path, r.Origin, origin)
	case r.Baseline != nil:
		return nil, fmt.Errorf("%s was itself made against a baseline, so it lists only a difference; "+
			"use a full report (lint --json without --baseline)", path)
	}
	return r.Findings, nil
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
	o := fetch.Options{Timeout: config.Seconds(cfg.Fetch.Timeout), Deadline: config.Seconds(cfg.Fetch.Deadline),
		MaxRecords: cfg.Fetch.MaxRecords, Canary: cfg.Probe.Canary, Canary6: cfg.Probe.CanaryV6, ProbeTimeout: config.Seconds(cfg.Probe.Timeout)}
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
	*p = append(*p, parity.Provider{Name: name, Addrs: addrList(addrs)})
	return nil
}

// addrList splits ADDR[,ADDR] and adds port 53 where none is given.
func addrList(addrs string) []string {
	var list []string
	for _, a := range strings.Split(addrs, ",") {
		if a = strings.TrimSpace(a); a != "" {
			if !strings.Contains(a, "]:") && strings.Count(a, ":") != 1 {
				a = net.JoinHostPort(strings.Trim(a, "[]"), "53")
			}
			list = append(list, a)
		}
	}
	return list
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
	parent := fs.String("parent", "", "the parent zone's servers, ADDR[,ADDR]: needed to check a signed zone's chain to its DS")
	asSARIF := fs.Bool("sarif", false, "print the findings as SARIF 2.1.0, for code-scanning views")
	evidenceDir := fs.String("evidence", "", "write an evidence bundle (every DNS exchange, report, versions, manifest) under this directory")
	var providers providerFlags
	fs.Var(&providers, "provider", "NAME=ADDR[,ADDR] (repeat; the first is the reference)")
	if err := fs.Parse(args); err != nil || *file == "" || *origin == "" || len(providers) < 2 || (*asJSON && *asSARIF) {
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
	snaps := map[string][]parity.Exchange{}
	var observe func(parity.Exchange)
	if *evidenceDir != "" {
		observe = func(e parity.Exchange) { snaps[e.Server+"-"+e.Transport] = append(snaps[e.Server+"-"+e.Transport], e) }
	}
	rep, err := parity.Run(z, providers, parity.Options{Model: cfg.Parity.Model,
		Timeout: config.Seconds(cfg.Parity.Timeout), EDNSBuffer: uint16(cfg.Parity.EDNSBuffer),
		NXProbe: cfg.Parity.NXProbe, Canary: cfg.Probe.Canary, Canary6: cfg.Probe.CanaryV6, ProbeTimeout: config.Seconds(cfg.Probe.Timeout),
		Now: time.Now(), MinSigLife: config.Seconds(cfg.Parity.MinSigLife), Deadline: config.Seconds(cfg.Parity.Deadline), MaxQueries: cfg.Parity.MaxQueries,
		Pace: time.Duration(cfg.Parity.Pace) * time.Millisecond, Parent: addrList(*parent), Observe: observe})
	if err != nil {
		fmt.Fprintln(stderr, "lostname parity:", err)
		return exitUsage
	}
	if *evidenceDir != "" {
		if err := writeEvidence(stderr, *evidenceDir, "parity", z.Origin, map[string]string{"zone": *file}, "parity.json", rep, snaps, nil); err != nil {
			fmt.Fprintln(stderr, "lostname parity: --evidence:", err)
			return exitUsage
		}
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
	if *asSARIF {
		var rs []sarif.Result
		for _, f := range rep.Findings {
			rs = append(rs, sarif.Result{RuleID: f.Kind, Level: parityLevel[f.Severity], URI: artifactURI(*file),
				Message: f.Provider + ": " + f.Detail, Logical: f.Name + " " + f.Type})
		}
		var ns []sarif.Notice
		for _, g := range rep.Gaps {
			ns = append(ns, sarif.Notice{Level: "warning", Message: strings.TrimSpace(fmt.Sprintf("no verdict: %s %s %s %s %s: %s",
				g.Provider, g.Addr, g.Transport, g.Name, g.Type, g.Reason))})
		}
		_ = sarif.Write(stdout, rs, ns, rep.Verdict != "no_verdict", func(id string) string {
			return "Lostname parity check " + id + " (model section 4)"
		})
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
