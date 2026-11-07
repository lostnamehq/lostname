package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"lostname.be/lostname/internal/records"
)

// MailReport is the JSON output of `lostname mail` (docs/schemas/mail-report.schema.json).
type MailReport struct {
	Schema   string            `json:"schema"`
	Origin   string            `json:"origin"`
	Source   string            `json:"source"`
	Verdict  string            `json:"verdict"` // pass or fail
	Counts   map[string]int    `json:"counts"`
	Posture  records.Posture   `json:"posture"`
	Findings []records.Finding `json:"findings"`
}

// runMail reads the zone's mail records (decision 0011): offline, from a zone file or DNSControl IR, only the names
// the zone contains.
func runMail(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mail", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("zone", "", "RFC 1035 zone file")
	irFile := fs.String("dnscontrol-ir", "", "the output of `dnscontrol print-ir` (instead of --zone)")
	origin := fs.String("origin", "", "zone origin, e.g. example.test")
	strict := fs.Bool("strict", false, "fail on risks as well as blockers")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	_ = fs.String("config", "", "configuration file (JSON); mail reads none of it yet")
	if err := fs.Parse(args); err != nil || (*file == "") == (*irFile == "") || *origin == "" {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	z, err := readLintInput(*file, *irFile, *origin)
	if err != nil {
		fmt.Fprintln(stderr, "lostname mail:", err)
		return exitUsage
	}
	posture, findings := records.Read(z)
	rep := MailReport{Schema: "lostname.mail/v0", Origin: z.Origin, Source: z.Source, Verdict: "pass",
		Counts: map[string]int{"blocker": 0, "risk": 0, "note": 0}, Posture: posture, Findings: findings}
	if rep.Findings == nil {
		rep.Findings = []records.Finding{}
	}
	code := exitPass
	for _, f := range findings {
		rep.Counts[string(f.Severity)]++
		if f.Severity == records.Blocker || (*strict && f.Severity == records.Risk) {
			rep.Verdict, code = "fail", exitFindings
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return code
	}
	p := rep.Posture
	yes := func(b bool) string { return map[bool]string{true: "yes", false: "no"}[b] }
	fmt.Fprintf(stdout, "mail %s: MX %s\n", rep.Origin, strings.Join(p.MX, ", "))
	fmt.Fprintf(stdout, "  SPF %s, DMARC %s, MTA-STS %s, TLS-RPT %s, DKIM selectors %d, TLSA %d, BIMI %d\n",
		yes(p.SPF != nil), dmarcText(p.DMARC), yes(p.MTASTS != nil), yes(p.TLSRPT != nil), len(p.DKIM), len(p.TLSA),
		len(p.BIMI))
	for _, f := range findings {
		fmt.Fprintf(stdout, "%-5s %-7s %s %s: %s (%s)\n", f.Rule, f.Severity, f.Name, f.Type, f.Message, f.Ref)
	}
	fmt.Fprintf(stdout, "mail %s: %s, %d blocker(s), %d risk(s), %d note(s)\n", rep.Verdict, rep.Origin,
		rep.Counts["blocker"], rep.Counts["risk"], rep.Counts["note"])
	return code
}

func dmarcText(d *records.DMARC) string {
	if d == nil {
		return "no"
	}
	if d.Policy == "" {
		return "yes (no valid policy)"
	}
	return "p=" + d.Policy
}
