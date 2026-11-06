// Package parity compares what DNS providers actually serve for a zone (model section 4), fail-closed:
//   - every authoritative address of every provider is asked over UDP (EDNS 1232, DO) and over TCP;
//   - an answer counts only with authority (AA), or as a referral where a zone cut is expected (P1);
//   - the path is checked for interception before any query (P1b);
//   - a definite difference fails; a missing authoritative answer gives no verdict; only full coverage passes.
//
// Signature validation (model section 4, "Signatures") is not in this version; DNSSEC records are not compared yet.
package parity

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/probe"
	"lostname.be/lostname/internal/zone"
)

// Provider is one DNS provider and the addresses ("host:port") of its authoritative servers for the zone.
type Provider struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

// Options control a run. Every field is required; the command fills them from the config (parity.*, probe.*).
type Options struct {
	Model        string        // transition model the comparison is for: T0, T1 (apex NS may differ) or T2 (must match)
	Timeout      time.Duration // per query
	EDNSBuffer   uint16        // advertised UDP payload size
	NXProbe      string        // label of the name that must not exist
	Canary       string        // interception probe address
	ProbeTimeout time.Duration
}

func (o Options) validate() error {
	if o.Model == "" || o.Timeout <= 0 || o.EDNSBuffer == 0 || o.NXProbe == "" || o.Canary == "" || o.ProbeTimeout <= 0 {
		return errors.New("parity: model, timeout, EDNS buffer, NX probe label, probe address and probe timeout are " +
			"required (set them in the config)")
	}
	return nil
}

// Severity of a finding.
type Severity string

const (
	Fail Severity = "fail"
	Risk Severity = "risk"
	Note Severity = "note"
)

// Finding is one difference or problem.
type Finding struct {
	Severity Severity `json:"severity"`
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Provider string   `json:"provider"`
	Detail   string   `json:"detail"`
}

// Gap is a question that got no usable authoritative answer: the reason there is no verdict.
type Gap struct {
	Provider  string `json:"provider"`
	Addr      string `json:"addr"`
	Transport string `json:"transport"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Reason    string `json:"reason"`
}

// Report is the result. It holds no timestamps, so equal inputs give equal reports.
type Report struct {
	Schema      string     `json:"schema"`
	Origin      string     `json:"origin"`
	Model       string     `json:"model"`
	Reference   string     `json:"reference"`
	Providers   []Provider `json:"providers"`
	Questions   int        `json:"questions"`
	Intercepted bool       `json:"intercepted"`
	Verdict     string     `json:"verdict"` // pass, fail or no_verdict
	Findings    []Finding  `json:"findings"`
	Gaps        []Gap      `json:"gaps"`
}

type question struct {
	name, typ string
	kind      string // "record", "referral", "nx-probe", "ent-probe"
}

// answer is one provider's canonical view of one question.
type answer struct {
	class string   // "data", "nodata", "nxdomain", "referral"
	rdata []string // sorted canonical RDATA (or NS targets for a referral)
	ttls  []uint32
}

func (a answer) key() string { return a.class + "|" + strings.Join(a.rdata, "\n") }

// Run compares the providers; the first is the reference the others are compared with.
func Run(z *zone.Zone, providers []Provider, o Options) (Report, error) {
	if err := o.validate(); err != nil {
		return Report{}, err
	}
	if len(providers) < 2 {
		return Report{}, errors.New("parity: give at least two providers; the first is the reference")
	}
	seen := map[string]bool{}
	for _, p := range providers {
		if p.Name == "" || seen[p.Name] || len(p.Addrs) == 0 {
			return Report{}, fmt.Errorf("parity: provider %q: names must be unique and non-empty, with at least one "+
				"address each", p.Name)
		}
		seen[p.Name] = true
	}
	rep := Report{Schema: "lostname.parity/v0", Origin: z.Origin, Model: o.Model, Providers: providers,
		Findings: []Finding{}, Gaps: []Gap{}}
	if len(providers) > 0 {
		rep.Reference = providers[0].Name
	}
	if probe.Intercepted(o.Canary, o.ProbeTimeout) {
		rep.Intercepted, rep.Verdict = true, "no_verdict"
		rep.Gaps = append(rep.Gaps, Gap{Reason: "the network path answers DNS for any address (probe " + o.Canary +
			"); no measurement over it can be trusted"})
		return rep, nil
	}
	qs := questions(z, o.NXProbe)
	rep.Questions = len(qs)
	views := map[string]map[question]*answer{}
	for _, p := range providers {
		views[p.Name] = map[question]*answer{}
		for _, q := range qs {
			views[p.Name][q] = ask(p, q, o, &rep)
		}
	}
	for _, q := range qs {
		ref := views[rep.Reference][q]
		for _, p := range providers {
			a := views[p.Name][q]
			if a == nil {
				continue
			}
			checkAgainstZone(z, q, p.Name, o.Model, *a, &rep)
			if p.Name != rep.Reference && ref != nil {
				compare(q, rep.Reference, *ref, p.Name, *a, o.Model, &rep)
			}
		}
	}
	sortReport(&rep)
	switch {
	case hasFail(rep.Findings):
		rep.Verdict = "fail"
	case len(rep.Gaps) > 0:
		rep.Verdict = "no_verdict"
	default:
		rep.Verdict = "pass"
	}
	return rep, nil
}

var skipTypes = map[string]bool{"RRSIG": true, "NSEC": true, "NSEC3": true, "NSEC3PARAM": true, "DNSKEY": true,
	"CDS": true, "CDNSKEY": true}

// questions lists what is asked: every (name, type) in the zone, the cut NS as a referral, a name that must not
// exist, and every empty non-terminal (model section 4, "Coverage").
func questions(z *zone.Zone, nxLabel string) []question {
	seen := map[question]bool{}
	var qs []question
	add := func(q question) {
		if !seen[q] {
			seen[q] = true
			qs = append(qs, q)
		}
	}
	cuts := z.Delegations()
	below := func(name string) string {
		for _, c := range cuts {
			if dns.IsSubDomain(c, name) {
				return c
			}
		}
		return ""
	}
	names := map[string]bool{}
	for _, r := range z.Records {
		names[r.Name] = true
		if skipTypes[r.Type] {
			continue
		}
		if c := below(r.Name); c != "" {
			add(question{c, "NS", "referral"}) // glue and records below a cut are the child's business
			continue
		}
		add(question{r.Name, r.Type, "record"})
	}
	add(question{nxLabel + "." + z.Origin, "A", "nx-probe"})
	for n := range names {
		for _, anc := range ancestors(n, z.Origin) {
			if !names[anc] && below(anc) == "" {
				add(question{anc, "A", "ent-probe"})
			}
		}
	}
	sort.Slice(qs, func(i, j int) bool {
		if qs[i].name != qs[j].name {
			return qs[i].name < qs[j].name
		}
		return qs[i].typ < qs[j].typ
	})
	return qs
}

func ancestors(name, origin string) []string {
	var out []string
	labels := dns.SplitDomainName(name)
	for i := 1; i < len(labels); i++ {
		a := dns.Fqdn(strings.Join(labels[i:], "."))
		if a == origin || !dns.IsSubDomain(origin, a) {
			break
		}
		out = append(out, a)
	}
	return out
}

// ask queries every address of p over UDP and TCP and returns the provider's single view, or nil when no address
// gave a usable answer. Different answers between a provider's own servers are a finding.
func ask(p Provider, q question, o Options, rep *Report) *answer {
	var got []answer
	for _, addr := range p.Addrs {
		for _, tr := range []string{"udp", "tcp"} {
			a, reason := query(addr, tr, q, o.Timeout, o.EDNSBuffer)
			if reason == truncatedUDP {
				continue // normal: the TCP answer for this address decides
			}
			if reason != "" {
				rep.Gaps = append(rep.Gaps, Gap{p.Name, addr, tr, q.name, q.typ, reason})
				continue
			}
			got = append(got, a)
		}
	}
	if len(got) == 0 {
		return nil
	}
	if q.typ == "SOA" && q.kind == "record" {
		// RL-1: a stale secondary shows as a different serial; report it as such and compare the rest without it.
		serials := map[string]bool{}
		for i := range got {
			if f := strings.Fields(strings.Join(got[i].rdata, " ")); len(f) == 8 {
				serials[f[3]] = true
				f[3] = "-"
				got[i].rdata = []string{strings.Join(f, " ")}
			}
		}
		if len(serials) > 1 {
			var list []string
			for s := range serials {
				list = append(list, s)
			}
			sort.Strings(list)
			rep.Findings = append(rep.Findings, Finding{Risk, "serial-drift", q.name, q.typ, p.Name,
				"the provider's servers serve different SOA serials (" + strings.Join(list, ", ") + "): a secondary is behind"})
		}
	}
	for _, a := range got[1:] {
		if a.key() != got[0].key() {
			rep.Findings = append(rep.Findings, Finding{Fail, "inconsistent-servers", q.name, q.typ, p.Name,
				"the provider's own servers or transports give different answers"})
			break
		}
	}
	return &got[0]
}

const truncatedUDP = "truncated over UDP"

func query(addr, transport string, q question, timeout time.Duration, edns uint16) (answer, string) {
	m := new(dns.Msg)
	m.SetQuestion(q.name, rrtype(q.typ))
	m.RecursionDesired = false
	m.SetEdns0(edns, true)
	c := &dns.Client{Net: transport, Timeout: timeout}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		return answer{}, "no answer: " + shortErr(err)
	}
	if r.Truncated {
		if transport == "udp" {
			return answer{}, truncatedUDP
		}
		return answer{}, "truncated over TCP"
	}
	switch r.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return answer{}, "rcode " + dns.RcodeToString[r.Rcode]
	}
	if q.kind == "referral" {
		var ns []string
		for _, rr := range r.Ns {
			if v, ok := rr.(*dns.NS); ok && strings.EqualFold(v.Hdr.Name, q.name) {
				ns = append(ns, strings.ToLower(v.Ns))
			}
		}
		if len(ns) == 0 {
			return answer{}, "no referral where a zone cut is expected"
		}
		sort.Strings(ns)
		return answer{class: "referral", rdata: ns}, ""
	}
	if !r.Authoritative {
		return answer{}, "not authoritative (AA not set)"
	}
	if r.Rcode == dns.RcodeNameError {
		return answer{class: "nxdomain"}, ""
	}
	var a answer
	for _, rr := range r.Answer {
		h := rr.Header()
		if !strings.EqualFold(h.Name, q.name) {
			continue // stop at the first CNAME: its target is another question
		}
		if h.Rrtype != rrtype(q.typ) && h.Rrtype != dns.TypeCNAME {
			continue // RRSIGs and other types that come with the answer are compared separately (DNSSEC parity)
		}
		a.rdata = append(a.rdata, dns.Type(h.Rrtype).String()+" "+canonical(rr))
		a.ttls = append(a.ttls, h.Ttl)
	}
	if len(a.rdata) == 0 {
		a.class = "nodata"
		return a, ""
	}
	a.class = "data"
	sort.Strings(a.rdata)
	sort.Slice(a.ttls, func(i, j int) bool { return a.ttls[i] < a.ttls[j] })
	return a, ""
}

// Types whose RDATA holds only domain names, numbers and addresses: compared case-insensitively (RFC 4343).
var foldTypes = map[uint16]bool{dns.TypeNS: true, dns.TypeCNAME: true, dns.TypeMX: true, dns.TypePTR: true,
	dns.TypeSRV: true, dns.TypeDNAME: true, dns.TypeSOA: true, dns.TypeA: true, dns.TypeAAAA: true}

func canonical(rr dns.RR) string {
	s := strings.TrimPrefix(rr.String(), rr.Header().String())
	if foldTypes[rr.Header().Rrtype] {
		s = strings.ToLower(s)
	}
	return s
}

func shortErr(err error) string {
	s := err.Error()
	if strings.Contains(s, "timeout") {
		return "timeout"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// checkAgainstZone: a record the zone has must be served with the zone's RDATA and TTL (H3: two providers that agree
// on wrong data must not pass), a record must not answer empty, and an empty non-terminal must not be NXDOMAIN.
func checkAgainstZone(z *zone.Zone, q question, provider, model string, a answer, rep *Report) {
	switch q.kind {
	case "record":
		if a.class == "nodata" || a.class == "nxdomain" {
			rep.Findings = append(rep.Findings, Finding{Fail, "record-missing", q.name, q.typ, provider,
				"the zone has this record, the provider answers " + a.class})
			return
		}
		if a.class != "data" || q.typ == "SOA" || (q.typ == "NS" && q.name == z.Origin && model != "T2") {
			return // SOA: providers rewrite serial and timers (RL-1 and the SOA rules cover it); apex NS: per model
		}
		want := expected(z, q)
		switch {
		case strings.Join(want.rdata, "\n") != strings.Join(a.rdata, "\n"):
			if q.typ == "TXT" && concat(want.rdata) == concat(a.rdata) {
				rep.Findings = append(rep.Findings, Finding{Note, "txt-split-differs-zone", q.name, q.typ, provider,
					"TXT strings are split differently from the zone file; the concatenated text is equal"})
				return
			}
			rep.Findings = append(rep.Findings, Finding{Fail, "zone-differs", q.name, q.typ, provider,
				fmt.Sprintf("the zone file has %v; this provider answers %v", want.rdata, a.rdata)})
		case !sameTTLs(want.ttls, a.ttls):
			rep.Findings = append(rep.Findings, Finding{Fail, "ttl-differs-zone", q.name, q.typ, provider,
				fmt.Sprintf("TTL %v in the zone file, %v here (a provider minimum or a stale copy)", want.ttls, a.ttls)})
		}
	case "ent-probe":
		if a.class == "nxdomain" {
			rep.Findings = append(rep.Findings, Finding{Fail, "ent-nxdomain", q.name, q.typ, provider,
				"an empty non-terminal answered NXDOMAIN instead of NODATA (RFC 8020)"})
		}
	case "nx-probe":
		if a.class != "nxdomain" && hasWildcard(z) {
			rep.Findings = append(rep.Findings, Finding{Note, "nx-probe-wildcard", q.name, q.typ, provider,
				"the zone has a wildcard, so a name that does not exist is synthesized (" + a.class + ")"})
		} else if a.class != "nxdomain" {
			rep.Findings = append(rep.Findings, Finding{Fail, "nx-probe", q.name, q.typ, provider,
				"a name that does not exist answered " + a.class + ": wildcard or synthesis to check"})
		}
	}
}

// expected is the zone file's own view of a record question, canonicalised like a provider answer.
func expected(z *zone.Zone, q question) answer {
	var a answer
	for _, r := range z.At(q.name, q.typ) {
		a.rdata = append(a.rdata, q.typ+" "+canonical(r.RR()))
		a.ttls = append(a.ttls, r.TTL)
	}
	sort.Strings(a.rdata)
	sort.Slice(a.ttls, func(i, j int) bool { return a.ttls[i] < a.ttls[j] })
	return a
}

func compare(q question, refName string, ref answer, name string, a answer, model string, rep *Report) {
	if q.typ == "SOA" && q.kind == "record" {
		compareSOA(q, refName, ref, name, a, rep)
		return
	}
	if ref.key() == a.key() {
		if !sameTTLs(ref.ttls, a.ttls) {
			rep.Findings = append(rep.Findings, Finding{Fail, "ttl-differs", q.name, q.typ, name,
				fmt.Sprintf("TTL %v at %s, %v here", ref.ttls, refName, a.ttls)})
		}
		return
	}
	if q.typ == "NS" && q.kind == "record" && ref.class == "data" && a.class == "data" && (model == "T0" || model == "T1") {
		rep.Findings = append(rep.Findings, Finding{Note, "apex-ns-differs", q.name, q.typ, name,
			"apex NS differs, as expected in " + model})
		return
	}
	if q.typ == "TXT" && concat(ref.rdata) == concat(a.rdata) {
		rep.Findings = append(rep.Findings, Finding{Note, "txt-split-differs", q.name, q.typ, name,
			"TXT strings are split differently; the concatenated text is equal"})
		return
	}
	rep.Findings = append(rep.Findings, Finding{Fail, "rrset-differs", q.name, q.typ, name,
		fmt.Sprintf("%s answers %s %v; this provider answers %s %v", refName, ref.class, ref.rdata, a.class, a.rdata)})
}

func compareSOA(q question, refName string, ref answer, name string, a answer, rep *Report) {
	f := func(an answer) []string {
		if an.class != "data" || len(an.rdata) == 0 {
			return nil
		}
		return strings.Fields(an.rdata[0]) // SOA mname rname serial refresh retry expire minimum
	}
	r, x := f(ref), f(a)
	if len(r) != 8 || len(x) != 8 {
		rep.Findings = append(rep.Findings, Finding{Fail, "soa-missing", q.name, q.typ, name, "no SOA to compare"})
		return
	}
	if r[7] != x[7] {
		rep.Findings = append(rep.Findings, Finding{Risk, "soa-minimum-differs", q.name, q.typ, name,
			"SOA MINIMUM " + r[7] + " at " + refName + ", " + x[7] + " here: the negative-caching TTL changes"})
	}
	for i, field := range []string{"REFRESH", "RETRY", "EXPIRE"} {
		if r[4+i] != x[4+i] {
			rep.Findings = append(rep.Findings, Finding{Note, "soa-timer-differs", q.name, q.typ, name,
				field + " " + r[4+i] + " at " + refName + ", " + x[4+i] + " here"})
		}
	}
}

func concat(rdata []string) string {
	var parts []string
	for _, r := range rdata {
		parts = append(parts, strings.ReplaceAll(strings.ReplaceAll(r, "\" \"", ""), " ", ""))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func sameTTLs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasFail(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == Fail {
			return true
		}
	}
	return false
}

func sortReport(r *Report) {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		return a.Name+a.Type+a.Provider+a.Kind < b.Name+b.Type+b.Provider+b.Kind
	})
	sort.SliceStable(r.Gaps, func(i, j int) bool {
		a, b := r.Gaps[i], r.Gaps[j]
		return a.Provider+a.Addr+a.Transport+a.Name+a.Type < b.Provider+b.Addr+b.Transport+b.Name+b.Type
	})
}

func hasWildcard(z *zone.Zone) bool {
	for _, r := range z.Records {
		if strings.HasPrefix(r.Name, "*.") {
			return true
		}
	}
	return false
}

// rrtype maps a type name back to its number, including the RFC 3597 form TYPEnnn used for types the library does
// not know (L13), so such records are asked about instead of type 0.
func rrtype(s string) uint16 {
	if t, ok := dns.StringToType[s]; ok {
		return t
	}
	if n, err := strconv.ParseUint(strings.TrimPrefix(s, "TYPE"), 10, 16); err == nil && strings.HasPrefix(s, "TYPE") {
		return uint16(n)
	}
	return 0
}
