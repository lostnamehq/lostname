// Package parity compares what DNS providers actually serve for a zone (model section 4), fail-closed:
//   - every authoritative address of every provider is asked over UDP (EDNS 1232, DO) and over TCP;
//   - an answer counts only with authority (AA), or as a referral where a zone cut is expected (P1);
//   - the path is checked for interception before any query (P1b);
//   - a definite difference fails; a missing authoritative answer gives no verdict; only full coverage passes.
//
// Signatures (model section 4): every RRSIG a server returns is checked against that server's own DNSKEY RRset:
// inside its validity window, made by a key the server publishes, and cryptographically valid. Where the zone file is
// signed, every answered RRset must carry a valid signature. Not yet: the chain to the parent's DS, and authenticated
// denial (NSEC, NSEC3).
package parity

import (
	"errors"
	"fmt"
	"net"
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
	Canary       string        // interception probe address, IPv4
	Canary6      string        // interception probe address, IPv6 (M9)
	ProbeTimeout time.Duration
	Now          time.Time     // the moment signatures are judged at; the command passes the current time
	MinSigLife   time.Duration // a valid signature that expires sooner than this is a risk (parity.min_signature_life_seconds)
	// Limits for a run against real providers (plan v0.1, "Parity at scale"); zero means none. A question that a
	// limit stops is a gap, so the run ends without a verdict rather than with a partial pass.
	Deadline   time.Duration  // the whole run (parity.deadline_seconds)
	MaxQueries int            // per server address (parity.max_queries_per_server)
	Pace       time.Duration  // the least time between two queries to one server address (parity.pace_milliseconds)
	Parent     []string       // the parent zone's servers, for the DS RRset; optional, but a signed zone needs it
	Observe    func(Exchange) // optional: called with every DNS exchange, for an evidence bundle
}

// Exchange is one DNS question and what came back, as an evidence bundle records it (model section 6).
type Exchange struct {
	Time       string   `json:"time"` // RFC 3339, UTC, when the answer (or the error) arrived
	Server     string   `json:"server"`
	Transport  string   `json:"transport"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Rcode      string   `json:"rcode,omitempty"`
	AA         bool     `json:"aa"`
	TC         bool     `json:"tc"`
	Answer     []string `json:"answer,omitempty"`
	Authority  []string `json:"authority,omitempty"`
	Additional []string `json:"additional,omitempty"`
	Error      string   `json:"error,omitempty"`
	// Started is when the query was sent, for a trace span; not part of the evidence JSON.
	Started time.Time `json:"-"`
}

func (o Options) validate() error {
	if o.Model == "" || o.Timeout <= 0 || o.EDNSBuffer == 0 || o.NXProbe == "" || o.Canary == "" || o.Canary6 == "" ||
		o.ProbeTimeout <= 0 || o.Now.IsZero() || o.MinSigLife <= 0 {
		return errors.New("parity: model, timeout, EDNS buffer, NX probe label, both probe addresses, probe timeout, " +
			"the time to judge signatures at and the minimum signature life are required (set them in the config)")
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

// sharedFate is lint rule L-20 on the providers' real addresses: two providers whose servers share an address or a
// prefix (/24 for IPv4, /48 for IPv6) fail together, whatever their names say. A risk: it never decides the verdict.
// AS numbers are not checked yet (RL-3).
func sharedFate(origin string, providers []Provider) []Finding {
	var out []Finding
	for i, a := range providers {
		for _, b := range providers[i+1:] {
			for _, x := range a.Addrs {
				for _, y := range b.Addrs {
					what := sharedPrefix(hostIP(x), hostIP(y))
					if hx, hy := hostOf(x), hostOf(y); what == "" && hostIP(x) == nil && strings.EqualFold(hx, hy) {
						what = "a host name" // red team 3, P3-8: the same server by name
					}
					if what != "" {
						out = append(out, Finding{Risk, "shared-fate", origin, "NS", b.Name, fmt.Sprintf("%s of %s "+
							"and %s of %s share %s: the two providers can fail together (lint L-20)", x, a.Name, y,
							b.Name, what)})
					}
				}
			}
		}
	}
	return out
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.TrimSuffix(addr, ".")
	}
	return strings.TrimSuffix(host, ".")
}

func hostIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(host)
}

// sharedPrefix says what two addresses share: "an address", "a /24 prefix" or "a /48 prefix", or "".
func sharedPrefix(x, y net.IP) string {
	switch {
	case x == nil || y == nil:
		return ""
	case x.Equal(y):
		return "an address"
	case x.To4() != nil && y.To4() != nil && x.Mask(net.CIDRMask(24, 32)).Equal(y.Mask(net.CIDRMask(24, 32))):
		return "a /24 prefix"
	case x.To4() == nil && y.To4() == nil && x.Mask(net.CIDRMask(48, 128)).Equal(y.Mask(net.CIDRMask(48, 128))):
		return "a /48 prefix"
	}
	return ""
}

// Interception is the probe address that answered and the protocols (udp, tcp) it answered over.
type Interception struct {
	Probe     string   `json:"probe"`
	Protocols []string `json:"protocols"`
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
	// Interception names the probe address that answered and the protocols it answered over, when Intercepted.
	Interception *Interception `json:"interception,omitempty"`
	Verdict      string        `json:"verdict"` // pass, fail or no_verdict
	Findings     []Finding     `json:"findings"`
	Gaps         []Gap         `json:"gaps"`
	// SignatureExpiry is, per provider, the earliest expiration (Unix seconds) of a valid RRSIG it served: the moment
	// its zone goes bogus if re-signing stops. Absent for a provider that served no valid signature.
	SignatureExpiry map[string]int64 `json:"signature_expiry,omitempty"`
	// Queries is, per server address, how many queries the run sent to it (the parent's servers included).
	Queries map[string]int `json:"queries"`
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
	rrs   []dns.RR     // the answered RRset as received, for signature checks; not part of the comparison
	sigs  []*dns.RRSIG // the RRSIGs over that RRset
	// denial holds the NSEC and NSEC3 records of a negative answer, and denialSigs their RRSIGs.
	denial     []dns.RR
	denialSigs []*dns.RRSIG
}

// run is the state of one Run that the checks share.
type runState struct {
	o          Options
	origin     string
	signed     bool                     // the zone file has an apex DNSKEY RRset: signatures are expected
	keys       map[string][]*dns.DNSKEY // per server address, its DNSKEY RRset
	keySet     map[string][]dns.RR      // per server address, the DNSKEY RRset as received, and its RRSIGs
	keySigs    map[string][]*dns.RRSIG
	denialType map[string]string // per provider, the denial it uses: NSEC or NSEC3
	keyAnswer  map[string]string // per server address, the DNSKEY answer's comparison key (TCP)
	ds         []*dns.DS         // the parent's DS RRset, asked once
	dsReason   string
	dsDone     bool
	noKeys     map[string]string // per server address, why it has none
	seen       map[string]bool   // signature findings already reported (one per provider, question and kind)
	secureCuts map[string]bool   // delegations with a DS in the zone file: their referrals need no denial
	started    time.Time
	queries    map[string]int       // per server address, queries sent
	last       map[string]time.Time // per server address, when the last query went out
	answered   map[string]bool      // per server address, whether it answered anything in this run
}

// query sends one question through the run's limits: the deadline, the per-server budget and pacing. A server that
// answered earlier in the run and then stops answering, or refuses, is labelled as possibly rate limiting: providers
// throttle bursts, and the gap should say so rather than look like a broken server.
func (ctx *runState) query(addr, transport string, q question) (answer, string) {
	o := ctx.o
	if o.Deadline > 0 && time.Since(ctx.started) >= o.Deadline {
		return answer{}, "not asked: the run reached its deadline (parity.deadline_seconds)"
	}
	if o.MaxQueries > 0 && ctx.queries[addr] >= o.MaxQueries {
		return answer{}, "not asked: the query budget for this server is spent (parity.max_queries_per_server)"
	}
	if wait := o.Pace - time.Since(ctx.last[addr]); o.Pace > 0 && wait > 0 {
		time.Sleep(wait)
	}
	ctx.last[addr] = time.Now()
	ctx.queries[addr]++
	a, reason := query(addr, transport, q, o.Timeout, o.EDNSBuffer, o.Observe)
	switch {
	case reason == "" || reason == truncatedUDP:
		ctx.answered[addr] = true
	case ctx.answered[addr] && (strings.HasPrefix(reason, "no answer") || reason == "rcode REFUSED"):
		reason += " (possibly rate limited: this server answered earlier in the run)"
	}
	return a, reason
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
	var targets []string
	for _, p := range providers {
		targets = append(targets, p.Addrs...)
	}
	rep.Findings = append(rep.Findings, sharedFate(z.Origin, providers)...)
	if c, protos := probe.FirstIntercepted(probe.Canaries(targets, o.Canary, o.Canary6), o.ProbeTimeout); c != "" {
		rep.Intercepted, rep.Verdict = true, "no_verdict"
		rep.Interception = &Interception{Probe: c, Protocols: protos}
		rep.Gaps = append(rep.Gaps, Gap{Reason: "the network path answers DNS for any address (probe " + c +
			"); no measurement over it can be trusted"})
		return rep, nil
	}
	qs := questions(z, o.NXProbe)
	rep.Questions = len(qs)
	ctx := &runState{o: o, origin: z.Origin, signed: len(z.At(z.Origin, "DNSKEY")) > 0, keys: map[string][]*dns.DNSKEY{},
		noKeys: map[string]string{}, seen: map[string]bool{}, keySet: map[string][]dns.RR{},
		keySigs: map[string][]*dns.RRSIG{}, denialType: map[string]string{}, keyAnswer: map[string]string{},
		secureCuts: map[string]bool{}, started: time.Now(), queries: map[string]int{}, last: map[string]time.Time{},
		answered: map[string]bool{}}
	for _, cut := range z.Delegations() {
		ctx.secureCuts[cut] = len(z.At(cut, "DS")) > 0
	}
	views := map[string]map[question]*answer{}
	for _, p := range providers {
		views[p.Name] = map[question]*answer{}
		for _, q := range qs {
			views[p.Name][q] = ask(ctx, p, q, &rep)
		}
		for _, addr := range p.Addrs {
			if _, served := ctx.keys[addr]; ctx.signed || served || len(o.Parent) > 0 {
				checkChain(ctx, p.Name, addr, &rep)
			}
		}
	}
	compareDenialTypes(ctx, providers, &rep)
	compareCDS(ctx, providers, &rep)
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
	rep.Queries = ctx.queries
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
			if r.Name == c && r.Type == "DS" {
				add(question{c, "DS", "record"}) // red team D1: the DS at a cut is this zone's own, signed data
				continue
			}
			add(question{c, "NS", "referral"}) // the NS and its glue; records below a cut are the child's business
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
func ask(ctx *runState, p Provider, q question, rep *Report) *answer {
	var got []answer
	for _, addr := range p.Addrs {
		for _, tr := range []string{"udp", "tcp"} {
			a, reason := ctx.query(addr, tr, q)
			if reason == truncatedUDP {
				continue // normal: the TCP answer for this address decides
			}
			if reason != "" {
				rep.Gaps = append(rep.Gaps, Gap{p.Name, addr, tr, q.name, q.typ, reason})
				continue
			}
			checkSignatures(ctx, p.Name, addr, tr, q, a, rep)
			checkDenial(ctx, p.Name, addr, tr, q, a, rep)
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
		if !sameTTLs(a.ttls, got[0].ttls) { // L15: authoritative servers serve the zone's TTL, never a countdown
			rep.Findings = append(rep.Findings, Finding{Fail, "inconsistent-servers", q.name, q.typ, p.Name,
				fmt.Sprintf("the provider's own servers or transports give the same data with different TTLs (%v, %v)",
					got[0].ttls, a.ttls)})
			break
		}
	}
	return &got[0]
}

const truncatedUDP = "truncated over UDP"

func query(addr, transport string, q question, timeout time.Duration, edns uint16, observe func(Exchange)) (answer, string) {
	m := new(dns.Msg)
	m.SetQuestion(q.name, rrtype(q.typ))
	m.RecursionDesired = false
	m.SetEdns0(edns, true)
	c := &dns.Client{Net: transport, Timeout: timeout}
	started := time.Now()
	r, _, err := c.Exchange(m, addr)
	if observe != nil {
		e := record(addr, transport, q, r, err)
		e.Started = started
		observe(e)
	}
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
		// Red team D3: a provider that answers for the delegated child with authority, or with data in the answer
		// section, serves its own copy of the child instead of delegating.
		if r.Authoritative || len(r.Answer) > 0 {
			return answer{class: "child-served"}, ""
		}
		var rdata []string
		targets := map[string]bool{}
		for _, rr := range r.Ns {
			if v, ok := rr.(*dns.NS); ok && strings.EqualFold(v.Hdr.Name, q.name) {
				t := strings.ToLower(v.Ns)
				targets[t] = true
				rdata = append(rdata, "NS "+t)
			}
		}
		if len(rdata) == 0 {
			return answer{}, "no referral where a zone cut is expected"
		}
		// Red team D2: glue for targets inside the delegated zone is part of the referral, and is compared too.
		for _, rr := range r.Extra {
			h := rr.Header()
			name := strings.ToLower(h.Name)
			if (h.Rrtype == dns.TypeA || h.Rrtype == dns.TypeAAAA) && targets[name] && dns.IsSubDomain(q.name, name) {
				rdata = append(rdata, dns.Type(h.Rrtype).String()+" "+name+" "+canonical(rr))
			}
		}
		sort.Strings(rdata)
		a := answer{class: "referral", rdata: rdata}
		a.denial, a.denialSigs = denialOf(r) // the no-DS proof of an insecure delegation; not part of the comparison
		return a, ""
	}
	if !r.Authoritative {
		return answer{}, "not authoritative (AA not set)"
	}
	if r.Rcode == dns.RcodeNameError {
		a := answer{class: "nxdomain"}
		a.denial, a.denialSigs = denialOf(r)
		return a, ""
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
		class := ""
		if h.Class != dns.ClassINET {
			class = "class=" + dns.Class(h.Class).String() + " " // red team D6: another class never compares equal
		}
		a.rdata = append(a.rdata, dns.Type(h.Rrtype).String()+" "+class+canonical(rr))
		a.ttls = append(a.ttls, h.Ttl)
		a.rrs = append(a.rrs, rr)
	}
	if len(a.rrs) > 0 {
		covered := a.rrs[0].Header().Rrtype
		for _, rr := range r.Answer {
			if s, ok := rr.(*dns.RRSIG); ok && strings.EqualFold(s.Hdr.Name, q.name) && s.TypeCovered == covered {
				a.sigs = append(a.sigs, s)
			}
		}
	}
	if len(a.rdata) == 0 {
		a.class = "nodata"
		a.denial, a.denialSigs = denialOf(r)
		return a, ""
	}
	a.class = "data"
	a.denial, a.denialSigs = denialOf(r) // a wildcard answer carries the proof that the name itself does not exist
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
		if a.class == "data" { // red team D5: the zone file has no data here
			rep.Findings = append(rep.Findings, Finding{Fail, "ent-has-data", q.name, q.typ, provider,
				fmt.Sprintf("the zone file has no data at this empty non-terminal; this provider answers %v", a.rdata)})
		}
	case "referral":
		want := expectedReferral(z, q.name)
		switch {
		case a.class == "child-served":
			rep.Findings = append(rep.Findings, Finding{Fail, "child-served", q.name, q.typ, provider,
				"the provider answers for the delegated child with authority or data instead of a referral: it serves " +
					"its own copy of the child zone"})
		case strings.Join(want, "\n") != strings.Join(a.rdata, "\n"):
			rep.Findings = append(rep.Findings, Finding{Fail, "referral-differs-zone", q.name, q.typ, provider,
				fmt.Sprintf("the zone file delegates with %v; this provider refers with %v", want, a.rdata)})
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

// expectedReferral is the zone file's referral at a cut: its NS targets and the glue for targets inside the
// delegated zone, in the form query() gives a referral.
func expectedReferral(z *zone.Zone, cut string) []string {
	var out []string
	for _, r := range z.At(cut, "NS") {
		t := strings.ToLower(r.RR().(*dns.NS).Ns)
		out = append(out, "NS "+t)
		if dns.IsSubDomain(cut, t) {
			for _, g := range append(z.At(t, "A"), z.At(t, "AAAA")...) {
				out = append(out, g.Type+" "+t+" "+canonical(g.RR()))
			}
		}
	}
	sort.Strings(out)
	return out
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

// concat is each TXT record's strings joined as a consumer joins them (RFC 7208 section 3.3: no separator), sorted.
// Red team D4: the spaces inside the strings are data and stay.
func concat(rdata []string) string {
	var parts []string
	for _, r := range rdata {
		rr, err := dns.NewRR(". 0 IN " + r)
		if t, ok := rr.(*dns.TXT); err == nil && ok {
			parts = append(parts, strings.Join(t.Txt, ""))
		} else {
			parts = append(parts, r) // not a TXT record as given: compared as is
		}
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

// record turns one exchange into its evidence form. The OPT pseudo-record is left out of the additional section.
func record(addr, transport string, q question, r *dns.Msg, err error) Exchange {
	e := Exchange{Time: time.Now().UTC().Format(time.RFC3339Nano), Server: addr, Transport: transport, Name: q.name,
		Type: q.typ}
	if err != nil {
		e.Error = err.Error()
		return e
	}
	e.Rcode, e.AA, e.TC = dns.RcodeToString[r.Rcode], r.Authoritative, r.Truncated
	for _, rr := range r.Answer {
		e.Answer = append(e.Answer, rr.String())
	}
	for _, rr := range r.Ns {
		e.Authority = append(e.Authority, rr.String())
	}
	for _, rr := range r.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			e.Additional = append(e.Additional, rr.String())
		}
	}
	return e
}
