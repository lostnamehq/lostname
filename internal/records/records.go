// Package records reads the DNS and mail records of a zone (decision 0006: the shared engine with VDHome
// trust-checks; decision 0011: offline, from the owner's own zone): SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI and TLSA.
// It reads only names the zone contains. It never guesses DKIM selectors and makes no network calls.
package records

import (
	"encoding/base64"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"lostname.be/lostname/internal/zone"
)

// Severity, as lint uses it: a blocker means receivers act as if the record were not there.
type Severity string

const (
	Blocker Severity = "blocker"
	Risk    Severity = "risk"
	Note    Severity = "note"
)

// Finding is one problem with a mail record. Message never quotes record data beyond the owner name: a record can
// carry addresses and keys.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Message  string   `json:"message"`
	Ref      string   `json:"ref"`
}

// Posture is what the zone publishes for mail, as a receiving or sending server would read it.
type Posture struct {
	Domain string   `json:"domain"`
	MX     []string `json:"mx"`
	SPF    *SPF     `json:"spf,omitempty"`
	DMARC  *DMARC   `json:"dmarc,omitempty"`
	DKIM   []DKIM   `json:"dkim"`
	MTASTS *MTASTS  `json:"mta_sts,omitempty"`
	TLSRPT *TLSRPT  `json:"tls_rpt,omitempty"`
	BIMI   []BIMI   `json:"bimi"`
	TLSA   []TLSA   `json:"tlsa"`
}

// SPF is the domain's one SPF record (RFC 7208).
type SPF struct {
	All      string   `json:"all,omitempty"`      // the qualifier of "all": +, -, ~ or ?; empty without one
	Includes []string `json:"includes,omitempty"` // include: targets, in order
	Redirect string   `json:"redirect,omitempty"`
}

// DMARC is the domain's one DMARC record (RFC 9989).
type DMARC struct {
	Policy    string `json:"policy,omitempty"`    // p
	SubPolicy string `json:"subpolicy,omitempty"` // sp
	Reports   bool   `json:"reports"`             // rua is set
}

// DKIM is one selector the zone publishes (RFC 6376 section 3.6).
type DKIM struct {
	Selector string `json:"selector"`
	KeyType  string `json:"key_type,omitempty"` // k, rsa by default
	Revoked  bool   `json:"revoked"`            // an empty p= (RFC 6376 section 3.6.1)
	Alias    string `json:"alias,omitempty"`    // the CNAME target, when the selector is delegated (to a mail provider)
}

// MTASTS is the domain's MTA-STS record (RFC 8461 section 3.1); the policy file itself is not fetched.
type MTASTS struct {
	ID string `json:"id"`
}

// TLSRPT is the domain's SMTP TLS reporting record (RFC 8460 section 3).
type TLSRPT struct {
	Destinations int `json:"destinations"`
}

// BIMI is one BIMI record (published as a draft, not an RFC: read, not judged).
type BIMI struct {
	Selector string `json:"selector"`
}

// TLSA is one DANE TLSA record for a mail host (RFC 6698, RFC 7672).
type TLSA struct {
	Name         string `json:"name"`
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
}

// MXHosts returns the zone's MX targets (lower case), whose _25._tcp names hold mail's TLSA.
func MXHosts(z *zone.Zone) map[string]bool {
	out := map[string]bool{}
	for _, r := range z.At(z.Origin, "MX") {
		out[strings.ToLower(r.RR().(*dns.MX).Mx)] = true
	}
	return out
}

// txt returns the TXT strings at name, each record's strings joined (RFC 7208 section 3.3).
func txt(z *zone.Zone, name string) []string {
	var out []string
	for _, r := range z.At(name, "TXT") {
		out = append(out, strings.Join(r.RR().(*dns.TXT).Txt, ""))
	}
	return out
}

// withPrefix returns the strings that start with the version tag, case-insensitively, followed by end or sep.
func withPrefix(ss []string, tag string, sep string) []string {
	var out []string
	for _, s := range ss {
		l := strings.ToLower(s)
		if strings.HasPrefix(l, tag) && (len(l) == len(tag) || strings.ContainsAny(l[len(tag):len(tag)+1], sep)) {
			out = append(out, s)
		}
	}
	return out
}

// tags parses a tag=value list separated by ';' (DMARC, DKIM, MTA-STS, TLS-RPT, BIMI). Names are lower case.
func tags(s string) (map[string]string, []string, bool) { return tagList(s, false) }

// tagList parses a tag list; with exact, tag names keep their case (DKIM, RFC 6376 section 3.2).
func tagList(s string, exact bool) (map[string]string, []string, bool) {
	m := map[string]string{}
	var order []string
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !exact {
			k = strings.ToLower(k)
		}
		if !ok || k == "" {
			return nil, nil, false
		}
		if _, dup := m[k]; dup {
			return nil, nil, false
		}
		m[k] = strings.TrimSpace(v)
		order = append(order, k)
	}
	return m, order, true
}

// Read returns the mail posture of z and the findings about its mail records.
func Read(z *zone.Zone) (Posture, []Finding) {
	p := Posture{Domain: z.Origin, DKIM: []DKIM{}, BIMI: []BIMI{}, TLSA: []TLSA{}, MX: []string{}}
	var fs []Finding
	for _, r := range z.At(z.Origin, "MX") {
		p.MX = append(p.MX, strings.ToLower(r.RR().(*dns.MX).Mx))
	}
	sort.Strings(p.MX)
	p.SPF, fs = readSPF(z, fs)
	p.DMARC, fs = readDMARC(z, fs)
	p.DKIM, fs = readDKIM(z, fs)
	p.MTASTS, fs = readMTASTS(z, fs)
	p.TLSRPT, fs = readTLSRPT(z, fs)
	p.BIMI = readBIMI(z)
	p.TLSA, fs = readTLSA(z, fs)
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Rule != fs[j].Rule {
			return fs[i].Rule < fs[j].Rule
		}
		return zone.CanonicalLess(fs[i].Name, fs[j].Name)
	})
	return p, fs
}

// spfModName is a modifier name (RFC 7208 section 12: ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )).
var spfModName = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)

// dkimSelector is a selector: dot-separated labels that start with a letter or digit (RFC 6376 3.1, RFC 5321).
var dkimSelector = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*$`)

var spfDomain = regexp.MustCompile(`^[A-Za-z0-9_%{}.+-]+$`) // a domain-spec, macros allowed (RFC 7208 section 7)

// readSPF reads the SPF record at the apex (RFC 7208): one record at most (section 4.5), terms that parse
// (sections 5 and 6), and the "all" it ends with.
func readSPF(z *zone.Zone, fs []Finding) (*SPF, []Finding) {
	recs := withPrefix(txt(z, z.Origin), "v=spf1", " ")
	switch {
	case len(recs) == 0:
		return nil, fs
	case len(recs) > 1:
		return nil, append(fs, Finding{"M-01", Blocker, z.Origin, "TXT", strconv.Itoa(len(recs)) +
			" SPF records: receivers treat this as a permanent error and apply none of them", "RFC 7208 4.5"})
	}
	s := &SPF{}
	terms := strings.Fields(recs[0])[1:]
	seenMod := map[string]bool{}
	for _, t := range terms {
		lt := strings.ToLower(t)
		if name, val, ok := strings.Cut(lt, "="); ok && !strings.ContainsAny(name, ":/") {
			// Red team 3, L3-2 and L3-3: only redirect and exp take a domain, and each at most once (section 6);
			// any other modifier is a name and a macro-string, which may be empty (section 12).
			if !spfModName.MatchString(name) {
				return nil, append(fs, spfSyntax(z, "a modifier name is not valid"))
			}
			switch name {
			case "redirect", "exp":
				if seenMod[name] {
					return nil, append(fs, spfSyntax(z, "the redirect or exp modifier appears twice"))
				}
				seenMod[name] = true
				if !spfDomain.MatchString(val) {
					return nil, append(fs, spfSyntax(z, "the redirect or exp modifier has no valid domain"))
				}
				if name == "redirect" {
					s.Redirect = val
				}
			}
			continue
		}
		q := "+"
		if strings.ContainsAny(lt[:1], "+-~?") {
			q, lt = lt[:1], lt[1:]
		}
		mech, arg, _ := strings.Cut(lt, ":")
		if i := strings.Index(mech, "/"); i >= 0 && arg == "" && (mech[:i] == "a" || mech[:i] == "mx") {
			mech = mech[:i] // a/24 and mx/24 carry a prefix length without a domain; no other mechanism does
		}
		switch mech {
		case "all":
			if arg != "" {
				return nil, append(fs, spfSyntax(z, "\"all\" takes no argument"))
			}
			s.All = q
		case "include", "exists":
			if !spfDomain.MatchString(arg) {
				return nil, append(fs, spfSyntax(z, "\""+mech+"\" needs a domain"))
			}
			if mech == "include" {
				s.Includes = append(s.Includes, arg)
			}
		case "a", "mx":
		case "ptr":
			fs = append(fs, Finding{"M-04", Note, z.Origin, "TXT", "the SPF record uses \"ptr\": it is slow and " +
				"unreliable, and receivers may skip it", "RFC 7208 5.5"})
		case "ip4":
			if !ip4Network(arg) {
				return nil, append(fs, spfSyntax(z, "an ip4 mechanism has no valid address or prefix length"))
			}
		case "ip6":
			if !ip6Network(arg) {
				return nil, append(fs, spfSyntax(z, "an ip6 mechanism has no valid address or prefix length"))
			}
		default:
			// Red team 3, L3-1: the term itself is record data; the message names it by position only.
			return nil, append(fs, spfSyntax(z, "an unknown mechanism"))
		}
	}
	if s.All == "+" {
		fs = append(fs, Finding{"M-03", Risk, z.Origin, "TXT", "the SPF record ends in \"+all\": every server " +
			"may send mail for this domain", "RFC 7208 5.1"})
	}
	return s, fs
}

func spfSyntax(z *zone.Zone, why string) Finding {
	return Finding{"M-02", Blocker, z.Origin, "TXT", "the SPF record does not parse (" + why + "): receivers " +
		"treat it as a permanent error", "RFC 7208 4.6"}
}

// readDMARC reads _dmarc at the apex (RFC 9989): one record at most, v=DMARC1 first, and a policy.
func readDMARC(z *zone.Zone, fs []Finding) (*DMARC, []Finding) {
	name := "_dmarc." + z.Origin
	recs := withPrefix(txt(z, name), "v=dmarc1", "; ")
	switch {
	case len(recs) == 0:
		return nil, fs
	case len(recs) > 1:
		return nil, append(fs, Finding{"M-05", Blocker, name, "TXT", strconv.Itoa(len(recs)) +
			" DMARC records: receivers apply none of them", "RFC 9989"})
	}
	m, order, ok := tags(recs[0])
	if !ok || len(order) == 0 || order[0] != "v" {
		return nil, append(fs, Finding{"M-06", Blocker, name, "TXT", "the DMARC record does not parse as a tag list " +
			"starting with v=DMARC1: receivers ignore it", "RFC 9989"})
	}
	d := &DMARC{Policy: strings.ToLower(m["p"]), SubPolicy: strings.ToLower(m["sp"]), Reports: m["rua"] != ""}
	valid := map[string]bool{"none": true, "quarantine": true, "reject": true}
	switch {
	case d.Policy == "none":
		fs = append(fs, Finding{"M-07", Note, name, "TXT", "the DMARC policy is p=none: receivers report, but " +
			"take no action on mail that fails", "RFC 9989 4.7"})
	case d.Policy == "":
		fs = append(fs, Finding{"M-07", Note, name, "TXT", "the DMARC record has no p tag, so receivers treat it " +
			"as p=none: they report, but take no action on mail that fails", "RFC 9989 4.7"})
	case !valid[d.Policy]:
		fs = append(fs, Finding{"M-06", Risk, name, "TXT", "the DMARC p tag is not none, quarantine or reject: " +
			"receivers discard it and apply p=none", "RFC 9989 4.8"})
	}
	if d.SubPolicy != "" && !valid[d.SubPolicy] {
		fs = append(fs, Finding{"M-06", Risk, name, "TXT", "the DMARC sp tag is not none, quarantine or reject: " +
			"receivers discard it, and subdomains get the p policy", "RFC 9989 4.8"})
	}
	return d, fs
}

// readDKIM reads every selector the zone publishes under _domainkey (RFC 6376 section 3.6.2.1). It does not guess
// selector names: what is not in the zone is not read.
func readDKIM(z *zone.Zone, fs []Finding) ([]DKIM, []Finding) {
	out := []DKIM{}
	base := "._domainkey." + z.Origin
	seen := map[string]bool{}
	for _, r := range z.Records {
		if (r.Type != "TXT" && r.Type != "CNAME") || !strings.HasSuffix(r.Name, base) || seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		sel := strings.TrimSuffix(r.Name, base)
		if !dkimSelector.MatchString(sel) {
			continue // red team 3, L3-8: _adsp and other underscore names are not selectors (RFC 6376 3.1)
		}
		if r.Type == "CNAME" {
			out = append(out, DKIM{Selector: sel, Alias: strings.ToLower(r.RR().(*dns.CNAME).Target)})
			continue
		}
		recs := txt(z, r.Name)
		if len(recs) != 1 {
			fs = append(fs, Finding{"M-08", Risk, r.Name, "TXT", strconv.Itoa(len(recs)) + " TXT records at a DKIM " +
				"selector: verifiers expect one key record", "RFC 6376 3.6.2.2"})
			continue
		}
		m, order, ok := tagList(recs[0], true)
		k := DKIM{Selector: sel}
		if ok {
			k.KeyType = strings.ToLower(m["k"])
		}
		if k.KeyType == "" {
			k.KeyType = "rsa"
		}
		key, hasP := m["p"]
		key = strings.Join(strings.Fields(key), "")
		_, err := base64.StdEncoding.DecodeString(key)
		switch {
		case !ok || !hasP || (m["v"] != "" && (order[0] != "v" || m["v"] != "DKIM1")):
			fs = append(fs, Finding{"M-08", Risk, r.Name, "TXT", "the DKIM key record does not parse (a tag list " +
				"with p=, and v=DKIM1 first when present): verifiers fail every signature with this selector",
				"RFC 6376 3.6.1"})
		case key == "":
			k.Revoked = true
		case err != nil:
			fs = append(fs, Finding{"M-08", Risk, r.Name, "TXT", "the DKIM key (p=) is not valid base64: verifiers " +
				"fail every signature with this selector", "RFC 6376 3.6.1"})
		}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Selector < out[j].Selector })
	return out, fs
}

var stsID = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)

// readMTASTS reads _mta-sts at the apex (RFC 8461 section 3.1): one record, v=STSv1 first, an id of 1 to 32
// letters and digits. More than one record means senders act as if there were none.
func readMTASTS(z *zone.Zone, fs []Finding) (*MTASTS, []Finding) {
	name := "_mta-sts." + z.Origin
	recs := withPrefix(txt(z, name), "v=stsv1", "; ")
	switch {
	case len(recs) == 0:
		return nil, fs
	case len(recs) > 1:
		return nil, append(fs, Finding{"M-09", Risk, name, "TXT", strconv.Itoa(len(recs)) + " MTA-STS records: " +
			"senders act as if the domain had no MTA-STS policy", "RFC 8461 3.1"})
	}
	m, order, ok := tags(recs[0])
	if !ok || len(order) == 0 || order[0] != "v" || !stsID.MatchString(m["id"]) {
		return nil, append(fs, Finding{"M-09", Risk, name, "TXT", "the MTA-STS record does not parse (v=STSv1 first, " +
			"an id of 1 to 32 letters and digits): senders ignore the policy", "RFC 8461 3.1"})
	}
	return &MTASTS{ID: m["id"]}, fs
}

// readTLSRPT reads _smtp._tls at the apex (RFC 8460 section 3): one record, v=TLSRPTv1 first, rua with mailto: or
// https: destinations.
func readTLSRPT(z *zone.Zone, fs []Finding) (*TLSRPT, []Finding) {
	name := "_smtp._tls." + z.Origin
	recs := withPrefix(txt(z, name), "v=tlsrptv1", "; ")
	switch {
	case len(recs) == 0:
		return nil, fs
	case len(recs) > 1:
		return nil, append(fs, Finding{"M-10", Risk, name, "TXT", strconv.Itoa(len(recs)) + " TLS-RPT records: " +
			"senders send no reports", "RFC 8460 3"})
	}
	m, order, ok := tags(recs[0])
	bad := !ok || len(order) == 0 || order[0] != "v" || m["rua"] == ""
	n := 0
	if !bad {
		for _, d := range strings.Split(m["rua"], ",") {
			d = strings.ToLower(strings.TrimSpace(d))
			if !strings.HasPrefix(d, "mailto:") && !strings.HasPrefix(d, "https:") {
				bad = true
			}
			n++
		}
	}
	if bad {
		return nil, append(fs, Finding{"M-10", Risk, name, "TXT", "the TLS-RPT record does not parse (v=TLSRPTv1 " +
			"first, rua with mailto: or https: destinations): senders send no reports", "RFC 8460 3"})
	}
	return &TLSRPT{Destinations: n}, fs
}

// readBIMI lists the BIMI selectors the zone publishes; BIMI is a draft, so it is read, not judged.
func readBIMI(z *zone.Zone) []BIMI {
	out := []BIMI{}
	base := "._bimi." + z.Origin
	for _, r := range z.Records {
		if r.Type == "TXT" && strings.HasSuffix(r.Name, base) && len(withPrefix(txt(z, r.Name), "v=bimi1", "; ")) > 0 {
			sel := strings.TrimSuffix(r.Name, base)
			if len(out) == 0 || out[len(out)-1].Selector != sel {
				out = append(out, BIMI{Selector: sel})
			}
		}
	}
	return out
}

// readTLSA reads the TLSA records for SMTP (owner _25._tcp.<host>, RFC 7672 section 2.2) and judges their
// parameters: usages PKIX-TA (0) and PKIX-EE (1) are not for SMTP (RFC 7672 section 3.1.3).
func readTLSA(z *zone.Zone, fs []Finding) ([]TLSA, []Finding) {
	out := []TLSA{}
	mx := MXHosts(z)
	for _, r := range z.Records {
		// Red team 3, L3-11: SMTP DANE looks up TLSA at the MX host's own name (RFC 7672 2.2); elsewhere it is not
		// mail's TLSA.
		if r.Type != "TLSA" || !strings.HasPrefix(r.Name, "_25._tcp.") || !mx[strings.TrimPrefix(r.Name, "_25._tcp.")] {
			continue
		}
		t := r.RR().(*dns.TLSA)
		out = append(out, TLSA{Name: r.Name, Usage: t.Usage, Selector: t.Selector, MatchingType: t.MatchingType})
		switch {
		case t.Usage > 3 || t.Selector > 1 || t.MatchingType > 2:
			fs = append(fs, Finding{"M-11", Risk, r.Name, "TLSA", "a TLSA record with a usage, selector or matching " +
				"type outside the defined values: DANE senders cannot use it", "RFC 6698 2.1"})
		case t.Usage < 2:
			fs = append(fs, Finding{"M-11", Note, r.Name, "TLSA", "a TLSA record with usage " +
				strconv.Itoa(int(t.Usage)) + " (PKIX): SMTP senders use only DANE-TA (2) and DANE-EE (3)", "RFC 7672 3.1.3"})
		}
	}
	return out, fs
}

// ip4Network checks an ip4 argument: a dotted quad of 0 to 255 and an optional /0 to /32 (RFC 7208 5.6). Bytes and
// digits only: this package imports no network package.
func ip4Network(s string) bool {
	addr, prefix, hasPrefix := strings.Cut(s, "/")
	if hasPrefix && !prefixLen(prefix, 32) {
		return false
	}
	parts := strings.Split(addr, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 || len(p) == 0 || len(p) > 3 || p[0] == '+' {
			return false
		}
	}
	return true
}

// ip6Network checks an ip6 argument: an IPv6 address in RFC 4291 text form, optionally ending in a dotted quad, and
// an optional /0 to /128 (RFC 7208 5.6).
func ip6Network(s string) bool {
	addr, prefix, hasPrefix := strings.Cut(s, "/")
	if hasPrefix && !prefixLen(prefix, 128) {
		return false
	}
	if strings.Count(addr, "::") > 1 || addr == "" {
		return false
	}
	groups, max := 0, 8
	if i := strings.LastIndex(addr, ":"); i >= 0 && strings.Contains(addr[i+1:], ".") {
		if !ip4Network(addr[i+1:]) {
			return false
		}
		addr, max = addr[:i+1], 6
		if !strings.HasSuffix(addr, "::") {
			addr = strings.TrimSuffix(addr, ":")
		}
	}
	compressed := strings.Contains(addr, "::")
	for _, side := range strings.Split(addr, "::") {
		if side == "" {
			continue
		}
		for _, g := range strings.Split(side, ":") {
			if len(g) == 0 || len(g) > 4 || strings.Trim(g, "0123456789abcdefABCDEF") != "" {
				return false
			}
			groups++
		}
	}
	return (compressed && groups < max) || (!compressed && groups == max)
}

func prefixLen(s string, max int) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= max && len(s) > 0 && s[0] != '+' && s[0] != '-'
}
