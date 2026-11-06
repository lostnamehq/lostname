// Package lint checks a zone for what breaks or is lost when it moves (model section 3). The checks here need only
// the zone itself; checks against a target provider's capabilities come with provider data. Lint never uses the
// network (decision 0008).
package lint

import (
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/zone"
)

// Severity orders findings; a blocker fails lint, a risk fails it only with --strict.
type Severity string

const (
	Note    Severity = "note"
	Risk    Severity = "risk"
	Blocker Severity = "blocker"
)

func (s Severity) rank() int { return map[Severity]int{Note: 0, Risk: 1, Blocker: 2}[s] }

// Finding is one problem at one owner name.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Name     string   `json:"name"`
	Type     string   `json:"type,omitempty"`
	Message  string   `json:"message"`
	Ref      string   `json:"ref"`
}

type check func(z *zone.Zone) []Finding

var checks = []check{l00, l07, l08, l09, l13, l14, l15, l18, l21}

// L-00 (M8): the input must be a zone at all: records, exactly one SOA at the apex and an apex NS set. Without them
// every other check passes vacuously, and an exit built on the input would serve nothing.
func l00(z *zone.Zone) []Finding {
	if len(z.Records) == 0 {
		return []Finding{{"L-00", Blocker, z.Origin, "", "the zone has no records", "RFC 1035 5.2"}}
	}
	var out []Finding
	if n := len(z.At(z.Origin, "SOA")); n != 1 {
		out = append(out, Finding{"L-00", Blocker, z.Origin, "SOA",
			"the apex has " + strconv.Itoa(n) + " SOA records; a zone has exactly one", "RFC 1035 5.2"})
	}
	if len(z.At(z.Origin, "NS")) == 0 {
		out = append(out, Finding{"L-00", Blocker, z.Origin, "NS", "the apex has no NS records", "RFC 1035 5.2"})
	}
	return out
}

// Signing algorithms per RFC 8624 section 3.1: "MUST NOT" for signing, and "NOT RECOMMENDED" for signing.
var (
	algMustNot        = map[uint8]string{1: "RSAMD5", 3: "DSA", 6: "DSA-NSEC3-SHA1", 12: "ECC-GOST"}
	algNotRecommended = map[uint8]string{5: "RSASHA1", 7: "RSASHA1-NSEC3-SHA1", 10: "RSASHA512"}
)

// L-21 (RL-2): DNSKEY algorithms that must not or should not be used for signing, and DS records with a SHA-1
// digest, which RFC 8624 section 3.3 says must not be used for delegations. A move is the moment to fix them,
// because the new signer may not support them at all.
func l21(z *zone.Zone) []Finding {
	var out []Finding
	for _, r := range z.Records {
		switch v := r.RR().(type) {
		case *dns.DNSKEY:
			if name, bad := algMustNot[v.Algorithm]; bad {
				out = append(out, Finding{"L-21", Risk, r.Name, "DNSKEY",
					"key tag " + strconv.Itoa(int(v.KeyTag())) + " uses " + name + ", which must not be used for signing", "RFC 8624 3.1"})
			} else if name, weak := algNotRecommended[v.Algorithm]; weak {
				out = append(out, Finding{"L-21", Note, r.Name, "DNSKEY",
					"key tag " + strconv.Itoa(int(v.KeyTag())) + " uses " + name + ", not recommended for signing", "RFC 8624 3.1"})
			}
		case *dns.DS:
			if v.DigestType == dns.SHA1 {
				out = append(out, Finding{"L-21", Risk, r.Name, "DS",
					"DS for key tag " + strconv.Itoa(int(v.KeyTag)) + " uses a SHA-1 digest, which must not be used for delegations",
					"RFC 8624 3.3"})
			}
		}
	}
	return out
}

// Run applies every zone-only check and returns the findings in a stable order.
func Run(z *zone.Zone) []Finding {
	var out []Finding
	for _, c := range checks {
		out = append(out, c(z)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Message < b.Message
	})
	return out
}

// Fails reports whether the findings fail lint: any blocker, or any risk when strict.
func Fails(fs []Finding, strict bool) bool {
	for _, f := range fs {
		if f.Severity == Blocker || (strict && f.Severity.rank() >= Risk.rank()) {
			return true
		}
	}
	return false
}

// L-07: CAA issue/issuewild without accounturi (RFC 8657): any account at that CA can issue, including one that
// is lost with the old provider.
func l07(z *zone.Zone) []Finding {
	var out []Finding
	for _, r := range z.Records {
		caa, ok := r.RR().(*dns.CAA)
		if !ok || (caa.Tag != "issue" && caa.Tag != "issuewild") || caa.Value == ";" {
			continue
		}
		if !strings.Contains(caa.Value, "accounturi=") {
			out = append(out, Finding{"L-07", Note, r.Name, "CAA",
				"CAA " + caa.Tag + " \"" + caa.Value + "\" has no accounturi: any account at that CA may issue", "RFC 8657"})
		}
	}
	return out
}

// L-08: CNAME at the apex, or a CNAME next to other data (only DNSSEC records may share its owner).
func l08(z *zone.Zone) []Finding {
	var out []Finding
	byName := map[string][]string{}
	for _, r := range z.Records {
		byName[r.Name] = append(byName[r.Name], r.Type)
	}
	for name, types := range byName {
		has, others := false, []string{}
		for _, t := range types {
			switch t {
			case "CNAME":
				has = true
			case "RRSIG", "NSEC", "NSEC3":
			default:
				others = append(others, t)
			}
		}
		if !has {
			continue
		}
		if name == z.Origin {
			out = append(out, Finding{"L-08", Blocker, name, "CNAME", "CNAME at the zone apex", "RFC 1034 3.6.2"})
		} else if len(others) > 0 {
			sort.Strings(others)
			out = append(out, Finding{"L-08", Blocker, name, "CNAME",
				"CNAME next to other data (" + strings.Join(uniq(others), ", ") + ")", "RFC 1034 3.6.2, RFC 2181 10.1"})
		}
	}
	return out
}

// L-09: in-domain delegation whose NS targets lie inside the delegated zone, without glue addresses.
func l09(z *zone.Zone) []Finding {
	var out []Finding
	for _, cut := range z.Delegations() {
		for _, r := range z.At(cut, "NS") {
			target := strings.ToLower(r.RR().(*dns.NS).Ns)
			if !dns.IsSubDomain(cut, target) {
				continue
			}
			if len(z.At(target, "A"))+len(z.At(target, "AAAA")) == 0 {
				out = append(out, Finding{"L-09", Blocker, cut, "NS",
					"delegation to " + target + " needs glue, and the zone has no A or AAAA for it", "RFC 9471 3.1"})
			}
		}
	}
	return out
}

// L-13: SVCB/HTTPS in AliasMode (SvcPriority 0); providers differ in support, so check the target.
func l13(z *zone.Zone) []Finding {
	var out []Finding
	for _, r := range z.Records {
		var prio uint16
		switch v := r.RR().(type) {
		case *dns.SVCB:
			prio = v.Priority
		case *dns.HTTPS:
			prio = v.Priority
		default:
			continue
		}
		if prio == 0 {
			out = append(out, Finding{"L-13", Risk, r.Name, r.Type,
				r.Type + " in AliasMode (SvcPriority 0): check the target provider supports it", "RFC 9460"})
		}
	}
	return out
}

var knownCAATags = map[string]bool{"issue": true, "issuewild": true, "iodef": true, "issuemail": true, "issuevmc": true,
	"contactemail": true, "contactphone": true}

// L-14: CAA with the critical flag and a tag a CA may not know: a conforming CA must then refuse to issue.
func l14(z *zone.Zone) []Finding {
	var out []Finding
	for _, r := range z.Records {
		caa, ok := r.RR().(*dns.CAA)
		if ok && caa.Flag&128 != 0 && !knownCAATags[strings.ToLower(caa.Tag)] {
			out = append(out, Finding{"L-14", Risk, r.Name, "CAA",
				"critical CAA tag \"" + caa.Tag + "\" is not a registered tag: a CA must refuse to issue", "RFC 8659 4.1"})
		}
	}
	return out
}

// L-15: fewer than two NS at the apex.
func l15(z *zone.Zone) []Finding {
	if n := len(z.At(z.Origin, "NS")); n < 2 {
		return []Finding{{"L-15", Risk, z.Origin, "NS", "the apex has fewer than two NS records", "RFC 1034 4.1"}}
	}
	return nil
}

// L-18: DNAME present, or MX/NS targets that are aliases (CNAME) in this zone.
func l18(z *zone.Zone) []Finding {
	var out []Finding
	isAlias := map[string]bool{}
	for _, r := range z.Records {
		if r.Type == "CNAME" {
			isAlias[r.Name] = true
		}
		if r.Type == "DNAME" {
			out = append(out, Finding{"L-18", Risk, r.Name, "DNAME", "DNAME present: check the target provider supports it",
				"RFC 6672"})
		}
	}
	for _, r := range z.Records {
		var target string
		switch v := r.RR().(type) {
		case *dns.MX:
			target = v.Mx
		case *dns.NS:
			target = v.Ns
		default:
			continue
		}
		if isAlias[strings.ToLower(target)] {
			out = append(out, Finding{"L-18", Risk, r.Name, r.Type,
				r.Type + " points at " + strings.ToLower(target) + ", which is a CNAME", "RFC 2181 10.3"})
		}
	}
	return out
}

func uniq(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Apply removes disabled rules and applies severity overrides from the config (lint.disabled_rules, lint.severity).
func Apply(fs []Finding, disabled []string, severity map[string]string) []Finding {
	off := map[string]bool{}
	for _, r := range disabled {
		off[r] = true
	}
	out := []Finding{}
	for _, f := range fs {
		if off[f.Rule] {
			continue
		}
		if s, ok := severity[f.Rule]; ok {
			f.Severity = Severity(s)
		}
		out = append(out, f)
	}
	return out
}
