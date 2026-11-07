package parity

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/zone"
)

// denialOf returns the NSEC and NSEC3 records in a negative answer's authority section, and their RRSIGs.
func denialOf(r *dns.Msg) ([]dns.RR, []*dns.RRSIG) {
	var recs []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range r.Ns {
		switch v := rr.(type) {
		case *dns.NSEC, *dns.NSEC3:
			recs = append(recs, rr)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC || v.TypeCovered == dns.TypeNSEC3 {
				sigs = append(sigs, v)
			}
		}
	}
	return recs, sigs
}

// checkDenial judges the authenticated denial in one server's negative answer (model section 4, "Denial"): the NSEC
// or NSEC3 records must be signed by the server's keys and must prove the answer, NODATA or NXDOMAIN, including the
// absence of a wildcard (RFC 4035 section 3.1.3, RFC 5155 section 7.2). Where the zone file is signed, a negative
// answer without them fails. Referrals are judged by checkReferralDenial, opt-out included.
func checkDenial(ctx *runState, provider, addr, transport string, q question, a answer, rep *Report) {
	if a.class == "referral" {
		checkReferralDenial(ctx, provider, addr, transport, q, a, rep)
		return
	}
	if a.class != "nodata" && a.class != "nxdomain" {
		return
	}
	if len(a.denial) == 0 {
		if ctx.signed {
			ctx.finding(rep, Fail, "denial-missing", q, provider, fmt.Sprintf("the zone is signed, but %s answered %s "+
				"without NSEC or NSEC3: validators cannot accept the answer", addr, a.class))
		}
		return
	}
	typ := dns.TypeToString[a.denial[0].Header().Rrtype]
	if ctx.denialType[provider] == "" {
		ctx.denialType[provider] = typ
	}
	if !denialSigned(ctx, provider, addr, transport, q, a, rep) {
		return
	}
	nx := a.class == "nxdomain"
	var proven bool
	if typ == "NSEC" {
		proven = nsecProves(q.name, rrtype(q.typ), nx, ctx.origin, a.denial)
	} else {
		proven = nsec3Proves(q.name, rrtype(q.typ), nx, ctx.origin, a.denial)
	}
	if !proven {
		ctx.finding(rep, Fail, "denial-invalid", q, provider, fmt.Sprintf("the %s records from %s do not prove the "+
			"%s answer", typ, addr, a.class))
	}
}

// denialSigned checks that every denial record in a carries a valid signature by the server's keys; it reports a
// gap (no keys) or a finding and returns false otherwise.
func denialSigned(ctx *runState, provider, addr, transport string, q question, a answer, rep *Report) bool {
	keys, reason := ctx.dnskeys(addr)
	if reason != "" {
		rep.Gaps = append(rep.Gaps, Gap{provider, addr, transport, q.name, q.typ,
			"denial records returned, but no DNSKEY RRset to check them against: " + reason})
		return false
	}
	now := ctx.o.Now.Unix()
	for _, rr := range a.denial {
		owner, t := rr.Header().Name, rr.Header().Rrtype
		ok := false
		for _, s := range a.denialSigs {
			if strings.EqualFold(s.Hdr.Name, owner) && s.TypeCovered == t {
				if kind, _ := judge(s, keys, []dns.RR{rr}, now, false); kind == "" {
					ok = true
				}
			}
		}
		if !ok {
			ctx.finding(rep, Fail, "denial-invalid", q, provider, fmt.Sprintf("the %s at %s from %s has no valid "+
				"signature", dns.TypeToString[t], owner, addr))
			return false
		}
	}
	return true
}

// checkReferralDenial judges the no-DS proof in a referral to an insecure delegation of a signed zone (RFC 4035
// section 3.1.4.1, RFC 5155 section 7.2.7): without it a validator cannot tell an insecure child from a stripped DS,
// and treats the child as bogus. The proof is an NSEC at the cut with NS and without DS and SOA, an NSEC3 that
// matches the cut likewise, or, under NSEC3 opt-out, the closest provable encloser and an opt-out NSEC3 covering the
// next closer name. A delegation with a DS in the zone file is secure; its DS is asked as a record of its own.
func checkReferralDenial(ctx *runState, provider, addr, transport string, q question, a answer, rep *Report) {
	if !ctx.signed || ctx.secureCuts[q.name] {
		return
	}
	if len(a.denial) == 0 {
		ctx.finding(rep, Fail, "referral-denial-missing", q, provider, fmt.Sprintf("%s refers %s without proving "+
			"that it has no DS: validators cannot tell an insecure delegation from a stripped DS", addr, q.name))
		return
	}
	if !denialSigned(ctx, provider, addr, transport, q, a, rep) {
		return
	}
	if !noDSProven(q.name, ctx.origin, a.denial) {
		ctx.finding(rep, Fail, "denial-invalid", q, provider, fmt.Sprintf("the denial records in the referral from "+
			"%s do not prove that %s has no DS", addr, q.name))
	}
}

// inChain reports whether n is an NSEC3 of the zone's own chain: its owner is one hash label (32 base32hex
// characters for SHA-1) directly under the origin (RFC 5155 section 3). miekg's Match and Cover compare only the
// first label, and a signature check only that the signer is a suffix, so an NSEC3 owned anywhere else in the zone
// would otherwise prove things (red team 3, P3-5).
func inChain(n *dns.NSEC3, origin string) bool {
	label, rest, ok := strings.Cut(n.Hdr.Name, ".")
	return ok && len(label) == 32 && strings.EqualFold(rest, origin)
}

// noDSProven reports whether recs prove that the delegation cut has no DS.
func noDSProven(cut, origin string, recs []dns.RR) bool {
	insecure := func(bitmap []uint16) bool {
		return hasType(bitmap, dns.TypeNS) && !hasType(bitmap, dns.TypeDS) && !hasType(bitmap, dns.TypeSOA)
	}
	var n3 []*dns.NSEC3
	for _, rr := range recs {
		switch v := rr.(type) {
		case *dns.NSEC:
			if strings.EqualFold(v.Hdr.Name, cut) && insecure(v.TypeBitMap) {
				return true
			}
		case *dns.NSEC3:
			if inChain(v, origin) {
				n3 = append(n3, v)
			}
		}
	}
	for _, n := range n3 {
		if n.Match(cut) {
			return insecure(n.TypeBitMap)
		}
	}
	// Opt-out (RFC 5155 section 7.2.7): the closest provable encloser matches, and the next closer name is covered
	// by an NSEC3 with the opt-out flag.
	labels := dns.SplitDomainName(cut)
	for i := 1; i < len(labels); i++ {
		ce := dns.Fqdn(strings.Join(labels[i:], "."))
		if !dns.IsSubDomain(origin, ce) {
			break
		}
		for _, m := range n3 {
			if !m.Match(ce) {
				continue
			}
			next := dns.Fqdn(strings.Join(labels[i-1:], "."))
			for _, c := range n3 {
				if c.Cover(next) && c.Flags&1 == 1 {
					return true
				}
			}
			return false
		}
	}
	return false
}

// compareDenialTypes reports providers that deny with different mechanisms (model section 4, "Denial"; RFC 8901
// section 5): a risk, not a failure.
func compareDenialTypes(ctx *runState, providers []Provider, rep *Report) {
	ref := ctx.denialType[providers[0].Name]
	for _, p := range providers[1:] {
		if t := ctx.denialType[p.Name]; ref != "" && t != "" && t != ref {
			ctx.finding(rep, Risk, "denial-type-differs", question{ctx.origin, "SOA", "record"}, p.Name, fmt.Sprintf(
				"%s denies with %s, this provider with %s: during a multi-signer period resolvers get both, and NSEC "+
					"undoes NSEC3's protection against zone walking (RFC 8901 section 5)", providers[0].Name, ref, t))
		}
	}
}

func hasType(bitmap []uint16, t uint16) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}

// nsecCovers reports whether n's span (owner, next) strictly contains x in canonical order; the last NSEC wraps to
// the apex.
func nsecCovers(n *dns.NSEC, x, origin string) bool {
	return zone.CanonicalLess(n.Hdr.Name, x) &&
		(zone.CanonicalLess(x, n.NextDomain) || strings.EqualFold(n.NextDomain, origin))
}

func nsecProves(name string, qtype uint16, nx bool, origin string, recs []dns.RR) bool {
	var ns []*dns.NSEC
	for _, rr := range recs {
		if n, ok := rr.(*dns.NSEC); ok {
			ns = append(ns, n)
		}
	}
	if !nx {
		for _, n := range ns {
			if strings.EqualFold(n.Hdr.Name, name) {
				return !hasType(n.TypeBitMap, qtype) && !hasType(n.TypeBitMap, dns.TypeCNAME)
			}
			// An empty non-terminal has no NSEC of its own: the NSEC before it points to a name below it.
			if nsecCovers(n, name, origin) && dns.IsSubDomain(name, n.NextDomain) {
				return true
			}
		}
		return false
	}
	for _, n := range ns {
		if !nsecCovers(n, name, origin) {
			continue
		}
		// The closest encloser is the longer common ancestor of the name with the NSEC's owner and next name.
		ce := ancestor(name, dns.CompareDomainName(name, n.Hdr.Name))
		if c := ancestor(name, dns.CompareDomainName(name, n.NextDomain)); dns.CountLabel(c) > dns.CountLabel(ce) {
			ce = c
		}
		for _, w := range ns {
			if nsecCovers(w, "*."+ce, origin) {
				return true
			}
		}
	}
	return false
}

func nsec3Proves(name string, qtype uint16, nx bool, origin string, recs []dns.RR) bool {
	var ns []*dns.NSEC3
	for _, rr := range recs {
		if n, ok := rr.(*dns.NSEC3); ok && inChain(n, origin) {
			ns = append(ns, n)
		}
	}
	match := func(x string) *dns.NSEC3 {
		for _, n := range ns {
			if n.Match(x) {
				return n
			}
		}
		return nil
	}
	covered := func(x string) bool {
		for _, n := range ns {
			if n.Cover(x) {
				return true
			}
		}
		return false
	}
	if !nx {
		n := match(name)
		return n != nil && !hasType(n.TypeBitMap, qtype) && !hasType(n.TypeBitMap, dns.TypeCNAME)
	}
	// Closest encloser proof (RFC 5155 section 7.2.1): an ancestor that matches, the next closer name covered, and
	// the wildcard at the closest encloser covered.
	labels := dns.SplitDomainName(name)
	for i := 1; i < len(labels); i++ {
		ce := dns.Fqdn(strings.Join(labels[i:], "."))
		if !dns.IsSubDomain(origin, ce) {
			break
		}
		if match(ce) != nil {
			return covered(dns.Fqdn(strings.Join(labels[i-1:], "."))) && covered("*."+ce)
		}
	}
	return false
}

// ancestor returns the last n labels of name as a name.
func ancestor(name string, n int) string {
	labels := dns.SplitDomainName(name)
	if n <= 0 || n > len(labels) {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[len(labels)-n:], "."))
}
