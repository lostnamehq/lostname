package parity

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// checkSignatures judges the RRSIGs one server returned with one answer (model section 4, "Signatures"). An RRset
// passes when at least one signature over it is inside its validity window, made by a key in that server's own
// DNSKEY RRset, and verifies; that is what a validating resolver needs. Where the zone file is signed, an answer
// without any signature fails too. A signature that is valid but expires within MinSigLife is a risk: the provider's
// re-signing is late, or the zone will go bogus after a move that stops re-signing.
func checkSignatures(ctx *runState, provider, addr, transport string, q question, a answer, rep *Report) {
	if a.class != "data" || (q.kind != "record" && q.kind != "nx-probe") {
		return // negative answers are checkDenial's; referrals are not signed
	}
	if len(a.sigs) == 0 {
		if ctx.signed {
			ctx.finding(rep, Fail, "rrsig-missing", q, provider,
				fmt.Sprintf("the zone is signed, but %s returned the RRset without an RRSIG", addr))
		}
		return
	}
	keys, reason := ctx.dnskeys(addr)
	if reason != "" {
		rep.Gaps = append(rep.Gaps, Gap{provider, addr, transport, q.name, q.typ,
			"signatures returned, but no DNSKEY RRset to check them against: " + reason})
		return
	}
	now := ctx.o.Now.Unix()
	var problems []string
	firstKind := ""
	soonest := int64(-1)
	for _, s := range a.sigs {
		kind, why := judge(s, keys, a.rrs, now, false)
		if kind == "" {
			if exp := int64(s.Expiration); soonest < 0 || exp < soonest {
				soonest = exp
			}
			// Labels does not count a leading "*" (RFC 4034 section 3.1.3): the wildcard's own owner is no expansion.
			n := dns.CountLabel(q.name)
			if strings.HasPrefix(q.name, "*.") {
				n--
			}
			if int(s.Labels) < n {
				checkWildcardProof(ctx, provider, addr, q, a, s, keys, rep)
			}
			continue
		}
		if firstKind == "" {
			firstKind = kind
		}
		problems = append(problems, why)
	}
	if soonest < 0 {
		ctx.finding(rep, Fail, firstKind, q, provider,
			fmt.Sprintf("no valid signature from %s: %s", addr, strings.Join(problems, "; ")))
		return
	}
	if rep.SignatureExpiry == nil {
		rep.SignatureExpiry = map[string]int64{}
	}
	if cur, ok := rep.SignatureExpiry[provider]; !ok || soonest < cur {
		rep.SignatureExpiry[provider] = soonest
	}
	if left := time.Duration(soonest-now) * time.Second; left < ctx.o.MinSigLife {
		ctx.finding(rep, Risk, "rrsig-expires-soon", q, provider, fmt.Sprintf("the signature from %s expires at %s, "+
			"in %s, under the minimum of %s", addr, time.Unix(soonest, 0).UTC().Format(time.RFC3339),
			left.Round(time.Minute), ctx.o.MinSigLife))
	}
}

// judge returns "" for a usable signature, or the finding kind and a reason.
func judge(s *dns.RRSIG, keys []*dns.DNSKEY, rrset []dns.RR, now int64, keySet bool) (string, string) {
	switch {
	case now < int64(s.Inception):
		return "rrsig-not-yet-valid", fmt.Sprintf("key %d: valid only from %s", s.KeyTag, stamp(s.Inception))
	case now > int64(s.Expiration):
		return "rrsig-expired", fmt.Sprintf("key %d: expired at %s", s.KeyTag, stamp(s.Expiration))
	}
	// Red team D10: key tags collide, so every key with the tag and algorithm is tried, as validators do. Red team
	// D11: a revoked key (RFC 5011 section 7) may only sign the DNSKEY RRset itself.
	candidates, revoked := 0, 0
	var lastErr error
	for _, k := range keys {
		if k.KeyTag() != s.KeyTag || k.Algorithm != s.Algorithm {
			continue
		}
		candidates++
		if k.Flags&dns.REVOKE != 0 && !keySet {
			revoked++
			continue
		}
		if lastErr = s.Verify(k, rrset); lastErr == nil {
			return "", ""
		}
	}
	switch {
	case candidates == 0:
		return "rrsig-unknown-key", fmt.Sprintf("key %d (algorithm %d) is not in the server's DNSKEY RRset",
			s.KeyTag, s.Algorithm)
	case revoked == candidates:
		return "rrsig-revoked-key", fmt.Sprintf("key %d is revoked (RFC 5011): it may only sign the DNSKEY RRset", s.KeyTag)
	}
	return "rrsig-invalid", fmt.Sprintf("key %d: %v", s.KeyTag, lastErr)
}

func stamp(t uint32) string { return time.Unix(int64(t), 0).UTC().Format(time.RFC3339) }

// dnskeys returns the server's apex DNSKEY RRset, asked once per address over TCP (it is often too large for UDP).
func (ctx *runState) dnskeys(addr string) ([]*dns.DNSKEY, string) {
	if k, ok := ctx.keys[addr]; ok {
		return k, ""
	}
	if r, ok := ctx.noKeys[addr]; ok {
		return nil, r
	}
	a, reason := ctx.query(addr, "tcp", question{ctx.origin, "DNSKEY", "record"})
	if reason == "" && a.class != "data" {
		reason = "the server has no DNSKEY RRset at the apex (" + a.class + ")"
	}
	if reason != "" {
		ctx.noKeys[addr] = reason
		return nil, reason
	}
	var keys []*dns.DNSKEY
	for _, rr := range a.rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	ctx.keys[addr] = keys
	ctx.keySet[addr], ctx.keySigs[addr], ctx.keyAnswer[addr] = a.rrs, a.sigs, a.key()
	return keys, ""
}

// checkChain checks, for one server, the link from the parent's DS RRset to the server's DNSKEY RRset (model section
// 4, "Signatures"): a key in the RRset matches a DS, and that key signs the RRset validly. Without a DS at the
// parent the delegation is insecure, which is valid DNS but no chain: a note. The DS RRset's own signature (the
// parent's chain to the root) is not checked here.
func checkChain(ctx *runState, provider, addr string, rep *Report) {
	q := question{ctx.origin, "DNSKEY", "record"}
	keys, kreason := ctx.dnskeys(addr)
	if len(ctx.o.Parent) == 0 {
		switch {
		case kreason != "" && ctx.signed:
			rep.Gaps = append(rep.Gaps, Gap{provider, addr, "tcp", ctx.origin, "DNSKEY",
				"the zone is signed, but the chain cannot be checked: " + kreason})
		case kreason == "" || ctx.signed:
			_, reason := ctx.parentDS()
			rep.Gaps = append(rep.Gaps, Gap{provider, addr, "", ctx.origin, "DS", reason})
		}
		return
	}
	ds, reason := ctx.parentDS()
	if reason != "" {
		rep.Gaps = append(rep.Gaps, Gap{provider, addr, "", ctx.origin, "DS", reason})
		return
	}
	if len(ds) == 0 {
		if kreason == "" {
			ctx.finding(rep, Note, "parent-no-ds", question{ctx.origin, "DS", "record"}, provider,
				"the parent publishes no DS: the delegation is insecure, so validators accept this zone unsigned")
		}
		return
	}
	// Red team D7 and D8: a DS at the parent over a provider that serves no keys is bogus for every validator,
	// whether or not the zone file is signed (a stale DS after an exit, or one unsigned provider of several).
	if kreason != "" {
		ctx.finding(rep, Fail, "ds-without-dnskey", q, provider, fmt.Sprintf("the parent publishes a DS for this zone, "+
			"but %s serves no DNSKEY RRset (%s): validators find the zone bogus here; remove the DS at the parent "+
			"first, or sign at this provider", addr, kreason))
		return
	}
	// Red team D9: validators usually fetch the DNSKEY RRset over UDP; it must be the same, signatures included.
	if au, r := ctx.query(addr, "udp", q); r == "" &&
		(au.key() != ctx.keyAnswer[addr] || len(au.sigs) < len(ctx.keySigs[addr])) {
		ctx.finding(rep, Fail, "dnskey-transport-differs", q, provider, fmt.Sprintf("%s serves a different DNSKEY "+
			"RRset or fewer signatures over UDP than over TCP: validators that ask over UDP cannot authenticate the keys",
			addr))
		return
	}
	now := ctx.o.Now.Unix()
	var matched []*dns.DNSKEY
	for _, k := range keys {
		if k.Flags&dns.ZONE == 0 {
			continue // only zone keys can sign the zone (RFC 4034 section 2.1.1)
		}
		for _, d := range ds {
			if kd := k.ToDS(d.DigestType); kd != nil && kd.KeyTag == d.KeyTag && kd.Algorithm == d.Algorithm &&
				strings.EqualFold(kd.Digest, d.Digest) {
				matched = append(matched, k)
			}
		}
	}
	if len(matched) == 0 {
		var tags []string
		for _, d := range ds {
			tags = append(tags, fmt.Sprint(d.KeyTag))
		}
		ctx.finding(rep, Fail, "ds-no-matching-key", q, provider, fmt.Sprintf("none of the keys %s serves matches the "+
			"parent's DS (key tags %s): validators will find this provider bogus", addr, strings.Join(tags, ", ")))
		return
	}
	for _, s := range ctx.keySigs[addr] {
		for _, k := range matched {
			if s.KeyTag == k.KeyTag() && s.Algorithm == k.Algorithm {
				if kind, _ := judge(s, []*dns.DNSKEY{k}, ctx.keySet[addr], now, true); kind == "" {
					return
				}
			}
		}
	}
	ctx.finding(rep, Fail, "dnskey-not-signed-by-ds-key", q, provider, fmt.Sprintf("%s serves the key the parent's DS "+
		"points to, but no valid signature by it over the DNSKEY RRset: the chain breaks there", addr))
}

// parentDS asks the parent's servers (Options.Parent) for the zone's DS RRset, once. Every parent server must answer
// authoritatively with the same RRset; anything else is a reason there is no verdict on the chain.
func (ctx *runState) parentDS() ([]*dns.DS, string) {
	if ctx.dsDone {
		return ctx.ds, ctx.dsReason
	}
	ctx.dsDone = true
	if len(ctx.o.Parent) == 0 {
		ctx.dsReason = "the chain to the parent's DS is not checked: give the parent zone's servers (--parent)"
		return nil, ctx.dsReason
	}
	first := ""
	for _, addr := range ctx.o.Parent {
		a, reason := ctx.query(addr, "tcp", question{ctx.origin, "DS", "record"})
		if reason != "" {
			ctx.dsReason = "the parent server " + addr + " gave no usable DS answer: " + reason
			return nil, ctx.dsReason
		}
		if first == "" {
			first = a.key()
			for _, rr := range a.rrs {
				if d, ok := rr.(*dns.DS); ok {
					ctx.ds = append(ctx.ds, d)
				}
			}
		} else if a.key() != first {
			ctx.ds, ctx.dsReason = nil, "the parent's servers answer different DS RRsets: the parent is mid-change"
			return nil, ctx.dsReason
		}
	}
	return ctx.ds, ""
}

// finding records one signature finding per provider, question and kind; the first server's detail stands for all.
func (ctx *runState) finding(rep *Report, sev Severity, kind string, q question, provider, detail string) {
	k := provider + "|" + q.name + "|" + q.typ + "|" + kind
	if ctx.seen[k] {
		return
	}
	ctx.seen[k] = true
	rep.Findings = append(rep.Findings, Finding{sev, kind, q.name, q.typ, provider, detail})
}

// checkWildcardProof: an answer expanded from a wildcard (the signature's Labels field is below the name's label
// count) must come with signed NSEC or NSEC3 proof that the name itself does not exist, or validators reject it
// (RFC 4035 section 5.3.4, RFC 5155 section 8.8). NSEC must cover the name; NSEC3 must cover the next closer name,
// one label longer than the wildcard's closest encloser.
func checkWildcardProof(ctx *runState, provider, addr string, q question, a answer, s *dns.RRSIG, keys []*dns.DNSKEY,
	rep *Report) {
	now := ctx.o.Now.Unix()
	proven := false
	for _, rr := range a.denial {
		signed := false
		for _, ds := range a.denialSigs {
			if strings.EqualFold(ds.Hdr.Name, rr.Header().Name) && ds.TypeCovered == rr.Header().Rrtype {
				if kind, _ := judge(ds, keys, []dns.RR{rr}, now, false); kind == "" {
					signed = true
				}
			}
		}
		if !signed {
			continue
		}
		switch v := rr.(type) {
		case *dns.NSEC:
			proven = proven || nsecCovers(v, q.name, ctx.origin)
		case *dns.NSEC3:
			proven = proven || (inChain(v, ctx.origin) && v.Cover(ancestor(q.name, int(s.Labels)+1)))
		}
	}
	if !proven {
		ctx.finding(rep, Fail, "wildcard-proof-missing", q, provider, fmt.Sprintf("%s expanded the answer from a "+
			"wildcard without a signed proof that %s itself does not exist: validators reject it", addr, q.name))
	}
}

// compareCDS is lint rule L-19 at the providers (RFC 8901 sections 8 and 9): when the parent scans CDS or CDNSKEY
// (RFC 7344, RFC 8078), it replaces the DS with what one server publishes. Whether a parent scans is not known here,
// so the check judges as if it does (fail-closed), and the red team of round 3 tightened it:
//   - every server is asked over UDP (where scanners usually ask) and TCP, and must give one answer (P3-3);
//   - a server that does not answer is a gap, not silence: nothing else asks for CDS (P3-2);
//   - in a signed zone the set must carry a valid signature by the server's keys (P3-4);
//   - a provider's CDS and CDNSKEY must describe the same keys (P3-6);
//   - every pair of providers that publish a set must publish the same one, the reference or not (P3-1); a set at
//     some providers only is a risk.
func compareCDS(ctx *runState, providers []Provider, rep *Report) {
	sets := map[string]map[string]cdsView{} // type -> provider -> what it publishes
	for _, typ := range []string{"CDS", "CDNSKEY"} {
		sets[typ] = map[string]cdsView{}
		q := question{ctx.origin, typ, "record"}
		for _, p := range providers {
			var view *cdsView
			for _, addr := range p.Addrs {
				for _, tr := range []string{"udp", "tcp"} {
					a, reason := ctx.query(addr, tr, q)
					if reason == truncatedUDP {
						continue // TCP answers for it
					}
					if reason != "" {
						rep.Gaps = append(rep.Gaps, Gap{p.Name, addr, tr, q.name, q.typ, reason})
						continue
					}
					v := cdsView{}
					if a.class == "data" {
						v.set, v.rrs = strings.Join(a.rdata, "\n"), a.rrs
						if ctx.signed && !cdsSigned(ctx, p.Name, addr, q, a, rep) {
							continue
						}
					}
					if view != nil && view.set != v.set {
						ctx.finding(rep, Fail, "cds-differs", q, p.Name, fmt.Sprintf("%s's servers or transports "+
							"publish different %s sets (%s over %s among them): a parent that scans may install "+
							"either", p.Name, typ, addr, tr))
						continue
					}
					view = &v
				}
			}
			if view != nil {
				sets[typ][p.Name] = *view
			}
		}
		var publishers, silent []string
		for _, p := range providers {
			if v, ok := sets[typ][p.Name]; ok {
				if v.set != "" {
					publishers = append(publishers, p.Name)
				} else {
					silent = append(silent, p.Name)
				}
			}
		}
		for i, a := range publishers {
			for _, b := range publishers[i+1:] {
				if sets[typ][a].set != sets[typ][b].set {
					ctx.finding(rep, Fail, "cds-differs", q, b, fmt.Sprintf("%s and %s publish different %s sets: "+
						"a parent that scans installs one provider's DS, and the zone is bogus at the other; in a "+
						"multi-signer setup each must publish the combined set (RFC 8901 section 8)", a, b, typ))
				}
			}
		}
		if len(publishers) > 0 {
			for _, p := range silent {
				ctx.finding(rep, Risk, "cds-one-sided", q, p, fmt.Sprintf("%s publishes %s and %s does not: a "+
					"parent that scans follows the publishing provider alone", strings.Join(publishers, ", "), typ, p))
			}
		}
	}
	for _, p := range providers {
		if cds, cdnskey := sets["CDS"][p.Name], sets["CDNSKEY"][p.Name]; cds.set != "" && cdnskey.set != "" &&
			!sameKeys(cds.rrs, cdnskey.rrs) {
			ctx.finding(rep, Fail, "cds-cdnskey-differ", question{ctx.origin, "CDS", "record"}, p.Name, p.Name+
				" publishes CDS and CDNSKEY sets that describe different keys: a parent reading one installs another "+
				"DS than a parent reading the other (RFC 7344 section 4)")
		}
	}
}

// cdsView is what one provider publishes as CDS or CDNSKEY: the comparison key, and the records.
type cdsView struct {
	set string
	rrs []dns.RR
}

// cdsSigned judges the signature over a CDS or CDNSKEY RRset with the server's own keys; it reports a gap or a
// finding and returns false when the set cannot count.
func cdsSigned(ctx *runState, provider, addr string, q question, a answer, rep *Report) bool {
	keys, reason := ctx.dnskeys(addr)
	if reason != "" {
		rep.Gaps = append(rep.Gaps, Gap{provider, addr, "tcp", q.name, q.typ,
			"a signed " + q.typ + " set, but no DNSKEY RRset to check it against: " + reason})
		return false
	}
	kind, detail := "rrsig-missing", "the "+q.typ+" set from "+addr+" is not signed: a validating parent ignores it"
	for _, s := range a.sigs {
		k, d := judge(s, keys, a.rrs, ctx.o.Now.Unix(), false)
		if k == "" {
			return true
		}
		kind, detail = k, q.typ+" from "+addr+": "+d
	}
	ctx.finding(rep, Fail, kind, q, provider, detail)
	return false
}

// sameKeys reports whether a CDS set and a CDNSKEY set describe the same keys: each CDNSKEY, digested with the CDS
// set's digest types, is in the CDS set, and each CDS matches a CDNSKEY. The delete forms (RFC 8078 section 4) match
// each other.
func sameKeys(cds, cdnskey []dns.RR) bool {
	var ds []*dns.CDS
	digests := map[uint8]bool{}
	for _, rr := range cds {
		if c, ok := rr.(*dns.CDS); ok {
			ds = append(ds, c)
			digests[c.DigestType] = true
		}
	}
	var keys []*dns.CDNSKEY
	for _, rr := range cdnskey {
		if k, ok := rr.(*dns.CDNSKEY); ok {
			keys = append(keys, k)
		}
	}
	deleteCDS := len(ds) == 1 && ds[0].Algorithm == 0 && ds[0].DigestType == 0
	deleteKey := len(keys) == 1 && keys[0].Algorithm == 0
	if deleteCDS || deleteKey {
		return deleteCDS == deleteKey
	}
	matched := map[int]bool{}
	for _, k := range keys {
		found := false
		for d := range digests {
			want := k.DNSKEY.ToDS(d)
			for i, c := range ds {
				if want != nil && c.KeyTag == want.KeyTag && c.Algorithm == want.Algorithm &&
					c.DigestType == want.DigestType && strings.EqualFold(c.Digest, want.Digest) {
					found, matched[i] = true, true
				}
			}
		}
		if !found {
			return false
		}
	}
	return len(matched) == len(ds)
}
