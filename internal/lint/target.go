package lint

import (
	"fmt"

	"lostname.be/lostname/internal/target"
	"lostname.be/lostname/internal/zone"
)

// RunTarget applies the checks that need a target provider (model section 3): what will not survive a move of z to
// p. The provider data is DNSControl's feature matrix at the release target.From names.
func RunTarget(z *zone.Zone, p target.Provider) []Finding {
	src := target.From()
	matrix := fmt.Sprintf("DNSControl %s provider matrix", src.Tag)
	var out []Finding
	// L-01: a target that needs an SOA in the config, and the config has none (M0 F2: push deletes the SOA).
	if why := p.NeedsSOA(); why != "" && len(z.At(z.Origin, "SOA")) == 0 {
		out = append(out, Finding{"L-01", Blocker, z.Origin, "SOA", fmt.Sprintf("the input has no SOA, and %s: add "+
			"an SOA to the config before the first push", why), "Lostname M0 F2"})
	}
	// L-02: record types the target does not serve, once per name and type.
	seen := map[string]bool{}
	for _, r := range z.Records {
		k := r.Name + " " + r.Type
		if seen[k] {
			continue
		}
		seen[k] = true
		switch p.Supports(r.Type) {
		case target.No:
			out = append(out, Finding{"L-02", Blocker, r.Name, r.Type, fmt.Sprintf("%s does not serve %s records: "+
				"they are lost in the move", p.Name, r.Type), matrix})
		case target.Unknown:
			out = append(out, Finding{"L-02", Risk, r.Name, r.Type, fmt.Sprintf("%s support for %s records is unknown "+
				"in the matrix: test it before the move", p.Name, r.Type), matrix})
		}
	}
	// L-03: ALIAS is a provider feature, not a DNS record; other pseudo-records likewise.
	for _, r := range z.Pseudo {
		switch {
		case r.Type == "ALIAS" && p.Supports("ALIAS") == target.No:
			out = append(out, Finding{"L-03", Blocker, r.Name, r.Type, fmt.Sprintf("%s has no ALIAS: this name stops "+
				"answering after the move; use a CNAME (not at the apex) or the target's own records", p.Name), matrix})
		case r.Type == "ALIAS":
			out = append(out, Finding{"L-03", Risk, r.Name, r.Type, "ALIAS is not a DNS record and behaves differently " +
				"per provider (one may answer empty, M0 F6): check the answer at the target before the move", "Lostname M0 F5, F6"})
		default:
			out = append(out, Finding{"L-02", Risk, r.Name, r.Type, fmt.Sprintf("%s is a DNSControl pseudo-record, a "+
				"provider feature with no DNS equivalent: check that %s has it", r.Type, p.Name), matrix})
		}
	}
	return out
}

// RunIntent is L-04: the DNSSEC intent of a config against the zone as it is served now and against the target.
// current may be nil (no --current); p may be nil (no --to).
func RunIntent(cfg, current *zone.Zone, p *target.Provider) []Finding {
	var out []Finding
	signedNow := current != nil && len(current.At(current.Origin, "DNSKEY")) > 0
	if signedNow && cfg.DNSSECIntent != "on" {
		out = append(out, Finding{"L-04", Blocker, cfg.Origin, "DNSKEY", "the zone is signed now, but the config does " +
			"not ask the new provider to sign it (no AUTODNSSEC_ON): validators reject the zone after the move unless " +
			"the DS is removed at the parent first (exit model T1)", "Lostname M0 F1, F3"})
	}
	if p != nil && cfg.DNSSECIntent == "on" && p.Feature("AUTODNSSEC") != target.Yes {
		out = append(out, Finding{"L-04", Blocker, cfg.Origin, "DNSKEY", fmt.Sprintf("the config asks for AUTODNSSEC_ON, "+
			"but %s cannot sign zones through DNSControl (%s in the %s matrix): sign there by hand, or choose a "+
			"target that can", p.Name, p.Feature("AUTODNSSEC"), target.From().Tag), "DNSControl provider matrix"})
	}
	return out
}
