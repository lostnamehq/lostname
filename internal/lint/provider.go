package lint

import (
	"bytes"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"lostname.be/lostname/internal/zone"
)

// Rules about the zone's current providers and nameservers, read from its apex NS (model section 3). Offline a
// provider is known only by the registered domain of its nameserver names (ns1.provider.example is
// provider.example); lint makes no network calls, so addresses are only those the zone itself holds as glue.

// registered returns the registered domain of a DNS name (public suffix plus one label), lower case, without the
// trailing dot; "" for a name that has none (a bare public suffix).
func registered(name string) string {
	d, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(strings.ToLower(name), "."))
	if err != nil {
		return ""
	}
	return d
}

// apexNS returns the apex NS targets, lower case, and the registered domains of the out-of-zone ones: the current
// providers' domains.
func apexNS(z *zone.Zone) (targets map[string]bool, providers map[string]bool) {
	targets, providers = map[string]bool{}, map[string]bool{}
	for _, r := range z.At(z.Origin, "NS") {
		t := strings.ToLower(r.RR().(*dns.NS).Ns)
		targets[t] = true
		if !dns.IsSubDomain(z.Origin, t) {
			if d := registered(t); d != "" {
				providers[d] = true
			}
		}
	}
	// Red team 3, L3-10: a zone served by its own organisation's nameservers (lab.example.test on ns1.example.test)
	// has no provider in that domain; the owner's registered domain is never "the provider".
	delete(providers, registered(z.Origin))
	return targets, providers
}

// L-11: a sub-delegation whose NS are the current provider's servers. After the exit that provider no longer hosts
// the zone's data, so the child is lame unless it moves too.
func l11(z *zone.Zone) []Finding {
	targets, providers := apexNS(z)
	var out []Finding
	for _, cut := range z.Delegations() {
		for _, r := range z.At(cut, "NS") {
			t := strings.ToLower(r.RR().(*dns.NS).Ns)
			if dns.IsSubDomain(z.Origin, t) {
				continue // the zone's own server, not a provider's
			}
			if targets[t] || providers[registered(t)] {
				out = append(out, Finding{"L-11", Blocker, cut, "NS", "the delegation names " + t +
					", a server of the current DNS provider: after the exit it is lame unless " + cut +
					" moves too", "Lostname model section 3"})
			}
		}
	}
	return out
}

// targetsOf returns the names a record points at, for the types whose target a resolver or client follows.
func targetsOf(r zone.Record) []string {
	switch rr := r.RR().(type) {
	case *dns.CNAME:
		return []string{rr.Target}
	case *dns.MX:
		return []string{rr.Mx}
	case *dns.SRV:
		return []string{rr.Target}
	case *dns.DNAME:
		return []string{rr.Target}
	case *dns.SVCB:
		return []string{rr.Target}
	case *dns.HTTPS:
		return []string{rr.Target}
	}
	return nil
}

// L-12: a target under the current DNS provider's own domain (a proxy, a redirect or a mail-forwarding host). It is
// that provider's service, not the zone's data, and can stop with the account.
func l12(z *zone.Zone) []Finding {
	_, providers := apexNS(z)
	if len(providers) == 0 {
		return nil
	}
	var out []Finding
	for _, r := range z.Records {
		for _, t := range targetsOf(r) {
			t = strings.ToLower(t)
			if t == "." || dns.IsSubDomain(z.Origin, t) {
				continue
			}
			if d := registered(t); providers[d] {
				out = append(out, Finding{"L-12", Risk, r.Name, r.Type, r.Type + " points at " + t + ", under " + d +
					", the current DNS provider's own domain: check that it keeps working after the exit",
					"Lostname model section 3"})
			}
		}
	}
	return out
}

// udpLimit is the EDNS UDP payload size that DNS Flag Day 2020 recommends and most resolvers use: a larger answer
// truncates over UDP, and the client must retry over TCP.
const udpLimit = 1232

// L-16: an RRset whose answer (with its signatures, as the zone holds them) is larger than udpLimit: it truncates
// over UDP, so it depends on TCP at the target, and a provider that splits or signs differently changes its size.
func l16(z *zone.Zone) []Finding {
	type key struct{ name, typ string }
	sets := map[key][]dns.RR{}
	var order []key
	for _, r := range z.Records {
		k := key{r.Name, r.Type}
		if r.Type == "RRSIG" {
			k.typ = "RRSIG " + dns.TypeToString[r.RR().(*dns.RRSIG).TypeCovered]
		}
		if _, ok := sets[k]; !ok {
			order = append(order, k)
		}
		sets[k] = append(sets[k], r.RR())
	}
	var out []Finding
	for _, k := range order {
		if strings.HasPrefix(k.typ, "RRSIG") {
			continue
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(k.name), dns.StringToType[k.typ])
		m.Answer = append(append(m.Answer, sets[k]...), sets[key{k.name, "RRSIG " + k.typ}]...)
		m.SetEdns0(udpLimit, true)
		m.Compress = true
		if n := m.Len(); n > udpLimit {
			out = append(out, Finding{"L-16", Note, k.name, k.typ, "the answer is about " + strconv.Itoa(n) +
				" bytes with its signatures, over " + strconv.Itoa(udpLimit) + ": it truncates over UDP and needs TCP " +
				"at the target", "DNS Flag Day 2020"})
		}
	}
	return out
}

// L-20: shared fate. Two apex nameservers that share an address, or a prefix (/24 for IPv4, /48 for IPv6), fail
// together: one network, two names. Offline only the zone's own glue gives addresses (vanity names such as
// ns1.<zone>); parity compares the providers' real addresses. AS numbers are not checked yet (RL-3, v0.2).
func l20(z *zone.Zone) []Finding {
	type addr struct {
		ns string
		ip []byte // 4 bytes for IPv4, 16 for IPv6
	}
	var addrs []addr
	for _, r := range z.At(z.Origin, "NS") {
		t := strings.ToLower(r.RR().(*dns.NS).Ns)
		for _, g := range append(z.At(t, "A"), z.At(t, "AAAA")...) {
			switch rr := g.RR().(type) {
			case *dns.A:
				addrs = append(addrs, addr{t, rr.A.To4()})
			case *dns.AAAA:
				addrs = append(addrs, addr{t, rr.AAAA.To16()})
			}
		}
	}
	seen := map[string]bool{}
	var out []Finding
	for i, a := range addrs {
		for _, b := range addrs[i+1:] {
			if a.ns == b.ns {
				continue
			}
			what := SharedFate(a.ip, b.ip)
			pair := []string{a.ns, b.ns}
			sort.Strings(pair)
			if what == "" || seen[pair[0]+" "+pair[1]] {
				continue
			}
			seen[pair[0]+" "+pair[1]] = true
			out = append(out, Finding{"L-20", Risk, z.Origin, "NS", pair[0] + " and " + pair[1] + " share " + what +
				": they can fail together", "RFC 2182 3.1"})
		}
	}
	return out
}

// SharedFate says what two nameserver addresses share: "an address", "a /24 prefix" (IPv4) or "a /48 prefix"
// (IPv6), or "". a and b are 4 bytes for IPv4 and 16 for IPv6; lint compares bytes and imports no network package.
func SharedFate(a, b []byte) string {
	switch {
	case len(a) != len(b) || (len(a) != 4 && len(a) != 16):
		return ""
	case bytes.Equal(a, b):
		return "an address"
	case len(a) == 4 && bytes.Equal(a[:3], b[:3]):
		return "a /24 prefix"
	case len(a) == 16 && bytes.Equal(a[:6], b[:6]):
		return "a /48 prefix"
	}
	return ""
}

// L-10: provider metadata on a record (DNSControl's meta: a proxy, geo or weighted routing setting). It is not DNS
// data: a zone transfer drops it, and another provider ignores it or reads it differently, so the behaviour it sets
// is lost on export.
func l10(z *zone.Zone) []Finding {
	var out []Finding
	for _, m := range z.Meta {
		out = append(out, Finding{"L-10", Risk, m.Name, m.Type, "provider metadata (" + strings.Join(m.Keys, ", ") +
			") on this record is not DNS data: a zone transfer or another provider does not carry it; set it up " +
			"again at the target, or accept the plain record", "Lostname M0 F1"})
	}
	return out
}

// L-22: DANE TLSA for a mail host of this zone. DANE senders check TLSA through DNSSEC: in an unsigned zone the
// records do nothing; in a signed one, an exit whose DNSSEC handover goes bogus makes those senders defer all mail
// (RFC 7672 section 2.2), so the handover decides mail delivery too (model section 13.7, D13).
func l22(z *zone.Zone) []Finding {
	signed := len(z.At(z.Origin, "DNSKEY")) > 0
	mx := map[string]bool{}
	for _, r := range z.At(z.Origin, "MX") {
		mx[strings.ToLower(r.RR().(*dns.MX).Mx)] = true
	}
	var out []Finding
	seen := map[string]bool{}
	for _, r := range z.Records {
		// Red team 3, L3-11: only the MX hosts' TLSA is mail's (RFC 7672 2.2).
		if r.Type != "TLSA" || !strings.HasPrefix(r.Name, "_25._tcp.") || seen[r.Name] ||
			!mx[strings.TrimPrefix(r.Name, "_25._tcp.")] {
			continue
		}
		seen[r.Name] = true
		if signed {
			out = append(out, Finding{"L-22", Note, r.Name, "TLSA", "DANE for mail: if the DNSSEC handover of the " +
				"exit goes bogus, DANE senders defer all mail to this host until it validates again", "RFC 7672 2.2"})
		} else {
			out = append(out, Finding{"L-22", Risk, r.Name, "TLSA", "TLSA in an unsigned zone: DANE senders ignore it, " +
				"and signing the zone after the move would switch DANE on for this host", "RFC 7672 2.2"})
		}
	}
	return out
}
