package authtest

import (
	"crypto"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/zone"
)

// Keys is a test key set: a KSK that signs the DNSKEY RRset and a ZSK that signs everything else, both ECDSA P-256
// (algorithm 13).
type Keys struct {
	KSK, ZSK         *dns.DNSKEY
	kskPriv, zskPriv crypto.Signer
}

// NewKeys generates a key set for origin.
func NewKeys(t *testing.T, origin string) *Keys {
	t.Helper()
	k := &Keys{}
	for _, flags := range []uint16{257, 256} {
		key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: dns.Fqdn(origin), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET,
			Ttl: 3600}, Flags: flags, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
		priv, err := key.Generate(256)
		if err != nil {
			t.Fatal(err)
		}
		if flags == 257 {
			k.KSK, k.kskPriv = key, priv.(crypto.Signer)
		} else {
			k.ZSK, k.zskPriv = key, priv.(crypto.Signer)
		}
	}
	return k
}

// Denial selects how a signed zone proves that names and types do not exist.
type Denial int

const (
	WithNSEC        Denial = iota // RFC 4034 section 4
	WithNSEC3                     // RFC 5155, with no salt and no extra iterations (RFC 9276)
	WithNSEC3OptOut               // NSEC3 with the opt-out flag: insecure delegations are left out of the chain (RFC 5155 6)
)

// Sign returns z signed with NSEC denial; see SignWith.
func Sign(t *testing.T, z *zone.Zone, k *Keys, inception, expiration time.Time) *zone.Zone {
	t.Helper()
	return SignWith(t, z, k, inception, expiration, WithNSEC)
}

// SignWith returns z with the keys' DNSKEY RRset, an NSEC or NSEC3 chain, and an RRSIG over every authoritative
// RRset, valid from inception to expiration. Delegation NS RRsets and glue are not signed (RFC 4035 section 2.2).
func SignWith(t *testing.T, z *zone.Zone, k *Keys, inception, expiration time.Time, d Denial) *zone.Zone {
	t.Helper()
	cuts := z.Delegations()
	below := func(name string) bool {
		for _, c := range cuts {
			if dns.IsSubDomain(c, name) {
				return true
			}
		}
		return false
	}
	sets := map[string][]dns.RR{}
	var rrs []dns.RR
	for _, r := range z.Records {
		if r.Type == "DNSKEY" || r.Type == "RRSIG" {
			continue
		}
		rrs = append(rrs, dns.Copy(r.RR())) // z may be served already; see the key copies below
		if below(r.Name) && !(r.Type == "DS") {
			continue
		}
		key := r.Name + " " + r.Type
		sets[key] = append(sets[key], r.RR())
	}
	// Copies: zone.FromRRs writes the owner name of each record, while a server started earlier may still be packing
	// the same record (a data race under -race); the keys are shared by every zone signed with k.
	ksk, zsk := dns.Copy(k.KSK), dns.Copy(k.ZSK)
	sets[z.Origin+" DNSKEY"] = []dns.RR{ksk, zsk}
	rrs = append(rrs, ksk, zsk)
	for _, rr := range denialChain(z, sets, d) {
		key := rr.Header().Name + " " + dns.TypeToString[rr.Header().Rrtype]
		sets[key] = append(sets[key], rr)
		rrs = append(rrs, rr)
	}
	keys := make([]string, 0, len(sets))
	for s := range sets {
		keys = append(keys, s)
	}
	sort.Strings(keys)
	for _, s := range keys {
		signer, priv := k.ZSK, k.zskPriv
		if strings.HasSuffix(s, " DNSKEY") {
			signer, priv = k.KSK, k.kskPriv
		}
		sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: sets[s][0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET,
			Ttl: sets[s][0].Header().Ttl}, Algorithm: signer.Algorithm, SignerName: z.Origin, KeyTag: signer.KeyTag(),
			Inception: uint32(inception.Unix()), Expiration: uint32(expiration.Unix())}
		if err := sig.Sign(priv, sets[s]); err != nil {
			t.Fatalf("sign %s: %v", s, err)
		}
		rrs = append(rrs, sig)
	}
	signed, err := zone.FromRRs(z.Origin, z.Source+"+signed", rrs)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// denialChain builds the NSEC or NSEC3 records for the authoritative names in sets (owner and type, "name TYPE").
func denialChain(z *zone.Zone, sets map[string][]dns.RR, d Denial) []dns.RR {
	types := map[string][]uint16{}
	for key := range sets {
		name, typ, _ := strings.Cut(key, " ")
		types[name] = append(types[name], dns.StringToType[typ])
	}
	// A delegation point is in the chain with its unsigned NS RRset; glue below it is not.
	insecure := map[string]bool{}
	for _, c := range z.Delegations() {
		insecure[c] = len(types[c]) == 0 // no DS was signed there
		types[c] = append(types[c], dns.TypeNS)
	}
	ttl := uint32(300)
	if soa := z.At(z.Origin, "SOA"); len(soa) == 1 {
		ttl = min(soa[0].RR().(*dns.SOA).Minttl, soa[0].TTL)
	}
	if d == WithNSEC3 || d == WithNSEC3OptOut {
		var flags uint8
		if d == WithNSEC3OptOut {
			flags = 1
			for c, open := range insecure {
				if open {
					delete(types, c) // opt-out: an insecure delegation has no NSEC3 of its own
				}
			}
		}
		param := &dns.NSEC3PARAM{Hdr: dns.RR_Header{Name: z.Origin, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET},
			Hash: dns.SHA1}
		types[z.Origin] = append(types[z.Origin], dns.TypeNSEC3PARAM)
		out := []dns.RR{param}
		// Empty non-terminals get an NSEC3 too (RFC 5155 section 7.1).
		for name := range types {
			for a := name; a != z.Origin; {
				_, next, _ := strings.Cut(a, ".")
				a = next
				if _, ok := types[a]; !ok && dns.IsSubDomain(z.Origin, a) {
					types[a] = nil
				}
			}
		}
		hashed := map[string]string{}
		var hashes []string
		for name := range types {
			h := strings.ToLower(dns.HashName(name, dns.SHA1, 0, ""))
			hashed[h] = name
			hashes = append(hashes, h)
		}
		sort.Strings(hashes)
		for i, h := range hashes {
			bitmap := types[hashed[h]]
			if len(bitmap) > 0 && !insecure[hashed[h]] {
				bitmap = append(bitmap, dns.TypeRRSIG)
			}
			out = append(out, &dns.NSEC3{Hdr: dns.RR_Header{Name: h + "." + z.Origin, Rrtype: dns.TypeNSEC3,
				Class: dns.ClassINET, Ttl: ttl}, Hash: dns.SHA1, Flags: flags,
				NextDomain: strings.ToUpper(hashes[(i+1)%len(hashes)]), HashLength: 20, TypeBitMap: sortTypes(bitmap)})
		}
		return out
	}
	var names []string
	for name := range types {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return zone.CanonicalLess(names[i], names[j]) })
	var out []dns.RR
	for i, name := range names {
		out = append(out, &dns.NSEC{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
			NextDomain: names[(i+1)%len(names)], TypeBitMap: sortTypes(append(types[name], dns.TypeRRSIG, dns.TypeNSEC))})
	}
	return out
}

func sortTypes(ts []uint16) []uint16 {
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	return ts
}
