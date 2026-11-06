// Package sim is the formal model behind Lostname's exit simulator (model section 5, feature D11).
//
// A plan is a sequence of worlds. Each world fixes what the parent publishes (DS, NS) and what every provider
// serves (whether it serves the zone, which DNSKEYs it publishes, which keys sign). A resolver may hold NS, DS and
// DNSKEY data fetched in any earlier world for as long as its TTL allows; the explorer enumerates every such
// combination and every server the resolver could ask, and classifies each answer. The invariant a safe plan keeps:
// no validating resolver ever gets a bogus answer, and no resolver is sent to a server that no longer serves the zone.
package sim

// Key names a DNSSEC key, for example "A.ksk" or "B.zsk".
type Key string

// Provider is what one DNS provider serves for the zone during one world.
type Provider struct {
	Serving bool  // the provider answers authoritatively for the zone
	DNSKEY  []Key // the DNSKEY RRset it publishes (own keys plus imported ones)
	KSKs    []Key // the keys that sign its DNSKEY RRset (two during a double-signature roll); empty when unsigned
	ZSK     Key   // the key that signs its zone data; "" when unsigned
}

// World is the state of parent and providers between two plan steps.
type World struct {
	ParentDS  []Key // KSKs the parent's DS RRset points to; empty means the zone is unsigned at the parent
	ParentNS  []string
	Providers map[string]Provider
}

// TTLs are the cache lifetimes that decide how long old state can survive in a resolver (seconds).
type TTLs struct {
	DS       int // DS RRset at the parent
	Neg      int // negative caching at the parent: min(SOA MINIMUM, SOA TTL), RFC 2308 section 5
	NSParent int // delegation NS RRset at the parent
	DNSKEY   int // DNSKEY RRset at the providers
	Margin   int // safety margin added to every computed wait
}

// Step is one world and how long it is held before the next step starts (seconds). The last step is held for
// the plan's horizon.
type Step struct {
	Name  string
	World World
	Hold  int
}

// Plan is a named sequence of steps; Steps[0] is the steady state before the exit starts.
type Plan struct {
	Name  string
	TTL   TTLs
	Steps []Step
}

// Outcome classifies one possible answer.
type Outcome string

const (
	Secure   Outcome = "secure"
	Insecure Outcome = "insecure"
	Bogus    Outcome = "bogus" // a validating resolver rejects the answer: the zone fails for its users
	Lame     Outcome = "lame"  // the resolver asks a server that no longer serves the zone
)

func has(keys []Key, k Key) bool {
	for _, x := range keys {
		if x == k {
			return true
		}
	}
	return false
}
