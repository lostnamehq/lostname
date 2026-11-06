package sim

// Test fixtures: the .be parent values measured on 2026-11-05 (DS and delegation NS 86400 s, negative TTL 600 s), a
// common DNSKEY TTL and margin, and the .be lock profiles. Production values come from the config, never from here.

const M = 3600

var DefaultTTLs = TTLs{DS: 86400, Neg: 600, NSParent: 86400, DNSKEY: 3600, Margin: M}

var (
	NoLock       = Lock{Name: "none"}
	DomainShield = Lock{Name: "Domain Shield", Latency: 4 * 3600, Window: 24 * 3600}
	DomainGuard  = Lock{Name: "Domain Guard", Latency: 2 * 86400}
)
