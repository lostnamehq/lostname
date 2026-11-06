package sim

// KSK rolls in place: the zone stays at provider A and its KSK changes from A.ksk to A.ksk2 (RFC 6781 section
// 4.1.2; timing in RFC 7583). These are the changes an operator like a federated site makes most often, so they are
// planned and simulated like an exit.

func signedA(dnskey []Key, ksks ...Key) Provider {
	return Provider{Serving: true, DNSKEY: dnskey, KSKs: ksks, ZSK: "A.zsk"}
}

func onlyA(ds []Key, a Provider) World {
	return World{ParentDS: ds, ParentNS: []string{"A"}, Providers: map[string]Provider{"A": a}}
}

// DoubleDS: publish the new DS next to the old one, wait, switch the DNSKEY RRset to the new KSK, wait, remove the
// old DS. dsWait is the hold after the double DS; keyWait the hold after the key switch.
func DoubleDS(t TTLs, dsWait, keyWait int) Plan {
	return Plan{Name: "KSK roll, double-DS", TTL: t, Steps: []Step{
		{"steady state, KSK 1", onlyA([]Key{"A.ksk"}, signedA([]Key{"A.ksk", "A.zsk"}, "A.ksk")), 0},
		{"DS for KSK 1 and KSK 2 at the parent", onlyA([]Key{"A.ksk", "A.ksk2"}, signedA([]Key{"A.ksk", "A.zsk"}, "A.ksk")), dsWait},
		{"DNSKEY switched to KSK 2", onlyA([]Key{"A.ksk", "A.ksk2"}, signedA([]Key{"A.ksk2", "A.zsk"}, "A.ksk2")), keyWait},
		{"old DS removed", onlyA([]Key{"A.ksk2"}, signedA([]Key{"A.ksk2", "A.zsk"}, "A.ksk2")), 0},
	}}
}

// DoubleSignature (double-KSK): publish both KSKs, each signing the DNSKEY RRset, wait, swap the DS, wait, remove
// the old KSK. keyWait is the hold after both keys appear; dsWait the hold after the DS swap.
func DoubleSignature(t TTLs, keyWait, dsWait int) Plan {
	both := []Key{"A.ksk", "A.ksk2", "A.zsk"}
	return Plan{Name: "KSK roll, double-signature", TTL: t, Steps: []Step{
		{"steady state, KSK 1", onlyA([]Key{"A.ksk"}, signedA([]Key{"A.ksk", "A.zsk"}, "A.ksk")), 0},
		{"KSK 2 published, both sign", onlyA([]Key{"A.ksk"}, signedA(both, "A.ksk", "A.ksk2")), keyWait},
		{"DS swapped to KSK 2", onlyA([]Key{"A.ksk2"}, signedA(both, "A.ksk", "A.ksk2")), dsWait},
		{"KSK 1 removed", onlyA([]Key{"A.ksk2"}, signedA([]Key{"A.ksk2", "A.zsk"}, "A.ksk2")), 0},
	}}
}

// NaiveRoll swaps key and DS at once, the mistake the explorer must catch.
func NaiveRoll(t TTLs) Plan {
	return Plan{Name: "KSK roll, naive swap", TTL: t, Steps: []Step{
		{"steady state, KSK 1", onlyA([]Key{"A.ksk"}, signedA([]Key{"A.ksk", "A.zsk"}, "A.ksk")), 0},
		{"key and DS swapped together", onlyA([]Key{"A.ksk2"}, signedA([]Key{"A.ksk2", "A.zsk"}, "A.ksk2")), 0},
	}}
}
