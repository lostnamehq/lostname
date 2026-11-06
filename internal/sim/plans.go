package sim

// The transition models of model section 5, as data. TTLs and the safety margin come from the caller (the config's
// sim section, or the zone's measured values); nothing here assumes them.

var (
	aSigned   = Provider{Serving: true, DNSKEY: []Key{"A.ksk", "A.zsk"}, KSKs: []Key{"A.ksk"}, ZSK: "A.zsk"}
	bSigned   = Provider{Serving: true, DNSKEY: []Key{"B.ksk", "B.zsk"}, KSKs: []Key{"B.ksk"}, ZSK: "B.zsk"}
	aUnsigned = Provider{Serving: true}
	bUnsigned = Provider{Serving: true}
	off       = Provider{}
)

func world(ds []Key, ns []string, a, b Provider) World {
	return World{ParentDS: ds, ParentNS: ns, Providers: map[string]Provider{"A": a, "B": b}}
}

// T0: unsigned zone, unsigned move. Only the NS waits matter.
func T0(t TTLs) Plan {
	return Plan{Name: "T0 unsigned to unsigned", TTL: t, Steps: []Step{
		{"steady state at A", world(nil, []string{"A"}, aUnsigned, off), 0},
		{"B serves identical data", world(nil, []string{"A"}, aUnsigned, bUnsigned), 60},
		{"NS switched to B at the parent", world(nil, []string{"B"}, aUnsigned, bUnsigned), t.NSParent + t.Margin},
		{"A stops", world(nil, []string{"B"}, off, bUnsigned), 0},
	}}
}

// T1 as model section 5 writes it (draft 4a): remove the DS, wait, switch NS, wait, B signs and is checked, then
// B's DS goes up. dnskeyWait is the hold between "B signs" and "B's DS published"; the draft names no wait there.
func T1(t TTLs, dnskeyWait int) Plan {
	return Plan{Name: "T1 insecure swap", TTL: t, Steps: []Step{
		{"steady state at A, signed", world([]Key{"A.ksk"}, []string{"A"}, aSigned, off), 0},
		{"DS removed at the parent", world(nil, []string{"A"}, aSigned, off), t.DS + t.Margin},
		{"B serves identical data, unsigned", world(nil, []string{"A"}, aSigned, bUnsigned), 60},
		{"NS switched to B", world(nil, []string{"B"}, aSigned, bUnsigned), t.NSParent + t.Margin},
		{"A stops; B signs", world(nil, []string{"B"}, off, bSigned), dnskeyWait},
		{"B's DS published", world([]Key{"B.ksk"}, []string{"B"}, off, bSigned), 0},
	}}
}

// T2 multi-signer, model 2, in the order of model section 5 (draft 4a): cross-import ZSKs, add B's DS, serve
// both NS, switch to B, remove A's DS, then remove A's ZSK and stop A. afterSwitch is the hold between "parent NS
// = B" and removing A's DS; the draft used the NS TTL plus margin.
func T2(t TTLs, afterSwitch int) Plan {
	aX := Provider{Serving: true, DNSKEY: []Key{"A.ksk", "A.zsk", "B.zsk"}, KSKs: []Key{"A.ksk"}, ZSK: "A.zsk"}
	bX := Provider{Serving: true, DNSKEY: []Key{"B.ksk", "B.zsk", "A.zsk"}, KSKs: []Key{"B.ksk"}, ZSK: "B.zsk"}
	both := []Key{"A.ksk", "B.ksk"}
	return Plan{Name: "T2 multi-signer", TTL: t, Steps: []Step{
		{"steady state at A, signed", world([]Key{"A.ksk"}, []string{"A"}, aSigned, off), 0},
		{"ZSKs cross-imported; B serves, signed", world([]Key{"A.ksk"}, []string{"A"}, aX, bX), t.DNSKEY + t.Margin},
		{"B's DS added next to A's", world(both, []string{"A"}, aX, bX), t.DS + t.Margin},
		{"parent NS = A and B", world(both, []string{"A", "B"}, aX, bX), t.NSParent + t.Margin},
		{"parent NS = B", world(both, []string{"B"}, aX, bX), afterSwitch},
		{"A's DS removed", world([]Key{"B.ksk"}, []string{"B"}, aX, bX), t.DS + t.Margin},
		{"A's ZSK removed at B; A stops", world([]Key{"B.ksk"}, []string{"B"}, off, bSigned), 0},
	}}
}

// T4: double DS without key import. Model section 5 refuses it; the explorer must find why.
func T4(t TTLs) Plan {
	both := []Key{"A.ksk", "B.ksk"}
	return Plan{Name: "T4 double DS, no key import", TTL: t, Steps: []Step{
		{"steady state at A, signed", world([]Key{"A.ksk"}, []string{"A"}, aSigned, off), 0},
		{"B serves, signed with its own keys", world([]Key{"A.ksk"}, []string{"A"}, aSigned, bSigned), 60},
		{"B's DS added next to A's", world(both, []string{"A"}, aSigned, bSigned), t.DS + t.Margin},
		{"NS switched to B", world(both, []string{"B"}, aSigned, bSigned), t.NSParent + t.Margin},
		{"A stops; A's DS removed", world([]Key{"B.ksk"}, []string{"B"}, off, bSigned), 0},
	}}
}
