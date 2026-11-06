package sim

import "testing"

func show(t *testing.T, r Report) {
	t.Helper()
	t.Logf("%s: counts %v", r.Plan, r.Counts)
	for i, v := range r.Violations {
		if i == 6 {
			t.Logf("  ... %d more", len(r.Violations)-6)
			break
		}
		t.Logf("  %s", v)
	}
}

// minimalWait finds the smallest hold (seconds) for which build(hold) keeps the invariant, by binary search.
func minimalWait(build func(int) Plan, hi int) int {
	lo := 0
	if !Explore(build(hi)).OK() {
		return -1
	}
	for lo < hi {
		mid := (lo + hi) / 2
		if Explore(build(mid)).OK() {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

func TestT0IsSafe(t *testing.T) {
	r := Explore(T0(DefaultTTLs))
	show(t, r)
	if !r.OK() {
		t.Fatal("T0 must be safe")
	}
}

func TestT4IsFoundUnsafe(t *testing.T) {
	r := Explore(T4(DefaultTTLs))
	show(t, r)
	if r.OK() {
		t.Fatal("the explorer must find why double DS without key import fails")
	}
}

// Finding S1 (2026-11-05): T1 as drafted publishes B's DS with no wait after B signs. A resolver can still hold
// A's DNSKEY RRset (or B's empty answer from before B signed) and goes bogus.
func TestT1AsDraftedIsUnsafe(t *testing.T) {
	r := Explore(T1(DefaultTTLs, 0))
	show(t, r)
	if r.OK() {
		t.Fatal("T1 without a DNSKEY wait must be found unsafe")
	}
}

func TestT1NeedsOneDNSKEYTTL(t *testing.T) {
	w := minimalWait(func(h int) Plan { return T1(DefaultTTLs, h) }, 10*DefaultTTLs.DNSKEY)
	t.Logf("T1 minimal safe hold between B signing and B's DS: %d s (DNSKEY TTL %d s)", w, DefaultTTLs.DNSKEY)
	if w != DefaultTTLs.DNSKEY {
		t.Fatalf("expected exactly one DNSKEY TTL, got %d", w)
	}
	if r := Explore(T1(DefaultTTLs, DefaultTTLs.DNSKEY+M)); !r.OK() {
		show(t, r)
		t.Fatal("corrected T1 must be safe")
	}
}

// Finding S2 (2026-11-05): T2 as drafted waits the NS TTL plus a margin before removing A's DS. That is safe only
// while the margin covers the DNSKEY TTL: a resolver can still hold A's DNSKEY RRset fetched just before its NS
// cache expired. With a one-day DNSKEY TTL (common) the draft fails.
func TestT2AsDraftedFailsWithLongDNSKEYTTL(t *testing.T) {
	long := DefaultTTLs
	long.DNSKEY = 86400
	r := Explore(T2(long, long.NSParent+M))
	show(t, r)
	if r.OK() {
		t.Fatal("T2 with only the NS wait plus margin must fail when the DNSKEY TTL exceeds the margin")
	}
	if !Explore(T2(long, long.NSParent+long.DNSKEY)).OK() {
		t.Fatal("T2 with NS TTL + DNSKEY TTL must be safe")
	}
}

func TestT2NeedsNSPlusDNSKEYTTL(t *testing.T) {
	tt := DefaultTTLs
	w := minimalWait(func(h int) Plan { return T2(tt, h) }, 3*tt.NSParent)
	t.Logf("T2 minimal safe hold between parent NS = B and removing A's DS: %d s (NS %d + DNSKEY %d)", w, tt.NSParent, tt.DNSKEY)
	if w != tt.NSParent+tt.DNSKEY {
		t.Fatalf("expected NS TTL + DNSKEY TTL, got %d", w)
	}
}
