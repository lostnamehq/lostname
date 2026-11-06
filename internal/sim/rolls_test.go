package sim

import "testing"

func TestNaiveRollIsFoundUnsafe(t *testing.T) {
	r := Explore(NaiveRoll(DefaultTTLs))
	show(t, r)
	if r.OK() {
		t.Fatal("swapping key and DS together must be found unsafe")
	}
}

// Double-DS: the key switch needs every cached DS to include KSK 2 (one DS TTL); removing the old DS needs every
// cached DNSKEY RRset to hold KSK 2 (one DNSKEY TTL).
func TestDoubleDSMinimalWaits(t *testing.T) {
	tt := DefaultTTLs
	ds := minimalWait(func(h int) Plan { return DoubleDS(tt, h, 10*tt.DS) }, 3*tt.DS)
	key := minimalWait(func(h int) Plan { return DoubleDS(tt, 10*tt.DS, h) }, 3*tt.DS)
	t.Logf("double-DS: wait after the double DS %d s (DS TTL %d), after the key switch %d s (DNSKEY TTL %d)",
		ds, tt.DS, key, tt.DNSKEY)
	if ds != tt.DS || key != tt.DNSKEY {
		t.Fatalf("want DS TTL then DNSKEY TTL, got %d and %d", ds, key)
	}
}

// Double-signature: the DS swap needs every cached DNSKEY RRset to hold KSK 2 (one DNSKEY TTL); removing KSK 1
// needs every cached DS to point at KSK 2 (one DS TTL).
func TestDoubleSignatureMinimalWaits(t *testing.T) {
	tt := DefaultTTLs
	key := minimalWait(func(h int) Plan { return DoubleSignature(tt, h, 10*tt.DS) }, 3*tt.DS)
	ds := minimalWait(func(h int) Plan { return DoubleSignature(tt, 10*tt.DS, h) }, 3*tt.DS)
	t.Logf("double-signature: wait after both keys %d s (DNSKEY TTL %d), after the DS swap %d s (DS TTL %d)",
		key, tt.DNSKEY, ds, tt.DS)
	if key != tt.DNSKEY || ds != tt.DS {
		t.Fatalf("want DNSKEY TTL then DS TTL, got %d and %d", key, ds)
	}
}

// On .be with Domain Shield, the waits between parent changes (a DS TTL of a day plus margin) outlast the 24-hour
// unlock, so every parent change needs its own unlock.
func TestLocksAddOneUnlockPerParentChange(t *testing.T) {
	tt := DefaultTTLs
	cases := []struct {
		name string
		p    Plan
	}{
		{"T1", T1(tt, tt.DNSKEY+M)},
		{"T2", T2(tt, tt.NSParent+tt.DNSKEY+M)},
		{"double-DS", DoubleDS(tt, tt.DS+M, tt.DNSKEY+M)},
		{"double-sig", DoubleSignature(tt, tt.DNSKEY+M, tt.DS+M)},
	}
	for _, c := range cases {
		free, shield, guard := ScheduleWith(c.p, NoLock), ScheduleWith(c.p, DomainShield), ScheduleWith(c.p, DomainGuard)
		t.Logf("%-10s parent changes %d | no lock %5.1f h | Shield %5.1f h (%d unlocks) | Guard %5.1f h (%d unlocks)",
			c.name, free.ParentChanges, float64(free.Total)/3600, float64(shield.Total)/3600, shield.Unlocks,
			float64(guard.Total)/3600, guard.Unlocks)
		if shield.Unlocks != shield.ParentChanges || guard.Unlocks != guard.ParentChanges {
			t.Errorf("%s: want one unlock per parent change, got Shield %d and Guard %d for %d", c.name, shield.Unlocks,
				guard.Unlocks, shield.ParentChanges)
		}
		if guard.Total <= shield.Total || shield.Total <= free.Total {
			t.Errorf("%s: locks must lengthen the plan in order none < Shield < Guard", c.name)
		}
	}
}

// Under a registry lock the roll with fewer parent changes wins: double-signature changes the DS once, double-DS twice.
func TestDoubleSignatureNeedsFewerUnlocks(t *testing.T) {
	tt := DefaultTTLs
	dds := ScheduleWith(DoubleDS(tt, tt.DS+M, tt.DNSKEY+M), DomainGuard)
	dsig := ScheduleWith(DoubleSignature(tt, tt.DNSKEY+M, tt.DS+M), DomainGuard)
	if dsig.Unlocks >= dds.Unlocks || dsig.Total >= dds.Total {
		t.Fatalf("double-signature should need fewer unlocks and less time under Guard: %+v vs %+v", dsig, dds)
	}
}
