package sim

import "testing"

// RL-4: the safe plans stay safe whatever the DNSKEY TTL, and lowering it never lengthens an exit. With a long DNSKEY
// TTL (a day, common for offline signers) lowering it to 5 minutes shortens the signed exits; T0 has no DNSKEY and
// gains nothing.
func TestPreStagingAdvice(t *testing.T) {
	tt := DefaultTTLs
	tt.DNSKEY = 86400
	for _, name := range []string{"T0", "T1", "T2"} {
		for _, l := range []Lock{NoLock, DomainShield} {
			a, err := PreStage(name, tt, 300, l)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%-13s %s", l.Name, a)
			if !a.SafeAtLower {
				t.Errorf("%s under %s: the safe plan must stay safe at the lower TTL", name, l.Name)
			}
			if a.Saving() < 0 {
				t.Errorf("%s under %s: lowering the DNSKEY TTL lengthened the exit by %d s", name, l.Name, -a.Saving())
			}
			if name == "T0" && (a.Saving() != 0 || a.PreStage != 0) {
				t.Errorf("T0 has no DNSKEY, but lowering it saved %d s after a %d s wait", a.Saving(), a.PreStage)
			}
			// .be defaults: T2 gains three DNSKEY TTLs and is worth the wait; T1 gains just under one and is not.
			if (name == "T2") != a.Worth() {
				t.Errorf("%s under %s: worth %v", name, l.Name, a.Worth())
			}
			if name != "T0" && a.Saving() <= 0 {
				t.Errorf("%s: a day-long DNSKEY TTL lowered to 5 minutes must save time", name)
			}
		}
	}
	if _, err := PreStage("T9", tt, 300, NoLock); err == nil {
		t.Error("an unknown exit model must be refused")
	}
	if _, err := PreStage("T1", tt, tt.DNSKEY+1, NoLock); err == nil {
		t.Error("a 'lowered' TTL above the current one must be refused")
	}
}
