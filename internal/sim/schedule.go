package sim

// Lock is a registry lock on the domain at the parent. Every parent change (DS or NS) needs an unlock first. Latency
// is the time from asking to unlocked; Window is how long an unlock lasts and may cover several changes (0: the
// unlock covers one change only).
//   - Domain Shield (.be): the registrar's shield users unlock for 24 hours, then it re-locks by itself.
//   - Domain Guard (.be): DNS Belgium phones a named person for each change request and answers within 2 working
//     days; the registrar then has 48 hours to make that one change.
//
// Profiles and their sources live in the config (sim.locks); nothing here assumes them.
type Lock struct {
	Name    string
	Latency int
	Window  int
}

// Schedule is the plan's timeline once parent changes wait for unlocks.
type Schedule struct {
	Total         int // seconds from the first change to the end of the last hold
	ParentChanges int // steps that change the parent's DS or NS
	Unlocks       int // unlock requests needed
}

func sameKeys(a, b []Key) bool {
	if len(a) != len(b) {
		return false
	}
	for _, k := range a {
		if !has(b, k) {
			return false
		}
	}
	return true
}

func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, n := range a {
		seen[n] = true
	}
	for _, n := range b {
		if !seen[n] {
			return false
		}
	}
	return true
}

// Plan timers start when a change is observed at every parent server, not when it is requested: the parent's
// publication delay is measured, never assumed (model section 5c).
func ScheduleWith(p Plan, l Lock) Schedule {
	var s Schedule
	t, windowEnd := 0, -1
	for i := 1; i < len(p.Steps); i++ {
		prev, cur := p.Steps[i-1].World, p.Steps[i].World
		if !sameKeys(prev.ParentDS, cur.ParentDS) || !sameNames(prev.ParentNS, cur.ParentNS) {
			s.ParentChanges++
			if l.Latency > 0 && t >= windowEnd {
				t += l.Latency
				s.Unlocks++
				windowEnd = t + l.Window
			}
		}
		t += p.Steps[i].Hold
	}
	s.Total = t
	return s
}
