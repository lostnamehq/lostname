package lint

// Diff compares findings with a baseline (model AU-2, `lint --baseline`): worse holds the findings that are new or
// whose severity rose, fixed holds the baseline findings that are gone. A finding is the same finding when its rule,
// name, type and message are equal; severity is compared, not matched, so a raised severity counts as worse and a
// lowered one as neither.
func Diff(baseline, now []Finding) (worse, fixed []Finding) {
	key := func(f Finding) string { return f.Rule + "\x00" + f.Name + "\x00" + f.Type + "\x00" + f.Message }
	before := map[string]Severity{}
	for _, f := range baseline {
		if s, ok := before[key(f)]; !ok || f.Severity.rank() > s.rank() {
			before[key(f)] = f.Severity
		}
	}
	seen := map[string]bool{}
	for _, f := range now {
		seen[key(f)] = true
		// Red team 2, P5: L-00 says the input is not a zone at all; no baseline may make that a pass.
		if s, ok := before[key(f)]; !ok || f.Severity.rank() > s.rank() || f.Rule == "L-00" {
			worse = append(worse, f)
		}
	}
	for _, f := range baseline {
		if !seen[key(f)] {
			fixed = append(fixed, f)
			seen[key(f)] = true // a duplicate in the baseline is fixed once
		}
	}
	return worse, fixed
}
