package watch

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// The keyed-hash zone label (docs/observability.md, "Zone names as labels"; decision of 2026-11-06): with a key, a
// zone's name never leaves watch. Its labels, event subjects and span attributes carry an id instead, HMAC-SHA-256 of
// the zone name under the deployer's key, stable per deployment and not reversible without the key. Owner names
// become relative to the zone ("www", "@"), because a full owner name contains the zone's name.

// ZoneID returns the id of zone under key: "z" and the first 32 hex digits (128 bits) of the HMAC.
func ZoneID(key []byte, zone string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(strings.ToLower(dnsName(zone))))
	return "z" + hex.EncodeToString(m.Sum(nil))[:32]
}

// relative returns name relative to zone: "@" for the apex, the labels below it otherwise, and "(outside the zone)"
// for a name that is not in it, which must not carry another name out either.
func relative(name, zone string) string {
	n, z := strings.ToLower(dnsName(name)), strings.ToLower(dnsName(zone))
	switch {
	case n == z:
		return "@"
	case strings.HasSuffix(n, "."+z):
		return strings.TrimSuffix(n, "."+z)
	}
	return "(outside the zone)"
}

// anonymise rewrites one result for the keyed-hash label: the zone becomes its id, finding owners and query names
// become relative. The result's maps and slices are copied, never changed in place.
func anonymise(key []byte, r CheckResult) CheckResult {
	zone := r.Zone
	r.Zone = ZoneID(key, zone)
	fs := make([]Finding, len(r.Findings))
	for i, f := range r.Findings {
		f.Name = relative(f.Name, zone)
		fs[i] = f
	}
	r.Findings = fs
	if r.Trace != nil {
		t := *r.Trace
		t.Exchanges = append(t.Exchanges[:0:0], t.Exchanges...)
		for i := range t.Exchanges {
			t.Exchanges[i].Name = relative(t.Exchanges[i].Name, zone)
		}
		r.Trace = &t
	}
	return r
}
