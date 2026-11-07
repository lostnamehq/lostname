package zone

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// CatalogMembers returns the member zones of a catalog zone (RFC 9432), sorted. The catalog must say version "2"
// (section 4.2.1: a consumer must not process a version it does not support). A member is the single PTR at
// <unique-id>.zones.<catalog> (section 4.3.1); an owner with more than one PTR is ignored, and a member listed under
// two ids is listed once. Member properties (group, coo) are not read.
func CatalogMembers(z *Zone) ([]string, error) {
	var version []string
	for _, r := range z.At("version."+z.Origin, "TXT") {
		version = append(version, strings.Join(r.RR().(*dns.TXT).Txt, ""))
	}
	if len(version) != 1 || version[0] != "2" {
		return nil, fmt.Errorf("%s: not a catalog zone of version 2 (version.%s TXT is %q): RFC 9432 4.2.1",
			z.Source, z.Origin, version)
	}
	base := ".zones." + z.Origin
	ptrs := map[string][]string{} // owner -> PTR targets
	for _, r := range z.Records {
		if r.Type != "PTR" || !strings.HasSuffix(r.Name, base) {
			continue
		}
		id := strings.TrimSuffix(r.Name, base)
		if strings.Contains(id, ".") {
			continue // a property below a member (group.<id>.zones..., coo.<id>.zones...), not a member
		}
		ptrs[r.Name] = append(ptrs[r.Name], strings.ToLower(dns.Fqdn(r.RR().(*dns.PTR).Ptr)))
	}
	seen := map[string]bool{}
	var out []string
	for _, targets := range ptrs {
		if len(targets) != 1 || seen[targets[0]] {
			continue
		}
		seen[targets[0]] = true
		out = append(out, targets[0])
	}
	sort.Slice(out, func(i, j int) bool { return CanonicalLess(out[i], out[j]) })
	return out, nil
}
