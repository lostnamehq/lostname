package zone

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// irFile is the part of `dnscontrol print-ir` output Lostname reads (DNSControl v5; the fixture in testdata is from
// v5.7.0). Lostname never runs DNSControl itself here: print-ir reads the credentials file, and Lostname never opens
// one (README, "The owner acts"). The owner runs print-ir and hands over its output.
type irFile struct {
	Domains []struct {
		Name       string `json:"name"`
		AutoDNSSEC string `json:"auto_dnssec"`
		Records    []struct {
			Type    string            `json:"type"`
			TypeNum uint16            `json:"typenum"`
			TTL     uint32            `json:"ttl"`
			Name    string            `json:"name"`
			Data    string            `json:"comparablev3"`
			Pos     string            `json:"filepos"`
			Meta    map[string]string `json:"meta"`
		} `json:"records"`
	} `json:"domains"`
}

// ReadDNSControlIR reads the domain origin from `dnscontrol print-ir` output. Records DNSControl defines itself
// (ALIAS and other pseudo-types, type numbers from 65280 up) go to Zone.Pseudo; everything else must parse as a DNS
// record, or the input is refused with the record's position in dnsconfig.js.
func ReadDNSControlIR(r io.Reader, name, origin string) (*Zone, error) {
	var f irFile
	d := json.NewDecoder(r)
	if err := d.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: not dnscontrol print-ir output: %v", name, err)
	}
	if d.More() { // red team 2, P6: a second JSON value would be ignored
		return nil, fmt.Errorf("%s: trailing data after the print-ir object", name)
	}
	origin = dns.Fqdn(strings.ToLower(origin))
	var found []string
	var match []int
	for i, dom := range f.Domains {
		if dns.Fqdn(strings.ToLower(dom.Name)) == origin {
			match = append(match, i)
		} else {
			found = append(found, dom.Name)
		}
	}
	switch len(match) {
	case 0:
		return nil, fmt.Errorf("%s has no domain %s (it has: %s)", name, origin, strings.Join(found, ", "))
	case 1:
	default: // red team 2, P6: which entry is the config would be a guess
		return nil, fmt.Errorf("%s has the domain %s %d times: give print-ir output with one", name, origin, len(match))
	}
	var rrs []dns.RR
	var pseudo []Record
	var meta []RecordMeta
	for _, rec := range f.Domains[match[0]].Records {
		// Red team 2, P6: the name and data are spliced into one presentation line, so they must be plain: a name of
		// letters, digits, '-', '_', '*' and '.', and data without line breaks.
		if rec.Name != "@" && !irName.MatchString(rec.Name) {
			return nil, fmt.Errorf("%s: record name %q at dnsconfig.js %s is not a plain DNS name", name, rec.Name, rec.Pos)
		}
		if strings.ContainsAny(rec.Data, "\r\n") {
			return nil, fmt.Errorf("%s: %s %s at dnsconfig.js %s has a line break in its data", name, rec.Name, rec.Type, rec.Pos)
		}
		owner := origin
		if rec.Name != "@" {
			owner = strings.ToLower(rec.Name) + "." + origin
		}
		// The type name decides; the number must agree with it (red team 2, P6: a CNAME numbered as a pseudo-type
		// would have dodged every check).
		if !irType.MatchString(rec.Type) { // red team 3, L3-9: the type reaches messages, SARIF and evidence
			return nil, fmt.Errorf("%s: record %q at dnsconfig.js %q has type %q, which is not a plain type name",
				name, owner, rec.Pos, rec.Type)
		}
		if len(rec.Meta) > 0 {
			m := RecordMeta{Name: owner, Type: rec.Type}
			for k := range rec.Meta {
				if !metaKey.MatchString(k) {
					return nil, fmt.Errorf("%s: %s %s at dnsconfig.js %s has metadata key %q that is not a plain name",
						name, owner, rec.Type, rec.Pos, k)
				}
				m.Keys = append(m.Keys, k)
			}
			sort.Strings(m.Keys)
			meta = append(meta, m)
		}
		num, standard := dns.StringToType[rec.Type]
		if !standard {
			pseudo = append(pseudo, Record{Name: owner, Type: rec.Type, TTL: rec.TTL, Data: rec.Data})
			continue
		}
		if num != rec.TypeNum {
			return nil, fmt.Errorf("%s: %s %s at dnsconfig.js %s has type number %d, not %d", name, owner, rec.Type,
				rec.Pos, rec.TypeNum, num)
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", owner, rec.TTL, rec.Type, rec.Data))
		if err != nil || rr == nil || rr.Header().Rrtype != num || !strings.EqualFold(rr.Header().Name, owner) {
			return nil, fmt.Errorf("%s: %s %s at dnsconfig.js %s is not a DNS record Lostname can read: %v",
				name, owner, rec.Type, rec.Pos, err)
		}
		rrs = append(rrs, rr)
	}
	z, err := FromRRs(origin, "dnscontrol-ir:"+name, rrs)
	if err != nil {
		return nil, err
	}
	z.Pseudo = pseudo
	z.Meta = meta
	z.DNSSECIntent = f.Domains[match[0]].AutoDNSSEC
	return z, nil
}

var irName = regexp.MustCompile(`^[A-Za-z0-9_*-]+(\.[A-Za-z0-9_*-]+)*$`)

// irType is a record type name as DNSControl writes it (A, CNAME, ALIAS, R53_ALIAS, CF_REDIRECT).
var irType = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,31}$`)

// metaKey is a DNSControl metadata key as providers name them (cloudflare_proxy, geo_region).
var metaKey = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
