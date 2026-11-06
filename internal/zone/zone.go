// Package zone is Lostname's neutral zone model (decision 0008): every input (zone files, AXFR, DNSControl,
// OpenTofu) is read into the same structure, and every check works on it. Reading never touches the network.
package zone

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Record is one resource record in presentation form. Names are lower-case and fully qualified.
type Record struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"` // the RDATA in presentation format
	rr   dns.RR
}

// RR returns the parsed record, for checks that need typed fields.
func (r Record) RR() dns.RR { return r.rr }

// Zone is a set of records under one origin, in a stable order.
type Zone struct {
	Origin  string   `json:"origin"`
	Source  string   `json:"source"` // where the records came from, e.g. "zonefile:example.test.zone"
	Records []Record `json:"records"`
}

// ReadFile reads an RFC 1035 zone file.
func ReadFile(path, origin string) (*Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f, path, origin)
}

// Read parses an RFC 1035 zone file from r; name is used in error messages and as the source label.
func Read(r io.Reader, name, origin string) (*Zone, error) {
	zp := dns.NewZoneParser(r, dns.Fqdn(origin), name)
	zp.SetIncludeAllowed(false) // a zone file must not pull in other files
	var rrs []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	return FromRRs(origin, "zonefile:"+name, rrs)
}

// FromRRs builds a zone from parsed records, for inputs other than zone files (AXFR, provider exports).
func FromRRs(origin, source string, rrs []dns.RR) (*Zone, error) {
	origin = dns.Fqdn(strings.ToLower(origin))
	z := &Zone{Origin: origin, Source: source}
	for _, rr := range rrs {
		h := rr.Header()
		h.Name = strings.ToLower(h.Name)
		if !dns.IsSubDomain(origin, h.Name) {
			return nil, fmt.Errorf("%s: %s is outside the origin %s", source, h.Name, origin)
		}
		// A record must survive its own presentation form, or a zone written by fetch could not be read by lint.
		// The parser accepts some records without data (meant for dynamic updates) that it cannot read back.
		if back, err := dns.NewRR(rr.String()); err != nil || back == nil || !dns.IsDuplicate(rr, back) {
			return nil, fmt.Errorf("%s: %s %s has data that cannot be written back in zone-file form: fix or remove it",
				source, h.Name, dns.Type(h.Rrtype).String())
		}
		z.Records = append(z.Records, Record{
			Name: h.Name,
			Type: dns.Type(h.Rrtype).String(),
			TTL:  h.Ttl,
			Data: strings.TrimPrefix(rr.String(), h.String()),
			rr:   rr,
		})
	}
	z.sort()
	return z, nil
}

func (z *Zone) sort() {
	sort.SliceStable(z.Records, func(i, j int) bool {
		a, b := z.Records[i], z.Records[j]
		if a.Name != b.Name {
			return canonicalLess(a.Name, b.Name)
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Data < b.Data
	})
}

// WriteZoneFile writes the zone in RFC 1035 presentation format, one record per line, in the zone's stable order.
func (z *Zone) WriteZoneFile(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "; source: %s\n$ORIGIN %s\n", z.Source, z.Origin); err != nil {
		return err
	}
	for _, r := range z.Records {
		if _, err := fmt.Fprintln(w, r.rr.String()); err != nil {
			return err
		}
	}
	return nil
}

// canonicalLess orders names by their labels from the right (RFC 4034 section 6.1, without the case and byte detail).
func canonicalLess(a, b string) bool {
	la, lb := dns.SplitDomainName(a), dns.SplitDomainName(b)
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if la[i] != lb[j] {
			return la[i] < lb[j]
		}
	}
	return len(la) < len(lb)
}

// At returns the records at name, optionally only of type t ("" for all).
func (z *Zone) At(name, t string) []Record {
	var out []Record
	for _, r := range z.Records {
		if r.Name == name && (t == "" || r.Type == t) {
			out = append(out, r)
		}
	}
	return out
}

// Delegations returns the names below the origin that carry NS records (zone cuts).
func (z *Zone) Delegations() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range z.Records {
		if r.Type == "NS" && r.Name != z.Origin && !seen[r.Name] {
			seen[r.Name] = true
			out = append(out, r.Name)
		}
	}
	return out
}
