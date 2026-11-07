// Package zone is Lostname's neutral zone model (decision 0008): every input (zone files, AXFR, DNSControl,
// OpenTofu) is read into the same structure, and every check works on it. Reading never touches the network.
package zone

import (
	"bufio"
	"bytes"
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

// RecordMeta is the provider metadata on one record: its owner, type and metadata key names, sorted.
type RecordMeta struct {
	Name string   `json:"name"`
	Type string   `json:"type"`
	Keys []string `json:"keys"`
}

// RR returns the parsed record, for checks that need typed fields.
func (r Record) RR() dns.RR { return r.rr }

// Zone is a set of records under one origin, in a stable order.
type Zone struct {
	Origin  string   `json:"origin"`
	Source  string   `json:"source"` // where the records came from, e.g. "zonefile:example.test.zone"
	Records []Record `json:"records"`
	// Pseudo holds what a source has that is not a DNS record, such as DNSControl's ALIAS: a provider feature, kept
	// apart so no check mistakes it for data a resolver will see.
	Pseudo []Record `json:"pseudo,omitempty"`
	// Meta names the provider metadata a source attaches to records (DNSControl's meta: a proxy, geo or weighted
	// routing setting). Only the keys are kept: what the provider does with them is not DNS data.
	Meta []RecordMeta `json:"meta,omitempty"`
	// DNSSECIntent is what a config asks of its DNS provider: "on" (sign the zone), "off", or "" when the source
	// says nothing (a zone file, or a DNSControl config without AUTODNSSEC_ON or _OFF).
	DNSSECIntent string `json:"dnssec_intent,omitempty"`
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
// $INCLUDE and $GENERATE are refused (L14): a zone file under test must hold its records itself, and one $GENERATE
// line can expand to 65536 records that no export or provider shows the same way.
func Read(r io.Reader, name, origin string) (*Zone, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if n := generateLine(b); n > 0 {
		return nil, fmt.Errorf("%s:%d: $GENERATE is not supported: expand it into plain records (for example with "+
			"named-checkzone -D) and check that file", name, n)
	}
	zp := dns.NewZoneParser(bytes.NewReader(b), dns.Fqdn(origin), name)
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

// generateLine returns the 1-based line of the first $GENERATE directive, or 0.
func generateLine(b []byte) int {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), len(b)+1)
	for n := 1; sc.Scan(); n++ {
		// Red team 2, P1: the parser drops carriage returns, and parentheses outside quotes, before it reads a
		// directive, so "\r$GENERATE", "($GENERATE ...)" and "$GEN()ERATE" are directives too. Look at the line as the
		// parser sees it.
		raw := sc.Bytes()
		var seen []byte
		quoted := false
		for i, c := range raw {
			switch {
			case c == '"' && (i == 0 || raw[i-1] != '\\'):
				quoted = !quoted
			case !quoted && (c == '\r' || c == '(' || c == ')'):
				continue
			}
			seen = append(seen, c)
		}
		line := bytes.TrimLeft(seen, " \t")
		if len(line) >= 9 && strings.EqualFold(string(line[:9]), "$GENERATE") {
			return n
		}
	}
	return 0
}

// FromRRs builds a zone from parsed records, for inputs other than zone files (AXFR, provider exports).
func FromRRs(origin, source string, rrs []dns.RR) (*Zone, error) {
	origin = dns.Fqdn(strings.ToLower(origin))
	z := &Zone{Origin: origin, Source: source}
	for _, rr := range rrs {
		h := rr.Header()
		h.Name = strings.ToLower(h.Name)
		if h.Class != dns.ClassINET { // red team 2, P2: no IN resolver sees another class; it must not satisfy a check
			return nil, fmt.Errorf("%s: %s %s is in class %s: Lostname checks IN zones only; remove the record",
				source, h.Name, dns.Type(h.Rrtype).String(), dns.Class(h.Class).String())
		}
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
			return CanonicalLess(a.Name, b.Name)
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

// CanonicalLess orders names as DNSSEC does (RFC 4034 section 6.1): label by label from the right, case-folded.
// Escaped octets in labels are compared in their escaped form, which keeps the order for the names a zone file holds.
func CanonicalLess(a, b string) bool {
	la, lb := dns.SplitDomainName(strings.ToLower(a)), dns.SplitDomainName(strings.ToLower(b))
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
