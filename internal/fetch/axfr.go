// Package fetch reads a zone from a live server by zone transfer (AXFR), fail-closed:
//   - the transfer must begin and end with the same SOA (RFC 5936 section 2.2);
//   - with TSIG the signatures are verified on every message;
//   - without TSIG the path is first checked for interception (package probe), and an intercepted path gives no
//     verdict instead of a zone.
package fetch

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"lostname.be/lostname/internal/probe"
	"lostname.be/lostname/internal/zone"
)

// ErrNoVerdict means the result cannot be trusted (P1, P1b); the command exits 2.
var ErrNoVerdict = errors.New("no verdict")

// TSIG is a transaction key. Algorithm is a name such as hmac-sha256; Secret is base64.
type TSIG struct {
	Name, Algorithm, Secret string
}

// ReadTSIGFile reads a key from a file with one line "algorithm name secret", so the secret never appears in argv.
func ReadTSIGFile(path string) (*TSIG, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s: want one line \"algorithm name secret\"", path)
		}
		return &TSIG{Algorithm: dns.Fqdn(strings.ToLower(parts[0])), Name: dns.Fqdn(strings.ToLower(parts[1])),
			Secret: parts[2]}, nil
	}
	return nil, fmt.Errorf("%s: no key found", path)
}

// Options control a transfer. All but TSIG are required and come from the config (fetch.timeout_seconds,
// probe.canary, probe.timeout_seconds).
type Options struct {
	TSIG         *TSIG
	Timeout      time.Duration
	Canary       string
	ProbeTimeout time.Duration
}

// AXFR transfers origin from server ("host:port") and returns it as a zone.
func AXFR(server, origin string, o Options) (*zone.Zone, error) {
	if o.Timeout <= 0 || o.Canary == "" || o.ProbeTimeout <= 0 {
		return nil, errors.New("fetch: timeout, probe address and probe timeout are required (set them in the config)")
	}
	if o.TSIG == nil {
		canary := o.Canary
		if probe.Intercepted(canary, o.ProbeTimeout) {
			return nil, fmt.Errorf("%w: something on this network answers DNS for any address (probe %s); "+
				"an unsigned transfer over this path cannot be trusted. Use TSIG or another network", ErrNoVerdict, canary)
		}
	}
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(origin))
	t := &dns.Transfer{DialTimeout: o.Timeout, ReadTimeout: o.Timeout, WriteTimeout: o.Timeout}
	if o.TSIG != nil {
		t.TsigSecret = map[string]string{o.TSIG.Name: o.TSIG.Secret}
		m.SetTsig(o.TSIG.Name, o.TSIG.Algorithm, 300, time.Now().Unix())
	}
	env, err := t.In(m, server)
	if err != nil {
		// M5: the server could not be reached or refused; that is a missing measurement, not a usage error.
		return nil, fmt.Errorf("%w: transfer from %s failed: %v", ErrNoVerdict, server, err)
	}
	var rrs []dns.RR
	for e := range env {
		if e.Error != nil {
			if errors.Is(e.Error, dns.ErrSig) || errors.Is(e.Error, dns.ErrTime) || errors.Is(e.Error, dns.ErrKey) ||
				strings.Contains(e.Error.Error(), "signature") {
				return nil, fmt.Errorf("%w: TSIG verification failed: %v", ErrNoVerdict, e.Error)
			}
			return nil, fmt.Errorf("%w: transfer from %s failed: %v", ErrNoVerdict, server, e.Error)
		}
		rrs = append(rrs, e.RR...)
	}
	if err := checkSOAFrame(rrs); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoVerdict, err)
	}
	// The closing SOA repeats the first; keep one copy.
	return zone.FromRRs(origin, "axfr:"+server, rrs[:len(rrs)-1])
}

func checkSOAFrame(rrs []dns.RR) error {
	if len(rrs) < 2 {
		return errors.New("transfer too short to be complete")
	}
	first, ok1 := rrs[0].(*dns.SOA)
	last, ok2 := rrs[len(rrs)-1].(*dns.SOA)
	if !ok1 || !ok2 {
		return errors.New("transfer does not begin and end with an SOA")
	}
	if first.Serial != last.Serial {
		return fmt.Errorf("SOA serial changed during the transfer (%d, then %d)", first.Serial, last.Serial)
	}
	return nil
}
