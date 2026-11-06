// Package probe detects a network path that answers DNS queries itself instead of passing them on (principle P1b,
// M0 finding F10). A query is sent to an address where no DNS server can exist; any answer means a middlebox (a VPN
// client, security software, a router or the ISP) is intercepting port 53, and no measurement over that path can
// be trusted.
package probe

import (
	"time"

	"github.com/miekg/dns"
)

// Intercepted reports whether a query to addr is answered over UDP or TCP. addr comes from the config (probe.canary,
// by default 203.0.113.1:53: TEST-NET-3, RFC 5737, documentation space where no server can exist); tests pass a
// local listener.
func Intercepted(addr string, timeout time.Duration) bool {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeSOA)
	for _, proto := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: proto, Timeout: timeout}
		if r, _, err := c.Exchange(q, addr); err == nil && r != nil {
			return true
		}
	}
	return false
}
