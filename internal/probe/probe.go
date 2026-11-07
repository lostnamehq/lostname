// Package probe detects a network path that answers DNS queries itself instead of passing them on (principle P1b,
// M0 finding F10). A query is sent to an address where no DNS server can exist; any answer means a middlebox (a VPN
// client, security software, a router or the ISP) is intercepting port 53, and no measurement over that path can
// be trusted. IPv4 and IPv6 are separate paths (M9): a middlebox can catch one family and not the other, so each
// family a measurement uses is probed with its own address.
package probe

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

// Intercepted reports whether a query to addr is answered over UDP or TCP. addr comes from the config (probe.canary,
// by default 203.0.113.1:53, TEST-NET-3, RFC 5737; probe.canary_v6, by default [2001:db8::53]:53, RFC 3849: both
// documentation space where no server can exist); tests pass a local listener.
func Intercepted(addr string, timeout time.Duration) bool {
	return len(Answered(addr, timeout)) > 0
}

// Answered returns the protocols (udp, tcp) over which a query to addr got an answer: none on a clean path.
//
// Nothing can exist at a canary, so any reply counts, parsed or not (red team 3, P3-7): over UDP a datagram back,
// over TCP an accepted connection. A middlebox that accepts and then garbles or drops the exchange still intercepts.
func Answered(addr string, timeout time.Duration) []string {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeSOA)
	wire, err := q.Pack()
	if err != nil {
		return nil
	}
	var got []string
	if c, err := net.DialTimeout("udp", addr, timeout); err == nil {
		_ = c.SetDeadline(time.Now().Add(timeout))
		buf := make([]byte, 512)
		if _, err := c.Write(wire); err == nil {
			if n, err := c.Read(buf); err == nil && n > 0 {
				got = append(got, "udp")
			}
		}
		c.Close()
	}
	if c, err := net.DialTimeout("tcp", addr, timeout); err == nil {
		got = append(got, "tcp")
		c.Close()
	}
	return got
}

// Canaries returns the probe addresses for the address families that targets ("host:port") use: v4 for IPv4
// targets, v6 for IPv6 ones, and both for a host name, whose family the resolver decides.
func Canaries(targets []string, v4, v6 string) []string {
	var use4, use6 bool
	for _, t := range targets {
		host, _, err := net.SplitHostPort(t)
		if err != nil {
			host = t
		}
		ip := net.ParseIP(host)
		switch {
		case ip == nil:
			use4, use6 = true, true
		case ip.To4() != nil:
			use4 = true
		default:
			use6 = true
		}
	}
	var out []string
	if use4 {
		out = append(out, v4)
	}
	if use6 {
		out = append(out, v6)
	}
	return out
}

// AnyIntercepted probes each canary and returns the first that answered, or "".
func AnyIntercepted(canaries []string, timeout time.Duration) string {
	c, _ := FirstIntercepted(canaries, timeout)
	return c
}

// FirstIntercepted probes each canary and returns the first that answered with the protocols that answered, or "".
func FirstIntercepted(canaries []string, timeout time.Duration) (string, []string) {
	for _, c := range canaries {
		if got := Answered(c, timeout); len(got) > 0 {
			return c, got
		}
	}
	return "", nil
}
