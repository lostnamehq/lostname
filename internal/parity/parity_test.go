package parity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/zone"
)

const base = `$ORIGIN example.test.
$TTL 3600
@          IN SOA   ns1.example.test. hostmaster.example.test. 1 7200 900 1209600 300
@          IN NS    ns1.example.test.
@          IN NS    ns2.example.test.
ns1        IN A     192.0.2.53
ns2        IN A     198.51.100.53
@          IN MX    10 mail.example.test.
mail       IN A     192.0.2.25
www        IN CNAME web.provider.invalid.
a.b        IN TXT   "deep"
sub        IN NS    ns.sub.example.test.
ns.sub     IN A     192.0.2.54
`

func zoneOf(t *testing.T, text string) *zone.Zone {
	t.Helper()
	z, err := zone.Read(strings.NewReader(text), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// quiet is a loopback port with nothing listening: the interception probe gets no answer, as on a clean path.
func quiet(t *testing.T) string {
	t.Helper()
	// Port 1 (tcpmux) is never bound by these tests. A freed ephemeral port could be reused by a parallel test's
	// server, which would then answer the probe and make the run flaky.
	return "127.0.0.1:1"
}

func run(t *testing.T, ref, other string, f authtest.Fault, model string) Report {
	t.Helper()
	a := authtest.Start(t, zoneOf(t, ref), authtest.None)
	b := authtest.Start(t, zoneOf(t, other), f)
	r := mustRun(t, zoneOf(t, ref), []Provider{{"A", []string{a.Addr}}, {"B", []string{b.Addr}}}, opts(t, model, quiet(t)))
	for _, x := range r.Findings {
		t.Logf("%s %s %s %s %s: %s", x.Severity, x.Kind, x.Name, x.Type, x.Provider, x.Detail)
	}
	if len(r.Gaps) > 0 {
		t.Logf("%d gap(s), first: %+v", len(r.Gaps), r.Gaps[0])
	}
	return r
}

func kinds(r Report) map[string]bool {
	k := map[string]bool{}
	for _, f := range r.Findings {
		k[f.Kind] = true
	}
	return k
}

func TestIdenticalProvidersPass(t *testing.T) {
	r := run(t, base, base, authtest.None, "T0")
	if r.Verdict != "pass" {
		t.Fatalf("verdict %s, want pass", r.Verdict)
	}
	if r.Questions < 10 {
		t.Fatalf("only %d questions: coverage too small", r.Questions)
	}
}

func TestMissingRecordFails(t *testing.T) {
	r := run(t, base, strings.Replace(base, "mail       IN A     192.0.2.25\n", "", 1), authtest.None, "T0")
	if r.Verdict != "fail" || !kinds(r)["record-missing"] {
		t.Fatalf("want fail with record-missing, got %s %v", r.Verdict, kinds(r))
	}
}

func TestChangedRecordFails(t *testing.T) {
	r := run(t, base, strings.Replace(base, "192.0.2.25", "192.0.2.99", 1), authtest.None, "T0")
	if r.Verdict != "fail" || !kinds(r)["rrset-differs"] {
		t.Fatalf("want fail with rrset-differs, got %s %v", r.Verdict, kinds(r))
	}
}

func TestTTLDifferenceFails(t *testing.T) {
	r := run(t, base, strings.Replace(base, "mail       IN A", "mail 300   IN A", 1), authtest.None, "T0")
	if r.Verdict != "fail" || !kinds(r)["ttl-differs"] {
		t.Fatalf("want fail with ttl-differs, got %s %v", r.Verdict, kinds(r))
	}
}

// H3: providers that agree with each other on data the zone file does not have must fail, not pass.
func TestProvidersAgreeingOnWrongDataFail(t *testing.T) {
	for _, c := range []struct{ name, served, kind string }{
		{"rdata", strings.Replace(base, "192.0.2.25", "192.0.2.99", 1), "zone-differs"},
		{"ttl", strings.Replace(base, "mail       IN A", "mail 300   IN A", 1), "ttl-differs-zone"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := authtest.Start(t, zoneOf(t, c.served), authtest.None)
			b := authtest.Start(t, zoneOf(t, c.served), authtest.None)
			r := mustRun(t, zoneOf(t, base), []Provider{{"A", []string{a.Addr}}, {"B", []string{b.Addr}}},
				opts(t, "T0", quiet(t)))
			if r.Verdict != "fail" || !kinds(r)[c.kind] || kinds(r)["rrset-differs"] || kinds(r)["ttl-differs"] {
				t.Fatalf("want fail with only %s, got %s %v", c.kind, r.Verdict, kinds(r))
			}
		})
	}
}

func TestApexNSDependsOnModel(t *testing.T) {
	other := strings.Replace(base, "@          IN NS    ns2.example.test.", "@          IN NS    ns3.example.test.", 1)
	if r := run(t, base, other, authtest.None, "T0"); r.Verdict != "pass" || !kinds(r)["apex-ns-differs"] {
		t.Fatalf("T0: apex NS may differ; got %s %v", r.Verdict, kinds(r))
	}
	if r := run(t, base, other, authtest.None, "T2"); r.Verdict != "fail" {
		t.Fatalf("T2: both providers serve both NS sets, a difference fails; got %s", r.Verdict)
	}
}

func TestSOAMinimumIsARisk(t *testing.T) {
	r := run(t, base, strings.Replace(base, "1209600 300", "1209600 3600", 1), authtest.None, "T0")
	if r.Verdict != "pass" || !kinds(r)["soa-minimum-differs"] {
		t.Fatalf("SOA MINIMUM is a risk, not a failure; got %s %v", r.Verdict, kinds(r))
	}
}

func TestENTAnsweredNXDOMAINFails(t *testing.T) {
	r := run(t, base, base, authtest.NXForENT, "T0")
	if r.Verdict != "fail" || !kinds(r)["ent-nxdomain"] {
		t.Fatalf("want fail with ent-nxdomain, got %s %v", r.Verdict, kinds(r))
	}
}

// F8 and P1: a lame or non-authoritative provider must never look like parity.
func TestLameProviderGivesNoVerdict(t *testing.T) {
	for _, f := range []authtest.Fault{authtest.Refuse, authtest.NoAA} {
		if r := run(t, base, base, f, "T0"); r.Verdict != "no_verdict" || len(r.Gaps) == 0 {
			t.Fatalf("fault %d: want no_verdict with gaps, got %s", f, r.Verdict)
		}
	}
}

// P1b and F10: an intercepted path gives no verdict without asking anything.
func TestInterceptedPathGivesNoVerdict(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	r := mustRun(t, zoneOf(t, base), []Provider{{"A", []string{a.Addr}}, {"B", []string{a.Addr}}}, opts(t, "T0", a.Addr))
	if r.Verdict != "no_verdict" || !r.Intercepted || r.Questions != 0 {
		t.Fatalf("want no_verdict before any question, got %+v", r)
	}
	// The report names what answered, for the probe.intercepted event: the canary, over both protocols here.
	if r.Interception == nil || r.Interception.Probe != a.Addr || strings.Join(r.Interception.Protocols, ",") != "udp,tcp" {
		t.Fatalf("want the interception named (%s over udp,tcp), got %+v", a.Addr, r.Interception)
	}
}

// M9: an IPv6 provider address brings the IPv6 probe in; with IPv4 addresses only, an IPv6-only middlebox is not
// consulted. The "IPv6 canary" here is a server that answers, as an intercepting middlebox would.
func TestIPv6ProbeFollowsTheProviderAddresses(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	o := opts(t, "T0", quiet(t))
	o.Canary6 = a.Addr
	r := mustRun(t, zoneOf(t, base), []Provider{{"A", []string{a.Addr}}, {"B", []string{a.Addr, "[2001:db8::99]:53"}}}, o)
	if r.Verdict != "no_verdict" || !r.Intercepted {
		t.Fatalf("an IPv6 provider address must bring in the IPv6 probe; got %s, intercepted %v", r.Verdict, r.Intercepted)
	}
	r = mustRun(t, zoneOf(t, base), []Provider{{"A", []string{a.Addr}}, {"B", []string{a.Addr}}}, o)
	if r.Intercepted {
		t.Fatal("with IPv4 addresses only, the IPv6 probe must not decide the run")
	}
}

func TestReportIsDeterministic(t *testing.T) {
	other := strings.Replace(base, "192.0.2.25", "192.0.2.99", 1)
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	b := authtest.Start(t, zoneOf(t, other), authtest.None)
	ps := []Provider{{"A", []string{a.Addr}}, {"B", []string{b.Addr}}}
	o := opts(t, "T0", quiet(t))
	j1, _ := json.Marshal(mustRun(t, zoneOf(t, base), ps, o))
	j2, _ := json.Marshal(mustRun(t, zoneOf(t, base), ps, o))
	if string(j1) != string(j2) {
		t.Fatal("two runs gave different reports")
	}
}

// RL-1: two servers of one provider with different serials is serial drift, a risk, not a hard failure.
func TestSerialDriftIsReported(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	b1 := authtest.Start(t, zoneOf(t, base), authtest.None)
	b2 := authtest.Start(t, zoneOf(t, strings.Replace(base, "hostmaster.example.test. 1 ", "hostmaster.example.test. 2 ", 1)), authtest.None)
	r := mustRun(t, zoneOf(t, base), []Provider{{"A", []string{a.Addr}}, {"B", []string{b1.Addr, b2.Addr}}},
		opts(t, "T0", quiet(t)))
	if r.Verdict != "pass" || !kinds(r)["serial-drift"] {
		t.Fatalf("want pass with serial-drift, got %s %v", r.Verdict, kinds(r))
	}
}

// L15: a provider whose own servers agree on the data but not on the TTL is inconsistent, not consistent.
func TestServersDifferingOnlyInTTLAreInconsistent(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	b1 := authtest.Start(t, zoneOf(t, base), authtest.None)
	b2 := authtest.Start(t, zoneOf(t, strings.Replace(base, "mail       IN A", "mail 300   IN A", 1)), authtest.None)
	r := mustRun(t, zoneOf(t, base), []Provider{{"A", []string{a.Addr}}, {"B", []string{b1.Addr, b2.Addr}}},
		opts(t, "T0", quiet(t)))
	if r.Verdict != "fail" || !kinds(r)["inconsistent-servers"] {
		t.Fatalf("want fail with inconsistent-servers, got %s %v", r.Verdict, kinds(r))
	}
}

func opts(t *testing.T, model, canary string) Options {
	t.Helper()
	return Options{Model: model, Timeout: 500 * time.Millisecond, EDNSBuffer: 1232, NXProbe: "lostname-nx-probe", Canary: canary,
		Canary6: canary, ProbeTimeout: 150 * time.Millisecond, Now: time.Now(), MinSigLife: 6 * time.Hour}
}

func mustRun(t *testing.T, z *zone.Zone, ps []Provider, o Options) Report {
	t.Helper()
	r, err := Run(z, ps, o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMissingOptionsAreRefused(t *testing.T) {
	if _, err := Run(zoneOf(t, base), nil, Options{}); err == nil {
		t.Fatal("a run without its settings must be refused, not filled with hidden defaults")
	}
}

// Red team round 1, HIGH 1 and 2: a provider without addresses, or a duplicate name, must never yield a pass.
func TestBadProviderListsAreRefused(t *testing.T) {
	a := authtest.Start(t, zoneOf(t, base), authtest.None)
	for name, ps := range map[string][]Provider{
		"no addresses": {{"A", []string{a.Addr}}, {"B", nil}},
		"duplicate":    {{"A", []string{a.Addr}}, {"A", []string{a.Addr}}},
		"only one":     {{"A", []string{a.Addr}}},
	} {
		if _, err := Run(zoneOf(t, base), ps, opts(t, "T0", quiet(t))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Red team round 1, MEDIUM 7: a wildcard zone answers the probe name; that is a note, not a failure.
func TestWildcardZoneProbeIsANote(t *testing.T) {
	wild := base + "*.w        IN A     192.0.2.80\n"
	r := run(t, wild, wild, authtest.None, "T0")
	if r.Verdict == "fail" {
		t.Fatalf("a wildcard must not fail the NX probe: %v", kinds(r))
	}
}

// L13: unknown types are asked about by number, never as type 0.
func TestRRTypeNames(t *testing.T) {
	for in, want := range map[string]uint16{"A": 1, "CAA": 257, "TYPE65534": 65534, "TYPEx": 0, "BOGUS": 0} {
		if got := rrtype(in); got != want {
			t.Errorf("rrtype(%q) = %d, want %d", in, got, want)
		}
	}
}

// L-20 on the providers' real addresses: two providers on one network fail together. A risk, never the verdict.
func TestSharedFateBetweenProviders(t *testing.T) {
	ps := func(a, b string) []Provider { return []Provider{{"A", []string{a}}, {"B", []string{b}}} }
	for _, tc := range []struct {
		name, a, b string
		want       int
	}{
		{"one address", "192.0.2.1:53", "192.0.2.1:53", 1},
		{"one /24", "192.0.2.1:53", "192.0.2.200:53", 1},
		{"one /48", "[2001:db8:1::1]:53", "[2001:db8:1:ff::1]:53", 1},
		{"apart", "192.0.2.1:53", "198.51.100.1:53", 0},
		{"apart, v6", "[2001:db8:1::1]:53", "[2001:db8:2::1]:53", 0},
	} {
		fs := sharedFate("example.test.", ps(tc.a, tc.b))
		if len(fs) != tc.want || (tc.want == 1 && (fs[0].Severity != Risk || fs[0].Provider != "B")) {
			t.Errorf("%s: %+v", tc.name, fs)
		}
	}
	if fs := sharedFate("example.test.", []Provider{{"A", []string{"192.0.2.1:53", "192.0.2.2:53"}}}); len(fs) != 0 {
		t.Errorf("one provider's own servers are L-20 offline (lint), not between providers: %+v", fs)
	}
}

// L-19: a parent that scans CDS installs whatever one provider publishes. Different sets fail; one-sided is a risk.
func TestCDSAcrossProviders(t *testing.T) {
	cds := func(tag string) string {
		return "@ IN CDS " + tag + " 13 2 " + strings.Repeat("AB", 32) + "\n"
	}
	kinds := func(a, b string) map[string]int {
		sa := authtest.Start(t, zoneOf(t, base+a), authtest.None)
		sb := authtest.Start(t, zoneOf(t, base+b), authtest.None)
		r := mustRun(t, zoneOf(t, base), []Provider{{"A", []string{sa.Addr}}, {"B", []string{sb.Addr}}},
			opts(t, "T0", "127.0.0.1:1"))
		got := map[string]int{}
		for _, f := range r.Findings {
			if strings.HasPrefix(f.Kind, "cds-") {
				got[f.Kind+"/"+string(f.Severity)]++
			}
		}
		return got
	}
	for _, tc := range []struct {
		name, a, b, want string
	}{
		{"same set", cds("11111"), cds("11111"), ""},
		{"none", "", "", ""},
		{"different sets", cds("11111"), cds("22222"), "cds-differs/fail"},
		{"one side only", cds("11111"), "", "cds-one-sided/risk"},
		{"other side only", "", cds("22222"), "cds-one-sided/risk"},
	} {
		got := kinds(tc.a, tc.b)
		if (tc.want == "" && len(got) != 0) || (tc.want != "" && (len(got) != 1 || got[tc.want] != 1)) {
			t.Errorf("%s: %v, want %q", tc.name, got, tc.want)
		}
	}
}

// L-19 inside one provider: its servers publish different CDS sets, so a scanning parent may install either.
func TestCDSWithinAProvider(t *testing.T) {
	cds := func(tag string) string { return "@ IN CDS " + tag + " 13 2 " + strings.Repeat("AB", 32) + "\n" }
	a1 := authtest.Start(t, zoneOf(t, base+cds("11111")), authtest.None)
	a2 := authtest.Start(t, zoneOf(t, base+cds("22222")), authtest.None)
	b := authtest.Start(t, zoneOf(t, base+cds("11111")), authtest.None)
	r := mustRun(t, zoneOf(t, base), []Provider{{"A", []string{a1.Addr, a2.Addr}}, {"B", []string{b.Addr}}},
		opts(t, "T0", "127.0.0.1:1"))
	for _, f := range r.Findings {
		if f.Kind == "cds-differs" && f.Provider == "A" && f.Severity == Fail {
			return
		}
	}
	t.Fatalf("A's two servers disagree on CDS: want cds-differs at A, got %+v", r.Findings)
}
