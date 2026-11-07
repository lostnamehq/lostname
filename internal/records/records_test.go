package records

import (
	"strings"
	"testing"

	"lostname.be/lostname/internal/zone"
)

const head = "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
	"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\n@ IN MX 10 mx.example.test.\nmx IN A 192.0.2.25\n"

func read(t *testing.T, extra string) (Posture, map[string][]Finding) {
	t.Helper()
	z, err := zone.Read(strings.NewReader(head+extra), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	p, fs := Read(z)
	got := map[string][]Finding{}
	for _, f := range fs {
		got[f.Rule] = append(got[f.Rule], f)
	}
	return p, got
}

func TestSPF(t *testing.T) {
	for _, tc := range []struct {
		name, rec, rule string
		sev             Severity
	}{
		{"good", `@ IN TXT "v=spf1 mx include:_spf.mail.example ip4:192.0.2.0/24 a/24 -all"`, "", ""},
		{"split strings join", `@ IN TXT "v=spf1 mx " "-all"`, "", ""},
		{"split inside a term joins without a space", `@ IN TXT "v=spf1 include:_spf.mail.exa" "mple -all"`, "", ""},
		{"two records", "@ IN TXT \"v=spf1 -all\"\n@ IN TXT \"v=spf1 mx -all\"", "M-01", Blocker},
		{"unknown mechanism", `@ IN TXT "v=spf1 mx foo:bar -all"`, "M-02", Blocker},
		{"include without domain", `@ IN TXT "v=spf1 include: -all"`, "M-02", Blocker},
		{"+all", `@ IN TXT "v=spf1 +all"`, "M-03", Risk},
		{"bare all is +all", `@ IN TXT "v=spf1 mx all"`, "M-03", Risk},
		{"ptr", `@ IN TXT "v=spf1 ptr -all"`, "M-04", Note},
		{"not SPF: prefix without a space", `@ IN TXT "v=spf10 -all"`, "", ""},
	} {
		p, got := read(t, tc.rec+"\n")
		if tc.rule == "" {
			if len(got) != 0 {
				t.Errorf("%s: unexpected %v", tc.name, got)
			}
			continue
		}
		if len(got[tc.rule]) != 1 || got[tc.rule][0].Severity != tc.sev {
			t.Errorf("%s: want one %s %s, got %v", tc.name, tc.rule, tc.sev, got)
		}
		_ = p
	}
	p, _ := read(t, `@ IN TXT "v=spf1 include:a.example include:b.example redirect=c.example ~all"`+"\n")
	if p.SPF == nil || p.SPF.All != "~" || strings.Join(p.SPF.Includes, ",") != "a.example,b.example" || p.SPF.Redirect != "c.example" {
		t.Errorf("SPF posture %+v", p.SPF)
	}
}

func TestDMARC(t *testing.T) {
	for _, tc := range []struct {
		name, rec, rule string
		sev             Severity
		policy          string
	}{
		{"reject", `_dmarc IN TXT "v=DMARC1; p=reject; rua=mailto:d@example.test"`, "", "", "reject"},
		{"none", `_dmarc IN TXT "v=DMARC1; p=none"`, "M-07", Note, "none"},
		{"two records", "_dmarc IN TXT \"v=DMARC1; p=reject\"\n_dmarc IN TXT \"v=DMARC1; p=none\"", "M-05", Blocker, ""},
		{"no policy is p=none (RFC 9989 4.7)", `_dmarc IN TXT "v=DMARC1; rua=mailto:d@example.test"`, "M-07", Note, ""},
		{"bad policy", `_dmarc IN TXT "v=DMARC1; p=block"`, "M-06", Risk, "block"},
		{"duplicate tag", `_dmarc IN TXT "v=DMARC1; p=reject; p=none"`, "M-06", Blocker, ""},
	} {
		p, got := read(t, tc.rec+"\n")
		if tc.rule == "" && len(got) != 0 || tc.rule != "" && (len(got[tc.rule]) != 1 || got[tc.rule][0].Severity != tc.sev) {
			t.Errorf("%s: want %q %s, got %v", tc.name, tc.rule, tc.sev, got)
		}
		if tc.policy != "" && (p.DMARC == nil || p.DMARC.Policy != tc.policy) {
			t.Errorf("%s: policy %+v", tc.name, p.DMARC)
		}
	}
}

func TestDKIMReadsOnlyWhatTheZoneHas(t *testing.T) {
	p, got := read(t, `sel1._domainkey IN TXT "v=DKIM1; k=ed25519; p=MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE="`+"\n"+
		`old._domainkey IN TXT "v=DKIM1; p="`+"\n"+
		"m365._domainkey IN CNAME m365._domainkey.mail.example.\n"+
		`bad._domainkey IN TXT "v=DKIM1; p=not*base64"`+"\n")
	sel := map[string]DKIM{}
	for _, k := range p.DKIM {
		sel[k.Selector] = k
	}
	if len(sel) != 4 || sel["sel1"].KeyType != "ed25519" || !sel["old"].Revoked || sel["m365"].Alias != "m365._domainkey.mail.example." {
		t.Fatalf("selectors %+v", p.DKIM)
	}
	if len(got["M-08"]) != 1 || got["M-08"][0].Name != "bad._domainkey.example.test." {
		t.Errorf("want one M-08 for the bad key, got %v", got)
	}
	// No selector in the zone: none is reported, and none is guessed.
	if p, _ := read(t, ""); len(p.DKIM) != 0 {
		t.Errorf("no DKIM in the zone, yet %+v", p.DKIM)
	}
}

func TestMTASTSAndTLSRPT(t *testing.T) {
	p, got := read(t, `_mta-sts IN TXT "v=STSv1; id=20261106T1200"`+"\n"+`_smtp._tls IN TXT "v=TLSRPTv1; rua=mailto:t@example.test,https://r.example/tls"`+"\n")
	if len(got) != 0 || p.MTASTS == nil || p.MTASTS.ID != "20261106T1200" || p.TLSRPT == nil || p.TLSRPT.Destinations != 2 {
		t.Fatalf("good records: %+v %+v %v", p.MTASTS, p.TLSRPT, got)
	}
	for _, tc := range []struct{ name, rec, rule string }{
		{"sts id too long", `_mta-sts IN TXT "v=STSv1; id=` + strings.Repeat("a", 33) + `"`, "M-09"},
		{"sts id with punctuation", `_mta-sts IN TXT "v=STSv1; id=2026-11-06"`, "M-09"},
		{"two sts", "_mta-sts IN TXT \"v=STSv1; id=a\"\n_mta-sts IN TXT \"v=STSv1; id=b\"", "M-09"},
		{"rpt without rua", `_smtp._tls IN TXT "v=TLSRPTv1"`, "M-10"},
		{"rpt bad scheme", `_smtp._tls IN TXT "v=TLSRPTv1; rua=ftp://r.example"`, "M-10"},
	} {
		if _, got := read(t, tc.rec+"\n"); len(got[tc.rule]) != 1 {
			t.Errorf("%s: want %s, got %v", tc.name, tc.rule, got)
		}
	}
}

func TestTLSAAndBIMI(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	p, got := read(t, "_25._tcp.mx IN TLSA 3 1 1 "+digest+"\n_25._tcp.mx IN TLSA 1 0 1 "+digest+"\n"+
		`default._bimi IN TXT "v=BIMI1; l=https://example.test/logo.svg"`+"\n")
	if len(p.TLSA) != 2 || len(p.BIMI) != 1 || p.BIMI[0].Selector != "default" {
		t.Fatalf("posture %+v %+v", p.TLSA, p.BIMI)
	}
	if len(got["M-11"]) != 1 || got["M-11"][0].Severity != Note {
		t.Errorf("usage 1 (PKIX-EE) is not for SMTP: want one M-11 note, got %v", got)
	}
}

// Findings never quote record data: a record can carry addresses, keys and report destinations.
func TestFindingsQuoteNoRecordData(t *testing.T) {
	_, got := read(t, `_dmarc IN TXT "v=DMARC1; p=none; rua=mailto:secret-reports@example.test"`+"\n"+
		`@ IN TXT "v=spf1 ip4:203.0.113.77 +all"`+"\n")
	for _, fs := range got {
		for _, f := range fs {
			if strings.Contains(f.Message, "secret-reports") || strings.Contains(f.Message, "203.0.113.77") {
				t.Errorf("record data in %s: %s", f.Rule, f.Message)
			}
		}
	}
}
