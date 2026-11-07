package records

import (
	"strings"
	"testing"
)

// L3-1: a finding quotes record data (the mechanism or modifier name) despite the Finding contract.
func TestRT3FindingsNeverQuoteRecordData(t *testing.T) {
	for _, rec := range []string{
		`@ IN TXT "v=spf1 mx s3cr3t-token-abc:x -all"`,
		`@ IN TXT "v=spf1 mx s3cr3t-token-abc=x:y -all"`,
	} {
		_, got := read(t, rec)
		for _, fs := range got {
			for _, f := range fs {
				if strings.Contains(f.Message, "s3cr3t-token-abc") {
					t.Errorf("%s: message quotes record data: %q", rec, f.Message)
				}
			}
		}
	}
}

// L3-2: unknown modifiers take a macro-string (RFC 7208 section 6 / 12 ABNF: unknown-modifier = name "=" macro-string,
// macro-literal = %x21-24 / %x26-7E, may be empty). A valid record must not be a permerror (M-02).
func TestRT3SPFUnknownModifierAnyMacroString(t *testing.T) {
	for _, rec := range []string{
		`@ IN TXT "v=spf1 mx -all moo=1:2"`,
		`@ IN TXT "v=spf1 mx -all moo="`,
		`@ IN TXT "v=spf1 mx -all ver=a/b"`,
	} {
		if _, got := read(t, rec); len(got["M-02"]) > 0 {
			t.Errorf("%s: valid unknown modifier rejected: %+v", rec, got["M-02"])
		}
	}
}

// L3-3: redirect and exp MUST NOT appear more than once (RFC 7208 section 6): a permerror.
func TestRT3SPFDuplicateRedirect(t *testing.T) {
	if _, got := read(t, `@ IN TXT "v=spf1 redirect=a.example redirect=b.example"`); len(got["M-02"]) == 0 {
		t.Error("two redirect= modifiers must be M-02 (RFC 7208 6)")
	}
}

// L3-4: ip4/ip6 arguments are not checked: ip4-network ABNF (RFC 7208 5.6, 12); a syntax error is a permerror (4.6).
func TestRT3SPFBadIP4(t *testing.T) {
	for _, rec := range []string{
		`@ IN TXT "v=spf1 ip4:999.1.1.1 -all"`,
		`@ IN TXT "v=spf1 ip4:192.0.2.0/33 -all"`,
		`@ IN TXT "v=spf1 ip6:zz::1 -all"`,
		`@ IN TXT "v=spf1 all/24"`,
	} {
		if _, got := read(t, rec); len(got["M-02"]) == 0 {
			t.Errorf("%s: invalid term passes", rec)
		}
	}
}

// L3-5: an invalid sp= makes receivers fall back to p=none or no DMARC (RFC 7489 6.6.3 step 6).
func TestRT3DMARCInvalidSP(t *testing.T) {
	_, got := read(t, `_dmarc IN TXT "v=DMARC1; p=reject; sp=rejct"`)
	if len(got["M-06"]) == 0 {
		t.Error("sp=rejct is not a valid policy: want M-06")
	}
}

// L3-6: v= first with a value other than DKIM1 MUST be discarded (RFC 6376 3.6.1, v= tag).
func TestRT3DKIMWrongVersion(t *testing.T) {
	_, got := read(t, `s1._domainkey IN TXT "v=DKIM2; k=rsa; p=AAAA"`)
	if len(got["M-08"]) == 0 {
		t.Error("v=DKIM2 key record must be M-08")
	}
}

// L3-7: DKIM tag names are case-sensitive (RFC 6376 3.2): "P=" is not p=, so the record has no key.
func TestRT3DKIMTagCase(t *testing.T) {
	_, got := read(t, `s1._domainkey IN TXT "v=DKIM1; P=AAAA"`)
	if len(got["M-08"]) == 0 {
		t.Error("P= (upper case) is not the p= tag: want M-08")
	}
}

// L3-8: names under _domainkey that cannot be selectors (selector = sub-domain, RFC 6376 3.1 via RFC 5321 Let-dig
// first) such as the historic ADSP record (RFC 5617 4.2.1, _adsp._domainkey) are not DKIM keys: no M-08.
func TestRT3DKIMADSPIsNotASelector(t *testing.T) {
	p, got := read(t, `_adsp._domainkey IN TXT "dkim=all"`)
	if len(got["M-08"]) > 0 || len(p.DKIM) > 0 {
		t.Errorf("_adsp is not a selector: dkim=%+v m08=%+v", p.DKIM, got["M-08"])
	}
}

// control: the same record with v=DKIM1 and p= must pass, so the two tests above fail on the defect alone.
func TestRT3DKIMControl(t *testing.T) {
	if _, got := read(t, `s1._domainkey IN TXT "v=DKIM1; p=AAAA"`); len(got["M-08"]) > 0 {
		t.Fatalf("control fails: %+v", got["M-08"])
	}
}
