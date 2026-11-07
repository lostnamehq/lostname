package main

// Contract tests (L12): the JSON that lint, parity and config print must validate against the published schemas in
// docs/schemas, and every parity finding kind in the code must be in the schema's enum. The validator below covers
// only the keywords those schemas use; it refuses any other keyword, so a schema cannot quietly outgrow it.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"lostname.be/lostname/internal/authtest"
	"lostname.be/lostname/internal/zone"
)

func loadSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "schemas", name))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return s
}

func mustValidate(t *testing.T, schema string, out []byte) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(out))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if err := validate(loadSchema(t, schema), v, "$"); err != nil {
		t.Fatalf("%s: %v", schema, err)
	}
}

var known = map[string]bool{"$schema": true, "$id": true, "title": true, "description": true, "type": true,
	"const": true, "enum": true, "required": true, "properties": true, "additionalProperties": true, "items": true,
	"minItems": true, "minimum": true, "maximum": true, "minLength": true, "pattern": true}

func validate(s map[string]any, v any, at string) error {
	for k := range s {
		if !known[k] {
			return fmt.Errorf("%s: the test validator does not know the schema keyword %q", at, k)
		}
	}
	if c, ok := s["const"]; ok && fmt.Sprint(c) != fmt.Sprint(v) {
		return fmt.Errorf("%s: %v, want %v", at, v, c)
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range e {
			found = found || fmt.Sprint(x) == fmt.Sprint(v)
		}
		if !found {
			return fmt.Errorf("%s: %v is not one of %v", at, v, e)
		}
	}
	switch s["type"] {
	case "object":
		o, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want an object", at)
		}
		for _, r := range asList(s["required"]) {
			if _, ok := o[r.(string)]; !ok {
				return fmt.Errorf("%s: missing %q", at, r)
			}
		}
		props, _ := s["properties"].(map[string]any)
		for k, x := range o {
			if ps, ok := props[k].(map[string]any); ok {
				if err := validate(ps, x, at+"."+k); err != nil {
					return err
				}
				continue
			}
			switch ap := s["additionalProperties"].(type) {
			case bool:
				if !ap {
					return fmt.Errorf("%s: %q is not in the schema", at, k)
				}
			case map[string]any:
				if err := validate(ap, x, at+"."+k); err != nil {
					return err
				}
			}
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%s: want an array", at)
		}
		if m, ok := s["minItems"].(float64); ok && float64(len(a)) < m {
			return fmt.Errorf("%s: %d item(s), want at least %v", at, len(a), m)
		}
		if is, ok := s["items"].(map[string]any); ok {
			for i, x := range a {
				if err := validate(is, x, fmt.Sprintf("%s[%d]", at, i)); err != nil {
					return err
				}
			}
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("%s: want a string", at)
		}
		if m, ok := s["minLength"].(float64); ok && float64(len(str)) < m {
			return fmt.Errorf("%s: shorter than %v", at, m)
		}
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(str) {
			return fmt.Errorf("%s: %q does not match %s", at, str, p)
		}
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return fmt.Errorf("%s: want an integer", at)
		}
		i, err := n.Int64()
		if err != nil {
			return fmt.Errorf("%s: %v is not an integer", at, n)
		}
		if m, ok := s["minimum"].(float64); ok && float64(i) < m {
			return fmt.Errorf("%s: %d below %v", at, i, m)
		}
		if m, ok := s["maximum"].(float64); ok && float64(i) > m {
			return fmt.Errorf("%s: %d above %v", at, i, m)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("%s: want a boolean", at)
		}
	}
	return nil
}

func asList(v any) []any { l, _ := v.([]any); return l }

func runCLI(t *testing.T, args ...string) []byte {
	t.Helper()
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb); code == exitUsage {
		t.Fatalf("%v: usage error: %s", args, errb.String())
	}
	return out.Bytes()
}

func TestLintJSONFollowsItsSchema(t *testing.T) {
	for _, z := range []string{"broken.example.test.zone", "clean.example.test.zone"} {
		p := filepath.Join("..", "..", "internal", "lint", "testdata", z)
		mustValidate(t, "lint-report.schema.json", runCLI(t, "lint", "--zone", p, "--origin", "example.test", "--json"))
	}
}

func TestConfigJSONFollowsItsSchema(t *testing.T) {
	mustValidate(t, "config.schema.json", runCLI(t, "config"))
}

func TestParityJSONFollowsItsSchema(t *testing.T) {
	t.Parallel() // independent servers and temp dirs; seconds of probe and query timeouts each
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.53\n" +
		"www IN A 192.0.2.80\n"
	z, err := zone.Read(strings.NewReader(src), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	a := authtest.Start(t, z, authtest.None)
	zp := filepath.Join(t.TempDir(), "z.zone")
	cfg := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(zp, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	// Port 1 is never bound by these tests: the probes get no answer, as on a clean path, and a provider there is
	// unreachable, which gives gaps to validate too.
	conf := `{"schema":"lostname.config/v0","probe":{"canary":"127.0.0.1:1","canary_v6":"[::1]:1","timeout_seconds":1},` +
		`"parity":{"timeout_seconds":1}}`
	if err := os.WriteFile(cfg, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{a.Addr, "127.0.0.1:1"} {
		mustValidate(t, "parity-report.schema.json", runCLI(t, "parity", "--config", cfg, "--zone", zp,
			"--origin", "example.test", "--provider", "A="+a.Addr, "--provider", "B="+b, "--json"))
	}
}

// Every finding kind the parity code can emit is documented in the schema, and the schema lists no kind the code
// cannot emit.
func TestParityKindsMatchTheSchema(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "internal", "parity", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	// A kind is emitted as Finding{Sev, "kind", ...}, through ctx.finding(rep, Sev, "kind", ...), or returned by the
	// signature judge as "rrsig-...".
	re := regexp.MustCompile(`(?:Finding\{\w+, |finding\(rep, \w+, |return )"([a-z0-9]+(?:-[a-z0-9]+)+)"`)
	code := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			code[m[1]] = true
		}
	}
	s := loadSchema(t, "parity-report.schema.json")
	f := s["properties"].(map[string]any)["findings"].(map[string]any)["items"].(map[string]any)
	enum := map[string]bool{}
	for _, k := range f["properties"].(map[string]any)["kind"].(map[string]any)["enum"].([]any) {
		enum[k.(string)] = true
	}
	var missing, extra []string
	for k := range code {
		if !enum[k] {
			missing = append(missing, k)
		}
	}
	for k := range enum {
		if !code[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(code) == 0 || len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("parity kinds: %d in code; not in the schema %v; in the schema only %v", len(code), missing, extra)
	}
}

func TestMailReportMatchesTheSchema(t *testing.T) {
	src := "$ORIGIN example.test.\n$TTL 3600\n@ IN SOA ns1 h 1 7200 900 1209600 300\n@ IN NS ns1\n@ IN NS ns2\n" +
		"ns1 IN A 192.0.2.53\nns2 IN A 198.51.100.53\n@ IN MX 10 mx\nmx IN A 192.0.2.25\n" +
		"@ IN TXT \"v=spf1 mx -all\"\n_dmarc IN TXT \"v=DMARC1; p=none; rua=mailto:d@example.test\"\n" +
		"s1._domainkey IN TXT \"v=DKIM1; p=\"\n_mta-sts IN TXT \"v=STSv1; id=1\"\n" +
		"_smtp._tls IN TXT \"v=TLSRPTv1; rua=mailto:t@example.test\"\n_25._tcp.mx IN TLSA 3 1 1 " +
		strings.Repeat("AB", 32) + "\n"
	p := filepath.Join(t.TempDir(), "z.zone")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	out := runCLI(t, "mail", "--zone", p, "--origin", "example.test", "--json")
	mustValidate(t, "mail-report.schema.json", out)
	var r MailReport
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "pass" || r.Posture.DMARC == nil || r.Posture.DMARC.Policy != "none" || len(r.Posture.TLSA) != 1 ||
		len(r.Posture.DKIM) != 1 || !r.Posture.DKIM[0].Revoked {
		t.Fatalf("report %+v", r)
	}
	var o, e bytes.Buffer
	if code := run([]string{"mail", "--zone", p, "--origin", "example.test", "--strict"}, &o, &e); code != exitPass {
		t.Errorf("only a note (p=none): --strict still passes, got exit %d", code)
	}
}
