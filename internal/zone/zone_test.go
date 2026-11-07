package zone

import (
	"strings"
	"testing"
)

// L13: a type the DNS library has no name for keeps its RFC 3597 name instead of an empty type.
func TestUnknownTypeKeepsItsName(t *testing.T) {
	z, err := Read(strings.NewReader("$ORIGIN example.test.\nx 3600 IN TYPE65534 \\# 3 010203\n"), "test", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Records) != 1 || z.Records[0].Type != "TYPE65534" {
		t.Fatalf("want one TYPE65534 record, got %+v", z.Records)
	}
	if got := z.At("x.example.test.", "TYPE65534"); len(got) != 1 {
		t.Fatalf("At by the RFC 3597 name found %d records", len(got))
	}
}

// L14: $GENERATE is refused with the line and a way forward; the same word inside data is not a directive.
func TestGenerateIsRefused(t *testing.T) {
	src := "$ORIGIN example.test.\n@ 3600 IN SOA ns h 1 1 1 1 1\n  $generate 1-65535 host$ A 192.0.2.1\n"
	_, err := Read(strings.NewReader(src), "gen.zone", "example.test")
	if err == nil || !strings.Contains(err.Error(), "gen.zone:3: $GENERATE is not supported") {
		t.Fatalf("want a refusal naming line 3, got %v", err)
	}
	ok := "$ORIGIN example.test.\nx 3600 IN TXT \"$GENERATE is just text here\"\n"
	if _, err := Read(strings.NewReader(ok), "txt.zone", "example.test"); err != nil {
		t.Fatalf("TXT data mentioning $GENERATE must parse: %v", err)
	}
}
