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
