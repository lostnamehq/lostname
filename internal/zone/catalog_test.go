package zone

import (
	"strings"
	"testing"
)

const catalogHead = "$ORIGIN catalog.invalid.\n$TTL 0\n@ IN SOA invalid. invalid. 1 3600 600 86400 0\n@ IN NS invalid.\n"

func readCatalog(t *testing.T, src string) ([]string, error) {
	t.Helper()
	z, err := Read(strings.NewReader(src), "test", "catalog.invalid")
	if err != nil {
		t.Fatal(err)
	}
	return CatalogMembers(z)
}

func TestCatalogMembers(t *testing.T) {
	got, err := readCatalog(t, catalogHead+"version IN TXT \"2\"\n"+
		"a1.zones IN PTR example.test.\n"+
		"b2.zones IN PTR Other.TEST.\n"+
		"group.b2.zones IN TXT \"edge\"\n"+ // a property, not a member
		"c3.zones IN PTR example.test.\n"+ // the same member under a second id: listed once
		"d4.zones IN PTR two.test.\nd4.zones IN PTR three.test.\n") // two PTRs at one id: ignored
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "example.test.,other.test." {
		t.Errorf("members %v, want example.test. and other.test.", got)
	}
}

func TestCatalogVersionRequired(t *testing.T) {
	for name, src := range map[string]string{
		"no version":   catalogHead + "a1.zones IN PTR example.test.\n",
		"version 1":    catalogHead + "version IN TXT \"1\"\na1.zones IN PTR example.test.\n",
		"two versions": catalogHead + "version IN TXT \"2\"\nversion IN TXT \"3\"\na1.zones IN PTR example.test.\n",
	} {
		if _, err := readCatalog(t, src); err == nil {
			t.Errorf("%s: accepted; RFC 9432 4.2.1 says a consumer must not process it", name)
		}
	}
}
