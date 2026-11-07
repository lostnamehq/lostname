package main

import (
	"bytes"
	"testing"
)

func TestSafeWriterNeutralisesControls(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain line\n", "plain line\n"},
		{"tab\tand newline\n", "tab\tand newline\n"},
		{"esc \x1b[31mred\x1b[0m\n", "esc ?[31mred?[0m\n"},
		{"bell\a and cr\r\n", "bell? and cr?\n"},
		{"del \x7f", "del ?"},
		{"c1 \u009b2J", "c1 ?2J"},
		{"bad utf-8 \xff\xfe", "bad utf-8 ??"},
		{"accents stay: é ü ç €", "accents stay: é ü ç €"},
	} {
		var b bytes.Buffer
		n, err := safeWriter{&b}.Write([]byte(c.in))
		if err != nil || n != len(c.in) {
			t.Fatalf("%q: wrote %d of %d, %v", c.in, n, len(c.in), err)
		}
		if b.String() != c.want {
			t.Errorf("%q: got %q, want %q", c.in, b.String(), c.want)
		}
	}
}
