package main

import (
	"io"
	"strings"
	"unicode/utf8"
)

// safeWriter replaces control characters before they reach a terminal (L14): zone data and server answers can carry
// bytes that would move the cursor, recolour or rewrite earlier lines. Newline and tab pass; every other C0 and C1
// control, DEL and invalid UTF-8 become "?". JSON output never contains raw controls (encoding/json escapes them), and
// zone files written by the dns library escape them as \DDD, so only text that would be misread changes.
type safeWriter struct{ w io.Writer }

func (s safeWriter) Write(p []byte) (int, error) {
	if clean(p) {
		return s.w.Write(p)
	}
	n := len(p)
	var b strings.Builder
	for len(p) > 0 {
		r, size := utf8.DecodeRune(p)
		if r == utf8.RuneError && size <= 1 || unsafeRune(r) {
			b.WriteByte('?')
		} else {
			b.Write(p[:size])
		}
		p = p[size:]
	}
	if _, err := io.WriteString(s.w, b.String()); err != nil {
		return 0, err
	}
	return n, nil
}

func clean(p []byte) bool {
	for _, c := range p {
		if c < 0x20 && c != '\n' && c != '\t' || c >= 0x7f {
			return false // DEL, and every non-ASCII byte gets the slower rune check
		}
	}
	return true
}

func unsafeRune(r rune) bool {
	return r < 0x20 && r != '\n' && r != '\t' || r == 0x7f || r >= 0x80 && r <= 0x9f
}
