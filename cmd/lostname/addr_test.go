package main

import (
	"reflect"
	"testing"
)

// Provider and parent addresses: IPv4 and IPv6, with or without a port, get port 53 and brackets where needed.
func TestAddrList(t *testing.T) {
	got := addrList("192.0.2.1, 192.0.2.2:5353,2001:db8::1,[2001:db8::2],[2001:db8::3]:5353")
	want := []string{"192.0.2.1:53", "192.0.2.2:5353", "[2001:db8::1]:53", "[2001:db8::2]:53", "[2001:db8::3]:5353"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
