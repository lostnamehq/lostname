package probe

import (
	"net"
	"testing"
	"time"
)

// P3-7: a middlebox that completes the TCP handshake to the canary (where nothing can listen) and then drops or
// garbles the DNS exchange is still an interceptor; Answered requires a parsed DNS reply, so it reports a clean path.
func TestRT3TCPAcceptWithoutAnswerIsInterception(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte{0, 2, 0xde, 0xad}) // garbage, then close
			c.Close()
		}
	}()
	if got := Answered(l.Addr().String(), 500*time.Millisecond); len(got) == 0 {
		t.Errorf("BREAK: the canary accepted a TCP connection and replied with garbage; Answered says clean")
	}
}
