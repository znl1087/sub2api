//go:build integration

package tlsfingerprint

import (
	"bufio"
	"context"
	"net/http"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TestRealHandshakeAgainstAnthropic verifies the hardened ClientHello still
// completes a real TLS 1.3 handshake with the upstream.
func TestRealHandshakeAgainstAnthropic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := NewDialer(nil, nil).DialTLSContext(ctx, "tcp", "api.anthropic.com:443")
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer conn.Close()

	type stater interface{ ConnectionState() utls.ConnectionState }
	s, ok := conn.(stater)
	if !ok {
		t.Fatalf("connection is %T, want a TLS conn", conn)
	}
	st := s.ConnectionState()
	t.Logf("version=%#x cipher=%#x alpn=%q", st.Version, st.CipherSuite, st.NegotiatedProtocol)
	if st.Version != 0x0304 {
		t.Errorf("negotiated version %#x, want TLS 1.3", st.Version)
	}
	if st.CipherSuite != 0x1301 && st.CipherSuite != 0x1302 && st.CipherSuite != 0x1303 {
		t.Errorf("negotiated non-TLS1.3 cipher %#x", st.CipherSuite)
	}

	// Send a real request over the connection to prove the record layer works.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.anthropic.com/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("anthropic-version", "2023-06-01")
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	t.Logf("status=%d", resp.StatusCode)
	if resp.StatusCode == 0 {
		t.Error("no status")
	}
}
