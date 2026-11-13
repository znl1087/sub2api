package tlsfingerprint

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// goldenPath points at the raw ClientHello captured from claude.exe 2.1.311.
// It lives inside the repo so the parity test is self-contained.
const goldenPath = "testdata/clienthello_real.bin"

// helloSummary is a parsed ClientHello, field by field.
type helloSummary struct {
	LegacyVersion   uint16
	SessionIDLen    int
	CipherSuites    []uint16
	Compression     []uint8
	ExtOrder        []uint16
	Groups          []uint16
	SignatureAlgs   []uint16
	KeyShares       []struct{ Group, Len uint16 }
	SupportedVers   []uint16
	ALPN            []string
	PointFormats    []uint8
	ServerName      string
	TotalLen        int
	RawExtLen       int
	RenegotiationIn []byte
	StatusRequest   []byte
}

// parseHello decodes a TLS record carrying a ClientHello.
func parseHello(b []byte) (*helloSummary, error) {
	if len(b) < 5+4+2+32 {
		return nil, fmt.Errorf("hello too short: %d", len(b))
	}
	if b[0] != 0x16 {
		return nil, fmt.Errorf("not a handshake record: %#x", b[0])
	}
	if b[5] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello: %#x", b[5])
	}
	s := &helloSummary{TotalLen: len(b)}
	s.LegacyVersion = uint16(b[9])<<8 | uint16(b[10])
	i := 43 // 5 record + 4 handshake + 2 version + 32 random

	s.SessionIDLen = int(b[i])
	i++
	if i+s.SessionIDLen > len(b) {
		return nil, fmt.Errorf("truncated session id")
	}
	i += s.SessionIDLen

	if i+2 > len(b) {
		return nil, fmt.Errorf("truncated cipher suites")
	}
	csLen := int(b[i])<<8 | int(b[i+1])
	i += 2
	for k := 0; k+1 < csLen; k += 2 {
		s.CipherSuites = append(s.CipherSuites, uint16(b[i+k])<<8|uint16(b[i+k+1]))
	}
	i += csLen

	if i >= len(b) {
		return nil, fmt.Errorf("truncated compression")
	}
	compLen := int(b[i])
	i++
	s.Compression = append(s.Compression, b[i:i+compLen]...)
	i += compLen

	if i+2 > len(b) {
		return nil, fmt.Errorf("no extensions block")
	}
	extLen := int(b[i])<<8 | int(b[i+1])
	i += 2
	s.RawExtLen = extLen
	end := i + extLen
	if end > len(b) {
		return nil, fmt.Errorf("extensions overrun: %d > %d", end, len(b))
	}

	for i+4 <= end {
		typ := uint16(b[i])<<8 | uint16(b[i+1])
		l := int(b[i+2])<<8 | int(b[i+3])
		i += 4
		if i+l > end {
			return nil, fmt.Errorf("ext %d overruns", typ)
		}
		d := b[i : i+l]
		s.ExtOrder = append(s.ExtOrder, typ)
		switch typ {
		case 0: // server_name
			if len(d) >= 5 {
				nl := int(d[3])<<8 | int(d[4])
				if 5+nl <= len(d) {
					s.ServerName = string(d[5 : 5+nl])
				}
			}
		case 10: // supported_groups
			if len(d) >= 2 {
				n := int(d[0])<<8 | int(d[1])
				for k := 0; k+1 < n; k += 2 {
					s.Groups = append(s.Groups, uint16(d[2+k])<<8|uint16(d[2+k+1]))
				}
			}
		case 11: // ec_point_formats
			if len(d) >= 1 {
				s.PointFormats = append(s.PointFormats, d[1:]...)
			}
		case 13: // signature_algorithms
			if len(d) >= 2 {
				n := int(d[0])<<8 | int(d[1])
				for k := 0; k+1 < n; k += 2 {
					s.SignatureAlgs = append(s.SignatureAlgs, uint16(d[2+k])<<8|uint16(d[2+k+1]))
				}
			}
		case 16: // alpn
			if len(d) >= 2 {
				p := 2
				for p < len(d) {
					pl := int(d[p])
					p++
					if p+pl > len(d) {
						break
					}
					s.ALPN = append(s.ALPN, string(d[p:p+pl]))
					p += pl
				}
			}
		case 43: // supported_versions
			if len(d) >= 1 {
				n := int(d[0])
				for k := 0; k+1 < n; k += 2 {
					s.SupportedVers = append(s.SupportedVers, uint16(d[1+k])<<8|uint16(d[1+k+1]))
				}
			}
		case 51: // key_share
			if len(d) >= 2 {
				n := int(d[0])<<8 | int(d[1])
				for k := 0; k+4 <= n; {
					g := uint16(d[2+k])<<8 | uint16(d[2+k+1])
					kl := uint16(d[2+k+2])<<8 | uint16(d[2+k+3])
					s.KeyShares = append(s.KeyShares, struct{ Group, Len uint16 }{g, kl})
					k += 4 + int(kl)
				}
			}
		case 65281:
			s.RenegotiationIn = d
		case 5:
			s.StatusRequest = d
		}
		i += l
	}
	if i != end {
		return nil, fmt.Errorf("extension walk ended at %d, want %d", i, end)
	}
	return s, nil
}

// captureClientHello dials a local listener with the real dialer and returns
// the ClientHello bytes it emits.
func captureClientHello(t *testing.T, profile *Profile, addr string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			ch <- result{err: err}
			return
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(conn, body); err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{b: append(hdr, body...)}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := NewDialer(profile, nil)
	done := make(chan struct{})
	go func() {
		_, _ = d.DialTLSContext(ctx, "tcp", ln.Addr().String())
		close(done)
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("capture: %v", r.err)
		}
		return r.b
	case <-time.After(6 * time.Second):
		t.Fatal("capture timeout")
	}
	return nil
}

func hexList[T uint16 | uint8](v []T) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%#x", x)
	}
	return strings.Join(parts, ",")
}

// TestClientHelloSNILeadsExtensionList checks that dialing a hostname puts
// server_name first, matching the real client, and that the payload is intact.
func TestClientHelloSNILeadsExtensionList(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			ch <- result{err: err}
			return
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(conn, body); err != nil {
			ch <- result{err: err}
			return
		}
		ch <- result{b: append(hdr, body...)}
	}()

	// Ignore the requested address and always connect to the local listener, so
	// the ClientHello carries a real hostname while the handshake stays local.
	base := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, _ = NewDialer(nil, base).DialTLSContext(ctx, "tcp", "api.anthropic.com:443") }()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("capture: %v", r.err)
		}
		s, err := parseHello(r.b)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(s.ExtOrder) == 0 || s.ExtOrder[0] != 0 {
			t.Fatalf("server_name must be the first extension, got order %s", hexList(s.ExtOrder))
		}
		if s.ServerName != "api.anthropic.com" {
			t.Errorf("SNI = %q, want api.anthropic.com", s.ServerName)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("capture timeout")
	}
}

// TestDumpEmittedHello writes the emitted ClientHello to disk so an external
// tool can compute the JA3/JA4 of the hostname form.
func TestDumpEmittedHello(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	out := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		out <- append(hdr, body...)
	}()

	base := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, _ = NewDialer(nil, base).DialTLSContext(ctx, "tcp", "api.anthropic.com:443") }()

	select {
	case b := <-out:
		dst := "testdata/our_clienthello.bin"
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("wrote %d bytes to %s", len(b), dst)
	case <-time.After(6 * time.Second):
		t.Fatal("timeout")
	}
}

// TestClientHelloParityAgainstRealCapture diffs the emitted ClientHello against
// the golden capture. SNI is expected to differ (the golden capture dialed an IP)
// and is reported separately.
func TestClientHelloParityAgainstRealCapture(t *testing.T) {
	goldenRaw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Skipf("golden capture not available: %v", err)
	}
	golden, err := parseHello(goldenRaw)
	if err != nil {
		t.Fatalf("parse golden: %v", err)
	}

	got, err := parseHello(captureClientHello(t, nil, ""))
	if err != nil {
		t.Fatalf("parse emitted: %v", err)
	}

	// Strip SNI from both sides before comparing extension order.
	stripSNI := func(s *helloSummary) []uint16 {
		out := make([]uint16, 0, len(s.ExtOrder))
		for _, e := range s.ExtOrder {
			if e != 0 {
				out = append(out, e)
			}
		}
		return out
	}

	var diffs []string
	cmp := func(name, want, have string) {
		if want != have {
			diffs = append(diffs, fmt.Sprintf("%s:\n  golden: %s\n  ours:   %s", name, want, have))
		}
	}

	cmp("legacy_version", fmt.Sprintf("%#x", golden.LegacyVersion), fmt.Sprintf("%#x", got.LegacyVersion))
	cmp("session_id_len", fmt.Sprint(golden.SessionIDLen), fmt.Sprint(got.SessionIDLen))
	cmp("cipher_suites", hexList(golden.CipherSuites), hexList(got.CipherSuites))
	cmp("compression", hexList(golden.Compression), hexList(got.Compression))
	cmp("extension_order", hexList(stripSNI(golden)), hexList(stripSNI(got)))
	cmp("supported_groups", hexList(golden.Groups), hexList(got.Groups))
	cmp("signature_algorithms", hexList(golden.SignatureAlgs), hexList(got.SignatureAlgs))
	cmp("supported_versions", hexList(golden.SupportedVers), hexList(got.SupportedVers))
	cmp("point_formats", hexList(golden.PointFormats), hexList(got.PointFormats))
	cmp("alpn", fmt.Sprint(golden.ALPN), fmt.Sprint(got.ALPN))
	cmp("renegotiation_info", hex.EncodeToString(golden.RenegotiationIn), hex.EncodeToString(got.RenegotiationIn))
	cmp("status_request", hex.EncodeToString(golden.StatusRequest), hex.EncodeToString(got.StatusRequest))

	// Key share groups and payload sizes must match exactly (the payload bytes
	// themselves are random per connection).
	gs, gk := "", ""
	for _, ks := range golden.KeyShares {
		gs += fmt.Sprintf("%#x:%d ", ks.Group, ks.Len)
	}
	for _, ks := range got.KeyShares {
		gk += fmt.Sprintf("%#x:%d ", ks.Group, ks.Len)
	}
	cmp("key_share", strings.TrimSpace(gs), strings.TrimSpace(gk))

	t.Logf("golden total=%d extlen=%d | ours total=%d extlen=%d",
		golden.TotalLen, golden.RawExtLen, got.TotalLen, got.RawExtLen)
	if got.ServerName != "" {
		t.Logf("SNI emitted by us: %q (golden dialed an IP, so none)", got.ServerName)
	}

	if len(diffs) > 0 {
		t.Errorf("ClientHello does not match the real capture (%d field(s)):\n%s",
			len(diffs), strings.Join(diffs, "\n"))
	}

	// Dialing an IP sends no SNI, so the byte counts must match exactly. When a
	// hostname is dialed the only delta allowed is the SNI extension itself.
	wantDelta := 0
	if got.ServerName != "" {
		wantDelta = 4 + 2 + 1 + 2 + len(got.ServerName)
	}
	if delta := got.TotalLen - golden.TotalLen; delta != wantDelta {
		t.Errorf("unexpected length delta %d (want %d for SNI %q)", delta, wantDelta, got.ServerName)
	}
}
