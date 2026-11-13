// Command tlsprobe prints the ClientHello fingerprint the gateway emits.
// It is a diagnostic tool: run it on the deployment host to verify parity with
// the real client without needing tcpdump inside the container.
package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

func main() {
	target := flag.String("target", "api.anthropic.com:443", "address to send the ClientHello to")
	flag.Parse()

	hello, err := capture(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capture failed: %v\n", err)
		os.Exit(1)
	}
	ja3, err := ja3Of(hello)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("len=%d ja3=%s\n", len(hello), ja3)
}

// capture dials target through the fingerprint dialer and returns the
// ClientHello bytes, without completing the handshake.
func capture(target string) ([]byte, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
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
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
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

	// Keep the requested hostname (for SNI) but always connect locally.
	base := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	go func() { _, _ = tlsfingerprint.NewDialer(nil, base).DialTLSContext(ctx, "tcp", target) }()

	select {
	case r := <-ch:
		return r.b, r.err
	case <-time.After(8 * time.Second):
		return nil, fmt.Errorf("timeout")
	}
}

// ja3Of computes the JA3 hash of a captured ClientHello.
func ja3Of(b []byte) (string, error) {
	if len(b) < 44 || b[0] != 0x16 || b[5] != 0x01 {
		return "", fmt.Errorf("not a ClientHello")
	}
	i := 43
	sid := int(b[i])
	i += 1 + sid
	csLen := int(b[i])<<8 | int(b[i+1])
	i += 2
	var ciphers []string
	for k := 0; k+1 < csLen; k += 2 {
		ciphers = append(ciphers, strconv.Itoa(int(b[i+k])<<8|int(b[i+k+1])))
	}
	i += csLen
	compLen := int(b[i])
	i += 1 + compLen
	extLen := int(b[i])<<8 | int(b[i+1])
	i += 2
	end := i + extLen
	var exts, groups, points []string
	for i+4 <= end {
		typ := int(b[i])<<8 | int(b[i+1])
		l := int(b[i+2])<<8 | int(b[i+3])
		i += 4
		d := b[i : i+l]
		switch typ {
		case 10:
			if len(d) >= 2 {
				n := int(d[0])<<8 | int(d[1])
				for k := 0; k+2 <= n; k += 2 {
					groups = append(groups, strconv.Itoa(int(d[2+k])<<8|int(d[2+k+1])))
				}
			}
		case 11:
			for _, p := range d[1:] {
				points = append(points, strconv.Itoa(int(p)))
			}
		}
		if typ != 0x0a0a && !isGREASE(typ) {
			exts = append(exts, strconv.Itoa(typ))
		}
		i += l
	}
	if i != end {
		return "", fmt.Errorf("malformed extensions")
	}
	raw := strings.Join([]string{
		"771",
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(groups, "-"),
		strings.Join(points, "-"),
	}, ",")
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:]), nil
}

func isGREASE(v int) bool {
	hi, lo := v>>8, v&0xff
	return hi == lo && hi&0x0f == 0x0a
}

var _ = sort.Ints
