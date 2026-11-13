package tlsfingerprint

import (
	"bytes"
	"net"
	"os"
	"strings"
	"testing"
)

// realHeaderBlock 返回 2.1.323 真机抓包里的原始请求头块（含结尾空行）。
func realHeaderBlock(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/cccaptures/2.1.323/oauth/haiku-4-5.raw")
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatal("capture has no header terminator")
	}
	return raw[:idx+4]
}

// shuffleAndLower 把 header 块打乱顺序并把所有 header 名改成小写，
// 模拟 Go map 遍历 + setHeaderRaw 小写写出的效果。
func shuffleAndLower(block []byte) []byte {
	lines := bytes.Split(block, []byte("\r\n"))
	head := lines[0]
	var hs [][]byte
	for _, l := range lines[1:] {
		if len(l) == 0 {
			continue
		}
		colon := bytes.IndexByte(l, ':')
		if colon <= 0 {
			continue
		}
		lowered := append(bytes.ToLower(l[:colon]), l[colon:]...)
		hs = append(hs, lowered)
	}
	// 反序 + 交错，确保与目标顺序不同
	out := bytes.Join(hs, []byte("\r\n"))
	reversed := make([][]byte, 0, len(hs))
	for i := len(hs) - 1; i >= 0; i-- {
		reversed = append(reversed, hs[i])
	}
	out = bytes.Join(reversed, []byte("\r\n"))
	return append(append(append([]byte{}, head...), "\r\n"...), append(out, "\r\n\r\n"...)...)
}

func TestRewriteHeaderBlockMatchesRealCapture(t *testing.T) {
	want := realHeaderBlock(t)
	got := rewriteHeaderBlock(shuffleAndLower(want), nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("header block mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestRewriteHeaderBlockAddsKeepAlive(t *testing.T) {
	block := []byte("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\ncontent-type: application/json\r\nAuthorization: Bearer x\r\n\r\n")
	got := string(rewriteHeaderBlock(block, []byte(`{"a":1}`)))
	want := "POST /v1/messages HTTP/1.1\r\n" +
		"Authorization: Bearer x\r\n" +
		"Content-Type: application/json\r\n" +
		"Connection: keep-alive\r\n" +
		"Host: api.anthropic.com\r\n" +
		"\r\n" + `{"a":1}`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRewriteHeaderBlockKeepsClose(t *testing.T) {
	block := []byte("POST / HTTP/1.1\r\nconnection: close\r\nHost: h\r\n\r\n")
	got := string(rewriteHeaderBlock(block, nil))
	if strings.Count(got, "Connection:") != 1 || !strings.Contains(got, "Connection: close") {
		t.Fatalf("connection header mishandled: %q", got)
	}
	if strings.Contains(got, "keep-alive") {
		t.Fatalf("unexpected keep-alive: %q", got)
	}
}

// blockingConn 收集写入并允许注入读，用于验证 conn 层的分片处理。
type blockingConn struct {
	net.Conn
	written bytes.Buffer
}

func (c *blockingConn) Write(p []byte) (int, error) { return c.written.Write(p) }

func TestHeaderOrderConnAssemblesSplitHeader(t *testing.T) {
	inner := &blockingConn{}
	conn := WrapHeaderOrderConn(inner)

	parts := []string{
		"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n",
		"content-type: application/json\r\nx-app: cli\r\n",
		"\r\n",
		`{"model":"x"}`,
	}
	for _, p := range parts {
		if _, err := conn.Write([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	want := "POST /v1/messages HTTP/1.1\r\n" +
		"Content-Type: application/json\r\n" +
		"x-app: cli\r\n" +
		"Connection: keep-alive\r\n" +
		"Host: api.anthropic.com\r\n" +
		"\r\n" + `{"model":"x"}`
	if inner.written.String() != want {
		t.Fatalf("got %q want %q", inner.written.String(), want)
	}
}

// 请求体分片里出现 "\r\n\r\n" 时不能被当成新 header 块。
func TestHeaderOrderConnBodyWithBlankLinePassesThrough(t *testing.T) {
	inner := &blockingConn{}
	conn := WrapHeaderOrderConn(inner)
	conn.Write([]byte("POST / HTTP/1.1\r\nHost: h\r\n\r\n"))
	body := "line1\r\n\r\nline2"
	if n, err := conn.Write([]byte(body)); err != nil || n != len(body) {
		t.Fatalf("body write: n=%d err=%v", n, err)
	}
	if !strings.HasSuffix(inner.written.String(), body) {
		t.Fatalf("body mangled: %q", inner.written.String())
	}
}
