package tlsfingerprint

import (
	"bytes"
	"net"
)

// headerWireOrder 是真机 Claude CLI (claude-cli 2.1.31x/2.1.32x) 请求头的
// 精确发送顺序，取自 testdata/cccaptures 下全部抓包（每个版本 6 个模型，
// 顺序完全一致）。
//
// 前 17 项是 undici Headers 的 ASCII 排序结果（大写字母先于小写），最后 4 项
// 由 Node 的 http 传输层按固定顺序追加。Go 的 http.Header 是 map，写出顺序随机，
// 所以在 conn 层重排：这是唯一能既保留 utls 指纹又控制 wire 顺序的位置。
//
// 键一律小写；值即该 header 在 wire 上的真实大小写。
var headerWireOrder = [][2]string{
	{"accept", "Accept"},
	{"authorization", "Authorization"},
	{"content-type", "Content-Type"},
	{"user-agent", "User-Agent"},
	{"x-claude-code-session-id", "X-Claude-Code-Session-Id"},
	{"x-stainless-arch", "X-Stainless-Arch"},
	{"x-stainless-lang", "X-Stainless-Lang"},
	{"x-stainless-os", "X-Stainless-OS"},
	{"x-stainless-package-version", "X-Stainless-Package-Version"},
	{"x-stainless-retry-count", "X-Stainless-Retry-Count"},
	{"x-stainless-runtime", "X-Stainless-Runtime"},
	{"x-stainless-runtime-version", "X-Stainless-Runtime-Version"},
	{"x-stainless-timeout", "X-Stainless-Timeout"},
	{"anthropic-beta", "anthropic-beta"},
	{"anthropic-dangerous-direct-browser-access", "anthropic-dangerous-direct-browser-access"},
	{"anthropic-version", "anthropic-version"},
	{"x-app", "x-app"},
}

// headerWireTailOrder 是传输层追加的尾部四项，顺序固定。
var headerWireTailOrder = []string{"connection", "host", "accept-encoding", "content-length"}

// headerWireOrderIndex 把 headerWireOrder 压成 lowercase -> (序号, wire 大小写)。
var headerWireOrderIndex = func() map[string]struct {
	idx   int
	cased string
} {
	m := make(map[string]struct {
		idx   int
		cased string
	}, len(headerWireOrder))
	for i, kv := range headerWireOrder {
		m[kv[0]] = struct {
			idx   int
			cased string
		}{i, kv[1]}
	}
	return m
}()

var headerWireTailIndex = func() map[string]int {
	m := make(map[string]int, len(headerWireTailOrder))
	for i, k := range headerWireTailOrder {
		m[k] = i
	}
	return m
}()

// maxPendingHeaderBytes 是累积 header 块的上限。正常请求头不到 1KB，
// 超过这个量说明判断错了，直接原样放行，避免把 body 永久扣在缓冲区里。
const maxPendingHeaderBytes = 64 << 10

// requestLinePrefixes 用于识别一个写入缓冲区是否以 HTTP 请求行开头。
// 请求体是 JSON（以 '{' 或 '[' 起始），不会与这些前缀冲突。
var requestLinePrefixes = [][]byte{
	[]byte("POST "), []byte("GET "), []byte("PUT "),
	[]byte("PATCH "), []byte("DELETE "), []byte("HEAD "), []byte("OPTIONS "),
}

// WrapHeaderOrderConn 包装一条已握手的 TLS 连接，使写出的每个请求头块按真机
// Claude CLI 的顺序与大小写重排，并在缺失时补 Connection: keep-alive。
//
// 只改明文 HTTP 层，TLS 握手（ClientHello / JA3）不受影响。
func WrapHeaderOrderConn(c net.Conn) net.Conn {
	if c == nil {
		return c
	}
	return &headerOrderConn{Conn: c}
}

type headerOrderConn struct {
	net.Conn
	pending []byte // 未写完的 header 块
}

func (c *headerOrderConn) Write(p []byte) (int, error) {
	// 已有待处理块，或本次写入看起来是请求行开头 → 进入 header 累积。
	if len(c.pending) > 0 || startsWithRequestLine(p) {
		c.pending = append(c.pending, p...)
		if idx := bytes.Index(c.pending, []byte("\r\n\r\n")); idx >= 0 {
			out := rewriteHeaderBlock(c.pending[:idx+4], c.pending[idx+4:])
			c.pending = nil
			if _, err := c.Conn.Write(out); err != nil {
				return 0, err
			}
			return len(p), nil
		}
		if len(c.pending) > maxPendingHeaderBytes {
			out := c.pending
			c.pending = nil
			if _, err := c.Conn.Write(out); err != nil {
				return 0, err
			}
		}
		// 已吸收但尚未落盘，按 bufio 语义报告整段写完。
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func startsWithRequestLine(p []byte) bool {
	for _, prefix := range requestLinePrefixes {
		if bytes.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// rewriteHeaderBlock 把 header 块（含结尾空行）重排为真机顺序。
// rest 是同一缓冲区里紧跟 header 的请求体片段，原样接在末尾。
func rewriteHeaderBlock(block, rest []byte) []byte {
	lines := bytes.Split(block, []byte("\r\n"))
	if len(lines) == 0 {
		return block
	}
	// lines[0] 是请求行；尾部会切出一个空串（block 以 \r\n\r\n 结尾）。
	requestLine := lines[0]

	type hline struct {
		lower string
		raw   []byte
	}
	var unknown []*hline
	var tail [4]*hline
	haveConnection := false

	knownSlots := make([]*hline, len(headerWireOrder))
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		h := &hline{lower: string(bytes.ToLower(line[:colon])), raw: line}
		if slot, ok := headerWireOrderIndex[h.lower]; ok {
			cased := []byte(slot.cased + ":")
			h.raw = append(cased, line[colon+1:]...)
			knownSlots[slot.idx] = h
			continue
		}
		if slot, ok := headerWireTailIndex[h.lower]; ok {
			cased := []byte(canonicalTailName(h.lower) + ":")
			h.raw = append(cased, line[colon+1:]...)
			tail[slot] = h
			if h.lower == "connection" {
				haveConnection = true
			}
			continue
		}
		unknown = append(unknown, h)
	}

	out := make([]byte, 0, len(block)+32)
	out = append(out, requestLine...)
	out = append(out, "\r\n"...)
	for _, h := range knownSlots {
		if h == nil {
			continue
		}
		out = append(out, h.raw...)
		out = append(out, "\r\n"...)
	}
	// 真机没有的 header 保持相对顺序，排在 SDK 头之后。
	for _, h := range unknown {
		out = append(out, h.raw...)
		out = append(out, "\r\n"...)
	}
	// Connection：Go 在 keep-alive 时不写，真机必写。
	if !haveConnection {
		out = append(out, "Connection: keep-alive\r\n"...)
	} else {
		out = append(out, tail[0].raw...)
		out = append(out, "\r\n"...)
	}
	for _, h := range tail[1:] {
		if h == nil {
			continue
		}
		out = append(out, h.raw...)
		out = append(out, "\r\n"...)
	}
	out = append(out, "\r\n"...)
	return append(out, rest...)
}

func canonicalTailName(lower string) string {
	switch lower {
	case "connection":
		return "Connection"
	case "host":
		return "Host"
	case "accept-encoding":
		return "Accept-Encoding"
	case "content-length":
		return "Content-Length"
	}
	return lower
}
