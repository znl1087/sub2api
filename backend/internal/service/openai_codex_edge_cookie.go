package service

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// 真机 codex-cli 0.167.0 的每个推理请求都带 chatgpt.com 的 cookie 束
// （`__oailb` + `__cf_bm` + `__cflb`，抓包实测）。`__oailb` 是 Cloudflare 边缘网关
// 签发的 ES256 JWT（内含 host/exp，有效期 1 小时），上游会在响应里以 Set-Cookie 下发，
// 客户端随后回带——这是「已建立会话的边缘节点」的凭据，无 cookie 的出站请求在边缘看
// 就是首访形态。
//
// 这里做同账号级的 cookie 束缓存：从上游 Set-Cookie 收集，下次出站回带。缓存是进程内的
// （不落库），丢了只是退化成首访形态，上游会重新下发，不影响正确性。

// codexEdgeCookieTTL 略短于 __oailb 的 1 小时有效期，避免回带刚过期的凭据。
const codexEdgeCookieTTL = 55 * time.Minute

// codexEdgeCookieNames 只收集真机会回带的 cookie，Cloudflare 的其他噪声 cookie 不掺进来。
var codexEdgeCookieNames = []string{"__oailb", "__cf_bm", "__cflb"}

type codexEdgeCookieEntry struct {
	pair    map[string]string
	expires time.Time
}

var codexEdgeCookieStore sync.Map // accountID(int64) -> *codexEdgeCookieEntry

// codexCookieHeader 按 __oailb/__cf_bm/__cflb 的固定顺序拼装 Cookie 头。
func codexCookieHeader(entry *codexEdgeCookieEntry) string {
	parts := make([]string, 0, len(codexEdgeCookieNames))
	for _, name := range codexEdgeCookieNames {
		if v := entry.pair[name]; v != "" {
			parts = append(parts, name+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}

// rememberCodexEdgeCookies 从上游响应的 Set-Cookie 收集 cookie 束。
// 只对 Codex 内部接口（带 chatgpt-account-id 的出站请求）生效。
func rememberCodexEdgeCookies(accountID int64, req *http.Request, resp *http.Response) {
	if accountID == 0 || req == nil || resp == nil {
		return
	}
	if req.Header.Get("chatgpt-account-id") == "" {
		return
	}
	setCookies := resp.Header.Values("Set-Cookie")
	if len(setCookies) == 0 {
		return
	}

	pair := make(map[string]string, len(codexEdgeCookieNames))
	if prev, ok := codexEdgeCookieStore.Load(accountID); ok {
		if entry, ok := prev.(*codexEdgeCookieEntry); ok && time.Now().Before(entry.expires) {
			for k, v := range entry.pair {
				pair[k] = v
			}
		}
	}
	for _, raw := range setCookies {
		name, value, ok := parseSetCookiePair(raw)
		if !ok {
			continue
		}
		for _, want := range codexEdgeCookieNames {
			if name == want {
				pair[name] = value
				break
			}
		}
	}
	if len(pair) == 0 {
		return
	}
	codexEdgeCookieStore.Store(accountID, &codexEdgeCookieEntry{
		pair:    pair,
		expires: time.Now().Add(codexEdgeCookieTTL),
	})
}

// parseSetCookiePair 取出 `name=value`，值本身可能含 '='（JWT 的 base64url 尾部填充），
// 因此只在第一个 '=' 处切分。
func parseSetCookiePair(raw string) (string, string, bool) {
	segment := raw
	if idx := strings.IndexByte(segment, ';'); idx >= 0 {
		segment = segment[:idx]
	}
	eq := strings.IndexByte(segment, '=')
	if eq <= 0 {
		return "", "", false
	}
	name := strings.TrimSpace(segment[:eq])
	value := strings.TrimSpace(segment[eq+1:])
	if name == "" || value == "" {
		return "", "", false
	}
	return name, value, true
}

// applyCodexEdgeCookies 在客户端没带 cookie 时回带缓存的 cookie 束。
// 客户端自带 cookie 说明它会话是热的，优先用它的。
func applyCodexEdgeCookies(h http.Header, accountID int64) {
	if h == nil || accountID == 0 || strings.TrimSpace(h.Get("cookie")) != "" {
		return
	}
	prev, ok := codexEdgeCookieStore.Load(accountID)
	if !ok {
		return
	}
	entry, ok := prev.(*codexEdgeCookieEntry)
	if !ok || time.Now().After(entry.expires) {
		codexEdgeCookieStore.Delete(accountID)
		return
	}
	if header := codexCookieHeader(entry); header != "" {
		h.Set("cookie", header)
	}
}
