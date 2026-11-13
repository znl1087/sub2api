package service

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 真机推理请求必带 __oailb/__cf_bm/__cflb。这里覆盖从 Set-Cookie 收集到回带的闭环，
// 以及「客户端自带 cookie 优先」「过期不复活」两条边界。

func codexCookieTestRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
	req.Header.Set("chatgpt-account-id", "acc-1")
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	return req
}

func codexCookieTestResponse(pairs ...string) *http.Response {
	resp := &http.Response{Header: http.Header{}}
	for _, pair := range pairs {
		resp.Header.Add("Set-Cookie", pair+"; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax")
	}
	return resp
}

func resetCodexCookieStore(t *testing.T) {
	t.Helper()
	codexEdgeCookieStore.Range(func(key, _ any) bool {
		codexEdgeCookieStore.Delete(key)
		return true
	})
}

func TestCodexEdgeCookies_CollectAndReplay(t *testing.T) {
	resetCodexCookieStore(t)

	const accountID int64 = 9102
	req := codexCookieTestRequest("tok")
	rememberCodexEdgeCookies(accountID, req, codexCookieTestResponse(
		"__oailb=abc.def.ghi", "__cf_bm=beam", "__cflb=lb", "__cf_noise=noise",
	))

	out := http.Header{}
	applyCodexEdgeCookies(out, accountID)

	// 顺序固定，噪声 cookie 不掺入。
	require.Equal(t, "__oailb=abc.def.ghi; __cf_bm=beam; __cflb=lb", out.Get("cookie"))
}

func TestCodexEdgeCookies_ClientCookieWins(t *testing.T) {
	resetCodexCookieStore(t)

	const accountID int64 = 9103
	rememberCodexEdgeCookies(accountID, codexCookieTestRequest("tok"),
		codexCookieTestResponse("__oailb=cached"))

	out := http.Header{}
	out.Set("cookie", "__oailb=client")
	applyCodexEdgeCookies(out, accountID)

	require.Equal(t, "__oailb=client", out.Get("cookie"))
}

func TestCodexEdgeCookies_ExpiredIsDropped(t *testing.T) {
	resetCodexCookieStore(t)

	const accountID int64 = 9104
	codexEdgeCookieStore.Store(accountID, &codexEdgeCookieEntry{
		pair:    map[string]string{"__oailb": "stale"},
		expires: time.Now().Add(-time.Minute),
	})

	out := http.Header{}
	applyCodexEdgeCookies(out, accountID)

	require.Empty(t, out.Get("cookie"))
	_, stillCached := codexEdgeCookieStore.Load(accountID)
	require.False(t, stillCached, "过期条目应被清理")
}

func TestCodexEdgeCookies_RequiresChatGPTAccountHeader(t *testing.T) {
	resetCodexCookieStore(t)

	req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", nil)
	rememberCodexEdgeCookies(9105, req, codexCookieTestResponse("__oailb=x"))

	_, cached := codexEdgeCookieStore.Load(int64(9105))
	require.False(t, cached, "平台 API 出站不应收集边缘 cookie")
}

func TestParseSetCookiePair(t *testing.T) {
	// JWT 尾部 base64url 填充里的 '=' 必须原样保留。
	name, value, ok := parseSetCookiePair("__oailb=abc.def.ghi==; Path=/; Secure")
	require.True(t, ok)
	require.Equal(t, "__oailb", name)
	require.Equal(t, "abc.def.ghi==", value)

	_, _, ok = parseSetCookiePair("no-equals; Path=/")
	require.False(t, ok)
}

// TestCodexEdgeCookies_ReplayedOnUpstreamRequest 覆盖出站构造端的接线。
func TestCodexEdgeCookies_ReplayedOnUpstreamRequest(t *testing.T) {
	resetCodexCookieStore(t)

	const accountID int64 = 9106
	rememberCodexEdgeCookies(accountID, codexCookieTestRequest("tok"),
		codexCookieTestResponse("__oailb=wired"))

	body := []byte(`{"model":"gpt-5","input":[]}`)
	c := newCodexParityGinContext(t, body)
	account := newTestOAuthAccount(accountID, nil)
	account.Credentials = map[string]any{
		"access_token":       "tok",
		"chatgpt_account_id": "acc-1",
	}

	svc := &OpenAIGatewayService{}
	req, err := svc.buildUpstreamRequest(t.Context(), c, account, body, "tok", true, "", true)
	require.NoError(t, err)

	require.Equal(t, "__oailb=wired", req.Header.Get("cookie"))
}

// TestCodexWireCompression_NoPlainBodyUpstream 断言压缩后不会再发明文 Content-Length。
func TestCodexWireCompression_NoPlainBodyUpstream(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses",
		bytesReaderCloser(`{"model":"gpt-5","input":[]}`))
	req.Header.Set("content-length", "25")

	require.NoError(t, applyCodexWireCompression(req))
	require.Equal(t, codexWireContentEncoding, req.Header.Get("content-encoding"))
	require.Empty(t, req.Header.Get("content-length"))
	// ContentLength 必须等于压缩体的实际长度，否则上游会读不满。
	require.Equal(t, int64(37), req.ContentLength)
	require.NotEqual(t, int64(25), req.ContentLength)
	// GetBody 必须可重复读，供重试复用同一份压缩体。
	again, err := req.GetBody()
	require.NoError(t, err)
	defer again.Close()
	raw, err := io.ReadAll(again)
	require.NoError(t, err)
	require.Equal(t, req.ContentLength, int64(len(raw)))
	require.True(t, bytes.HasPrefix(raw, []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58}))
}

func bytesReaderCloser(s string) *codexBytesReadCloser {
	return newCodexBytesReadCloser([]byte(s))
}

// newCodexParityGinContext 构造一个只带最小上下文的 gin context。
func newCodexParityGinContext(t *testing.T, body []byte) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", bytesReaderCloser(string(body)))
	c.Request.Header.Set("content-type", "application/json")
	return c
}
