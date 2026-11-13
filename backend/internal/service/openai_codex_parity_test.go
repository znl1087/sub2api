package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 本文件以真机抓包为金标准，断言 sub2api 的出站报文与 codex-cli 0.167.0 逐项一致。
// 金标准样本：sandbox/codex_cap2/001.json（真实 codex exec 经 mitmproxy 抓到）。
// 抓包缺失时跳过，便于在无样本环境跑全量测试。

type codexGoldenCapture struct {
	Headers []struct {
		Name  string
		Value string
	}
	Body         map[string]any
	BodyKeyOrder []string
}

func loadCodexGoldenCapture(t *testing.T) *codexGoldenCapture {
	t.Helper()
	path := filepath.Join("testdata", "codex", "golden_exec_0167.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("缺少真机抓包样本 %s: %v", path, err)
	}
	var doc struct {
		Headers [][2]string `json:"headers"`
		Body    string      `json:"body"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))

	g := &codexGoldenCapture{}
	for _, pair := range doc.Headers {
		g.Headers = append(g.Headers, struct{ Name, Value string }{pair[0], pair[1]})
	}
	require.NoError(t, json.Unmarshal([]byte(doc.Body), &g.Body))
	// 键序信息在 map 解码后丢失，单独从原始 body 保留一份有序清单。
	g.BodyKeyOrder = jsonObjectKeyOrder(t, []byte(doc.Body))
	return g
}

// jsonObjectKeyOrder 按书写顺序返回 JSON 对象的顶层键。
func jsonObjectKeyOrder(t *testing.T, body []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	require.NoError(t, err)
	require.Equal(t, json.Delim('{'), tok)
	keys := make([]string, 0, 16)
	for dec.More() {
		keyTok, err := dec.Token()
		require.NoError(t, err)
		key, ok := keyTok.(string)
		require.True(t, ok)
		keys = append(keys, key)
		var skip json.RawMessage
		require.NoError(t, dec.Decode(&skip))
	}
	return keys
}

func (g *codexGoldenCapture) header(name string) string {
	for _, h := range g.Headers {
		if http.CanonicalHeaderKey(h.Name) == http.CanonicalHeaderKey(name) {
			return h.Value
		}
	}
	return ""
}

// buildCodexParityRequest 用与真机等价的客户端输入走一遍真实出站构造。
func buildCodexParityRequest(t *testing.T, golden *codexGoldenCapture) *http.Request {
	t.Helper()
	gin.SetMode(gin.TestMode)

	body, err := json.Marshal(golden.Body)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", bytes.NewReader(body))
	// 复刻真机客户端自带的头；服务端需要补齐的项故意不设。
	c.Request.Header.Set("content-type", golden.header("content-type"))
	c.Request.Header.Set("accept", golden.header("accept"))
	c.Request.Header.Set("session-id", golden.header("session-id"))
	c.Request.Header.Set("thread-id", golden.header("thread-id"))
	c.Request.Header.Set("x-codex-window-id", golden.header("x-codex-window-id"))
	c.Request.Header.Set("x-codex-turn-metadata", golden.header("x-codex-turn-metadata"))
	c.Request.Header.Set("x-codex-beta-features", golden.header("x-codex-beta-features"))
	c.Request.Header.Set("originator", golden.header("originator"))
	c.Request.Header.Set("user-agent", golden.header("user-agent"))

	account := newTestOAuthAccount(9101, nil)
	account.Credentials = map[string]any{
		"access_token":       "golden-token",
		"chatgpt_account_id": golden.header("chatgpt-account-id"),
	}

	svc := &OpenAIGatewayService{cfg: &config.Config{}}
	req, err := svc.buildUpstreamRequest(context.Background(), c, account, body, "golden-token", true, "", true)
	require.NoError(t, err)
	return req
}

// TestCodexOutboundParity_IdentityHeaders 断言身份类头与真机一致。
func TestCodexOutboundParity_IdentityHeaders(t *testing.T) {
	golden := loadCodexGoldenCapture(t)
	req := buildCodexParityRequest(t, golden)

	require.Equal(t, golden.header("originator"), req.Header.Get("originator"), "originator 必须与真机一致")
	require.Equal(t, golden.header("user-agent"), req.Header.Get("user-agent"), "UA 必须与真机逐字节一致")
	require.Equal(t, openai.CodexExecOriginator, req.Header.Get("originator"))
	// 真机推理面没有 version 头。
	require.Empty(t, req.Header.Get("version"), "推理面不应发送 version 头")
	require.Equal(t, golden.header("accept"), req.Header.Get("accept"))
	require.Equal(t, golden.header("content-type"), req.Header.Get("content-type"))
}

// TestCodexOutboundParity_SessionHeaders 断言会话标识头齐备且内部自洽。
func TestCodexOutboundParity_SessionHeaders(t *testing.T) {
	golden := loadCodexGoldenCapture(t)
	req := buildCodexParityRequest(t, golden)

	for _, name := range []string{
		"session-id", "thread-id", "x-client-request-id",
		"x-codex-window-id", "x-codex-turn-metadata", "x-codex-beta-features",
	} {
		require.NotEmpty(t, req.Header.Get(name), "缺少真机必带的头 %s", name)
	}

	// window-id 必须是 thread-id 的 0 号窗口。
	require.Equal(t, req.Header.Get("thread-id")+":0", req.Header.Get("x-codex-window-id"))
	require.Equal(t, req.Header.Get("thread-id"), req.Header.Get("x-client-request-id"))
	require.Equal(t, openAIRemoteCompactionV2Feature, req.Header.Get("x-codex-beta-features"))

	// turn-metadata 必须与真机同构：22 个键一个不少。
	var metadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(req.Header.Get("x-codex-turn-metadata")), &metadata))
	var goldenMetadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(golden.header("x-codex-turn-metadata")), &goldenMetadata))
	for key := range goldenMetadata {
		require.Contains(t, metadata, key, "turn-metadata 缺少真机键 %s", key)
	}
	require.Equal(t, "turn", metadata["request_kind"])
	require.Equal(t, "/root", metadata["agent_name"])
	require.Equal(t, "exec", metadata["turn_trigger"])
}

// TestCodexOutboundParity_BodyShape 断言 body 顶层键序与真机一致，且关键字段取值正确。
func TestCodexOutboundParity_BodyShape(t *testing.T) {
	golden := loadCodexGoldenCapture(t)
	req := buildCodexParityRequest(t, golden)

	raw, err := openAIRequestBody(req)
	require.NoError(t, err)

	require.Equal(t, golden.BodyKeyOrder, jsonObjectKeyOrder(t, raw), "body 顶层键序必须与真机一致")

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var body map[string]json.RawMessage
	require.NoError(t, dec.Decode(&body))

	// reasoning.context 是真机新增字段，必须为 all_turns。
	var reasoning map[string]any
	require.NoError(t, json.Unmarshal(body["reasoning"], &reasoning))
	require.Equal(t, "all_turns", reasoning["context"])

	// client_metadata 必须携带会话三元组与安装指纹。
	var clientMetadata map[string]any
	require.NoError(t, json.Unmarshal(body["client_metadata"], &clientMetadata))
	require.Equal(t, "true", clientMetadata["guardian_credits_requested"])
	require.NotEmpty(t, clientMetadata["x-codex-installation-id"])
	require.NotEmpty(t, clientMetadata["x-codex-turn-metadata"])
	require.Equal(t, `{"status":"none"}`, clientMetadata["mcp_attribution"])

	// input 末项必须是真机固定的 configuration_update 收尾（键序 type 在前）。
	var items []json.RawMessage
	require.NoError(t, json.Unmarshal(body["input"], &items))
	var tail map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(items[len(items)-1], &tail))
	require.Equal(t, `"configuration_update"`, string(tail["type"]))
	require.Equal(t, `{"type":"configuration_update","reasoning":{"effort":"xhigh"}}`,
		string(items[len(items)-1]))

	// 头 / metadata / client_metadata / prompt_cache_key 四处的会话标识必须恒等，
	// 否则是「头说 A、体说 B」的拼接形态。
	sessionID := req.Header.Get("session-id")
	require.NotEmpty(t, sessionID)
	require.Equal(t, sessionID, clientMetadata["session_id"])
	require.Equal(t, sessionID, clientMetadata["thread_id"])
	require.Equal(t, sessionID+":0", clientMetadata["x-codex-window-id"])
	require.Equal(t, req.Header.Get("x-codex-turn-metadata"), clientMetadata["x-codex-turn-metadata"])
}

// TestCodexOutboundParity_TurnMetadataKeyOrder 断言 metadata 内部键序与真机一致。
func TestCodexOutboundParity_TurnMetadataKeyOrder(t *testing.T) {
	golden := loadCodexGoldenCapture(t)
	req := buildCodexParityRequest(t, golden)

	require.Equal(t,
		jsonObjectKeyOrder(t, []byte(golden.header("x-codex-turn-metadata"))),
		jsonObjectKeyOrder(t, []byte(req.Header.Get("x-codex-turn-metadata"))),
		"turn-metadata 键序必须与真机一致")
}

// TestCodexOutboundParity_WireEncoding 断言出站体走真机同款 zstd 帧形态。
func TestCodexOutboundParity_WireEncoding(t *testing.T) {
	golden := loadCodexGoldenCapture(t)
	req := buildCodexParityRequest(t, golden)

	require.Equal(t, golden.header("content-encoding"), req.Header.Get("content-encoding"))
	require.Equal(t, codexWireContentEncoding, req.Header.Get("content-encoding"))

	// 帧头必须与真机抓包逐字节一致：magic + FHD=0x00 + windowDesc=0x58。
	var compressed []byte
	{
		var err error
		compressed, err = io.ReadAll(req.Body)
		require.NoError(t, err)
		req.Body = newCodexBytesReadCloser(compressed)
	}
	require.True(t, bytes.HasPrefix(compressed, []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58}),
		"zstd 帧头必须为真机形态，实际 %x", compressed[:6])
	require.Equal(t, int64(len(compressed)), req.ContentLength)
	// 压缩后必须明显小于明文，否则说明压缩没生效。
	plain, err := openAIRequestBody(req)
	require.NoError(t, err)
	require.Less(t, len(compressed), len(plain))
}
