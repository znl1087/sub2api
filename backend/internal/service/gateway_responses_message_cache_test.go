//go:build unit

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestClaudeResponsesMessageCache_CompatibleBreakpoints(t *testing.T) {
	for _, tt := range []struct {
		name  string
		body  string
		paths []string
	}{
		{"plain string", `{"messages":[{"role":"user","content":"hello\nworld"}]}`, []string{"messages.0.content.0.cache_control"}},
		{"tool result", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"done"}]}]}`, []string{"messages.0.content.0.cache_control"}},
		{"skip thinking and empty text", `{"messages":[{"role":"assistant","content":[{"type":"text","text":"answer"},{"type":"thinking","thinking":"private","signature":"signed"},{"type":"text","text":""}]}]}`, []string{"messages.0.content.0.cache_control"}},
		{"skip thinking-only tail", `{"messages":[{"role":"user","content":"question"},{"role":"assistant","content":[{"type":"thinking","thinking":"private","signature":"signed"}]}]}`, []string{"messages.0.content.0.cache_control"}},
		{"preserve ttl", `{"messages":[{"role":"user","content":[{"type":"text","text":"hello","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}`, []string{"messages.0.content.0.cache_control"}},
		{"one free slot prioritizes history tail", `{"system":[{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}},{"type":"text","text":"s2","cache_control":{"type":"ephemeral"}},{"type":"text","text":"s3","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"},{"role":"user","content":"c"}]}`, []string{"messages.2.content.0.cache_control"}},
		{"full slots preserve existing markers", `{"system":[{"type":"text","text":"s1","cache_control":{"type":"ephemeral"}},{"type":"text","text":"s2","cache_control":{"type":"ephemeral"}},{"type":"text","text":"s3","cache_control":{"type":"ephemeral"}},{"type":"text","text":"s4","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"a"}]}`, nil},
		{"automatic caching", `{"cache_control":{"type":"ephemeral"},"messages":[{"role":"user","content":"a"}]}`, nil},
		{"uncacheable tail", `{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"private","signature":"signed"},{"type":"redacted_thinking","data":"opaque"},{"type":"text","text":" "}]}]}`, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(tt.body)
			out := addClaudeResponsesMessageCacheBreakpoints(body)
			_, paths, tools, system := collectCacheControlPaths(out)
			require.Equal(t, tt.paths, paths)
			require.LessOrEqual(t, len(paths)+len(tools)+len(system), maxCacheControlBlocks)
			require.Equal(t, out, addClaudeResponsesMessageCacheBreakpoints(out), "adding markers must be idempotent")
			require.Equal(t, tt.body, string(body), "borrowed input must remain unchanged")
			require.Equal(t, cacheIndependentMessages(t, body), cacheIndependentMessages(t, out), "markers must not alter message meaning or signatures")
			if tt.name == "preserve ttl" {
				require.Equal(t, "1h", gjson.GetBytes(out, paths[0]+".ttl").String())
			}
			requireCacheTTLOrderAccepted(t, enforceCacheControlLimit(out))
		})
	}
}

func cacheIndependentMessages(t *testing.T, body []byte) any {
	t.Helper()
	var request map[string]any
	require.NoError(t, json.Unmarshal(body, &request))
	messages, _ := request["messages"].([]any)
	for _, raw := range messages {
		message := raw.(map[string]any)
		if text, ok := message["content"].(string); ok {
			message["content"] = []any{map[string]any{"type": "text", "text": text}}
		}
		blocks, _ := message["content"].([]any)
		for _, rawBlock := range blocks {
			delete(rawBlock.(map[string]any), "cache_control")
		}
	}
	return messages
}

func TestClaudeResponsesMessageCache_LongToolConversationKeepsPriorTail(t *testing.T) {
	messages := []any{
		map[string]any{"role": "user", "content": "stable previous user"},
		map[string]any{"role": "assistant", "content": "previous answer"},
		map[string]any{"role": "user", "content": "new task"},
	}
	for i := 0; i < 30; i++ {
		messages = append(messages,
			map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": fmt.Sprint("toolu_", i), "name": "lookup", "input": map[string]any{}}}},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": fmt.Sprint("toolu_", i), "content": "done"}}},
		)
	}
	body, err := json.Marshal(map[string]any{"messages": messages})
	require.NoError(t, err)
	out := addClaudeResponsesMessageCacheBreakpoints(body)
	_, paths, _, _ := collectCacheControlPaths(out)
	require.Len(t, paths, 2)
	require.True(t, gjson.GetBytes(out, "messages.60.content.0.cache_control").Exists())
	require.True(t, gjson.GetBytes(out, "messages.62.content.0.cache_control").Exists())
	require.Equal(t, cacheIndependentMessages(t, body), cacheIndependentMessages(t, out))

	// The next tool result keeps the prior tail as an explicit cache lookup
	// boundary, even after a long conversation with many tool iterations.
	messages = append(messages,
		map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "toolu_next", "name": "lookup", "input": map[string]any{}}}},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "toolu_next", "content": "next result"}}},
	)
	next, err := json.Marshal(map[string]any{"messages": messages})
	require.NoError(t, err)
	next = addClaudeResponsesMessageCacheBreakpoints(next)
	require.True(t, gjson.GetBytes(next, "messages.62.content.0.cache_control").Exists())
	require.True(t, gjson.GetBytes(next, "messages.64.content.0.cache_control").Exists())
	before := cacheIndependentMessages(t, out).([]any)
	after := cacheIndependentMessages(t, next).([]any)
	require.Equal(t, before, after[:len(before)])
}

func TestForwardAsResponses_ClaudeMessageCacheScope(t *testing.T) {
	for _, tt := range []struct {
		name, accountType, switchValue string
		wantHistory                    bool
	}{
		{"default enabled OAuth", AccountTypeOAuth, "", true},
		{"disabled OAuth", AccountTypeOAuth, "false", false},
		{"explicit enabled OAuth", AccountTypeOAuth, "true", true},
		{"setup token uses OAuth cache path", AccountTypeSetupToken, "true", true},
		{"API key unchanged", AccountTypeAPIKey, "true", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resetGatewayForwardingSettingsCacheForTest(t)
			repo := &gatewayTTLSettingRepo{data: map[string]string{SettingKeyEnableClaudeResponsesMessageCache: tt.switchValue, SettingKeyRewriteMessageCacheControl: "false"}}
			settings := NewSettingService(repo, &config.Config{})
			require.Equal(t, tt.switchValue != "false", settings.IsClaudeResponsesMessageCacheEnabled(context.Background()))
			require.False(t, settings.IsRewriteMessageCacheControlEnabled(context.Background()))
			upstream := &anthropicHTTPUpstreamRecorder{}
			svc := &GatewayService{cfg: &config.Config{}, settingService: settings, httpUpstream: upstream}
			account := &Account{ID: 46, Platform: PlatformAnthropic, Type: tt.accountType, Credentials: map[string]any{"access_token": "fixture-oauth-token", "api_key": "fixture-api-key"}}
			for _, stream := range []bool{false, true} {
				var previous []byte
				for turn := 1; turn <= 2; turn++ {
					input := []map[string]any{{"role": "user", "content": "stable initial context"}}
					if turn == 2 {
						input = append(input, map[string]any{"role": "assistant", "content": "OK"}, map[string]any{"role": "user", "content": "next question"})
					}
					body, err := json.Marshal(map[string]any{"model": "claude-opus-4-8", "instructions": "stable project instructions", "input": input, "stream": stream, "max_output_tokens": 64})
					require.NoError(t, err)
					upstream.resp = &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_cache\",\"model\":\"claude-opus-4-8\",\"content\":[],\"usage\":{\"input_tokens\":10}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))}
					rec := httptest.NewRecorder()
					c, _ := gin.CreateTestContext(rec)
					c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))
					result, err := svc.ForwardAsResponses(context.Background(), c, account, body, nil)
					require.NoError(t, err)
					require.NotNil(t, result)
					require.Equal(t, 200, rec.Code)
					_, paths, tools, system := collectCacheControlPaths(upstream.lastBody)
					require.LessOrEqual(t, len(paths)+len(tools)+len(system), 4)
					require.Equal(t, tt.wantHistory, len(paths) > 0)
					if tt.wantHistory {
						last := len(gjson.GetBytes(upstream.lastBody, "messages").Array()) - 1
						require.Equal(t, "5m", gjson.GetBytes(upstream.lastBody, fmt.Sprintf("messages.%d.content.0.cache_control.ttl", last)).String())
					}
					if previous != nil {
						before := cacheIndependentMessages(t, previous).([]any)
						after := cacheIndependentMessages(t, upstream.lastBody).([]any)
						require.Equal(t, before, after[:len(before)], "the previous turn must remain an identical prefix")
					}
					previous = append([]byte(nil), upstream.lastBody...)
				}
			}
		})
	}
}
