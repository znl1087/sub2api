package service

import (
	"fmt"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// addClaudeResponsesMessageCacheBreakpoints fills missing conversation cache
// breakpoints on the Responses → Claude OAuth bridge. Unlike the opt-in global
// rewrite, it keeps existing markers and their TTLs, and only uses free slots.
// A tail breakpoint caches the growing history; a previous-user breakpoint
// keeps the preceding turn's boundary explicitly discoverable during tool use.
func addClaudeResponsesMessageCacheBreakpoints(body []byte) []byte {
	// Automatic caching already covers the tail and consumes a breakpoint slot.
	if gjson.GetBytes(body, "cache_control").Exists() {
		return body
	}
	messages := gjson.GetBytes(body, "messages").Array()
	if len(messages) == 0 {
		return body
	}
	_, messagePaths, toolPaths, systemPaths := collectCacheControlPaths(body)
	available := maxCacheControlBlocks - len(messagePaths) - len(toolPaths) - len(systemPaths)
	if available <= 0 {
		return body
	}

	add := func(messageIndex int) bool {
		content := messages[messageIndex].Get("content")
		prefix := fmt.Sprintf("messages.%d.content", messageIndex)
		if content.Type == gjson.String {
			if strings.TrimSpace(content.String()) == "" {
				return false
			}
			block := fmt.Sprintf(`[{"type":"text","text":%s,"cache_control":{"type":"ephemeral","ttl":%q}}]`, mustJSONString(content.String()), claude.DefaultCacheControlTTL)
			if next, err := sjson.SetRawBytes(body, prefix, []byte(block)); err == nil {
				body = next
				available--
				return true
			}
			return false
		}
		blocks := content.Array()
		for i := len(blocks) - 1; i >= 0; i-- {
			if !isClaudeResponsesCacheableBlock(blocks[i]) {
				continue
			}
			path := fmt.Sprintf("%s.%d.cache_control", prefix, i)
			if gjson.GetBytes(body, path).Exists() {
				return true
			}
			marker := fmt.Sprintf(`{"type":"ephemeral","ttl":%q}`, claude.DefaultCacheControlTTL)
			if next, err := sjson.SetRawBytes(body, path, []byte(marker)); err == nil {
				body = next
				available--
				return true
			}
			return false
		}
		return false
	}

	// Walk backward past empty or thinking-only messages. Thinking signatures
	// remain untouched and are never direct cache-control targets.
	for i := len(messages) - 1; i >= 0; i-- {
		if add(i) {
			break
		}
	}
	if available <= 0 {
		return body
	}
	userCount := 0
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Get("role").String() != "user" {
			continue
		}
		userCount++
		if userCount == 2 {
			add(i)
			break
		}
	}
	return body
}

func isClaudeResponsesCacheableBlock(block gjson.Result) bool {
	switch block.Get("type").String() {
	case "text":
		return strings.TrimSpace(block.Get("text").String()) != ""
	case "image", "document", "tool_use", "tool_result":
		return true
	default:
		return false
	}
}
