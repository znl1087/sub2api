package service

import (
	"fmt"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/tidwall/gjson"
)

// 本文件负责把请求体里的 Claude Code 身份句与主 prompt 对齐到账号所属版本。
//
// 为什么必须做：UA、billing cc_version、beta 集合、TLS 握手都已经按账号版本走，
// 只有 system 还留着客户端自带的原文。客户端是 2.1.323、账号却被判成 2.1.312 时，
// 头和体就自相矛盾——这是比"版本统一"更容易被抓的破绽。
//
// 实测同一版本下 prompt 与 tools 还随模型代次变化（2.1.323：sonnet-4-5 主 prompt
// 27082B，opus-5-5 只有 6740B；4-5 代与 5 代 tools 也不同），所以取模板时必须带上
// 出站模型 ID，走 profile.PromptForModel 的族匹配。

// claudeVersionPromptBillingPrefix 标识 system[0] 的 billing 头块。
const claudeVersionPromptBillingPrefix = "x-anthropic-billing-header"

// applyClaudeVersionSystemPrompt 用账号版本的快照覆盖 system 里的身份句与主 prompt。
//
// 只处理"已经是 Claude Code 形状"的 body（含 billing 头块，或 system 直接是字符串）：
// 非 Claude Code 客户端由 mimicry 路径先注入 billing 块，之后自然会走到这里；
// 完全没伪装的第三方 body 保持原样，避免把用户自己的 system 顶掉。
//
// 任何一步失败都返回原 body，不 panic、不半改。
func applyClaudeVersionSystemPrompt(body []byte, profile claude.VersionProfile, modelID string) []byte {
	if len(body) == 0 {
		return body
	}
	identity, prompt, _ := profile.PromptForModel(modelID)
	if prompt == "" {
		return body
	}

	system := gjson.GetBytes(body, "system")
	if !system.Exists() {
		return body
	}

	if system.Type == gjson.String {
		if system.String() == prompt || !looksLikeClaudeCodePrompt(system.String()) {
			return body
		}
		if next, ok := setJSONValueBytes(body, "system", prompt); ok {
			return next
		}
		return body
	}
	if !system.IsArray() {
		return body
	}

	blocks := system.Array()
	billingIdx, longestIdx, longestLen := -1, -1, 0
	already := false
	for i, block := range blocks {
		text := block.Get("text").String()
		if text == prompt {
			already = true
		}
		if billingIdx < 0 && isClaudeVersionBillingBlock(text) {
			billingIdx = i
			continue
		}
		if len(text) > longestLen {
			longestIdx, longestLen = i, len(text)
		}
	}
	if already {
		return body
	}

	// 真机报文固定是 [billing][身份句][主 prompt]，按位定位。
	identityIdx, promptIdx := -1, longestIdx
	if billingIdx >= 0 {
		if billingIdx+1 < len(blocks) {
			identityIdx = billingIdx + 1
		}
		if billingIdx+2 < len(blocks) {
			promptIdx = billingIdx + 2
		}
	}

	// 只覆盖"看起来就是 Claude Code"的块：管理员自定义过的 system 保持不动。
	if identity != "" && identityIdx >= 0 && looksLikeClaudeCodeIdentity(blocks[identityIdx].Get("text").String()) {
		if next, ok := setJSONValueBytes(body, fmt.Sprintf("system.%d.text", identityIdx), identity); ok {
			body = next
		}
	}
	if promptIdx >= 0 && looksLikeClaudeCodePrompt(blocks[promptIdx].Get("text").String()) {
		if next, ok := setJSONValueBytes(body, fmt.Sprintf("system.%d.text", promptIdx), prompt); ok {
			body = next
		}
	}
	return body
}

// looksLikeClaudeCodePrompt 判断一块 system 是不是 Claude Code 的主 prompt。
// 覆盖两代写法：老版 "You are Claude Code"、2.1.32x 的 "You are an agent working with..."，
// 以及当前内置常量（未自定义时就是它）。
func looksLikeClaudeCodePrompt(text string) bool {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return false
	}
	if trimmed == claudeCodeSystemPromptExpansion || trimmed == claudeCodeSystemPrompt {
		return true
	}
	return strings.HasPrefix(trimmed, claudeVersionPromptAgentPrefix) ||
		strings.HasPrefix(trimmed, claudeVersionPromptCLIPrefix)
}

// looksLikeClaudeCodeIdentity 判断一块 system 是不是身份句。
func looksLikeClaudeCodeIdentity(text string) bool {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || len(trimmed) > 200 {
		return false
	}
	return strings.HasPrefix(trimmed, "You are Claude") || strings.HasPrefix(trimmed, "You are a Claude")
}

const (
	claudeVersionPromptAgentPrefix = "You are an agent working with the user"
	claudeVersionPromptCLIPrefix   = "You are Claude Code"
)

// applyClaudeVersionTools 仅在 body 完全没有 tools 时补上版本快照。
// body 自带 tools 时不覆盖：客户端可能只带子集，且工具名混淆/断点注入依赖原有结构。
func applyClaudeVersionTools(body []byte, tools []byte) []byte {
	if len(body) == 0 || len(tools) == 0 {
		return body
	}
	if existing := gjson.GetBytes(body, "tools"); existing.Exists() && existing.IsArray() && len(existing.Array()) > 0 {
		return body
	}
	if next, ok := setJSONRawBytes(body, "tools", tools); ok {
		return next
	}
	return body
}

// claudeVersionToolsFor 取出该账号版本对指定模型的 tools 快照。
func claudeVersionToolsFor(profile claude.VersionProfile, modelID string) (string, []byte) {
	identity, _, tools := profile.PromptForModel(modelID)
	return identity, tools
}

func isClaudeVersionBillingBlock(text string) bool {
	return len(text) >= len(claudeVersionPromptBillingPrefix) &&
		text[:len(claudeVersionPromptBillingPrefix)] == claudeVersionPromptBillingPrefix
}
