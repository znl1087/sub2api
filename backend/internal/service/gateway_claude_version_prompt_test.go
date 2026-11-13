package service

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/tidwall/gjson"
)

func testVersionProfile() claude.VersionProfile {
	return claude.VersionProfile{
		Version:        "2.1.323",
		IdentityPrompt: "You are a Claude agent, built on Anthropic's Claude Agent SDK.",
		Variants: []claude.PromptVariant{
			{Family: "^claude-[a-z]+-5-[0-9]", Prompt: strings.Repeat("NEW-GEN-PROMPT ", 200), Tools: []byte(`[{"name":"NewGen"}]`)},
			{Family: "", Prompt: strings.Repeat("OLD-GEN-PROMPT ", 200), Tools: []byte(`[{"name":"OldGen"}]`)},
		},
	}
}

// 族匹配依赖未导出字段 re，只能经特征库加载路径构造；本文件统一用兜底档验证改写行为，
// 族匹配本身由 internal/pkg/claude 的测试覆盖。
func bodyWithSystem(t *testing.T, blocks ...string) []byte {
	t.Helper()
	parts := make([]string, 0, len(blocks))
	for _, b := range blocks {
		parts = append(parts, `{"type":"text","text":`+jsonString(b)+`}`)
	}
	return []byte(`{"model":"claude-sonnet-4-5","system":[` + strings.Join(parts, ",") + `],"messages":[]}`)
}

func jsonString(s string) string {
	var buf bytes.Buffer
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
	return buf.String()
}

func TestApplyClaudeVersionSystemPromptReplacesIdentityAndPrompt(t *testing.T) {
	p := testVersionProfile()
	body := bodyWithSystem(t,
		"x-anthropic-billing-header: cc_version=2.1.323.1a2; cc_entrypoint=sdk-cli;",
		"You are Claude Code, Anthropic's official CLI for Claude.",
		"You are an agent working with the user, and this is the client prompt.",
	)

	got := applyClaudeVersionSystemPrompt(body, p, "claude-sonnet-4-5")

	blocks := gjson.GetBytes(got, "system").Array()
	if len(blocks) != 3 {
		t.Fatalf("块数变了: %d", len(blocks))
	}
	if !strings.HasPrefix(blocks[0].Get("text").String(), "x-anthropic-billing-header") {
		t.Error("billing 块被改动")
	}
	if blocks[1].Get("text").String() != p.IdentityPrompt {
		t.Errorf("身份句未替换: %q", blocks[1].Get("text").String())
	}
	if !strings.HasPrefix(blocks[2].Get("text").String(), "OLD-GEN-PROMPT") {
		t.Errorf("主 prompt 未替换: %.40q", blocks[2].Get("text").String())
	}
}

func TestApplyClaudeVersionSystemPromptFallsBackToLongestBlock(t *testing.T) {
	p := testVersionProfile()
	// 非 Claude Code 形状：没有 billing 块。
	body := bodyWithSystem(t,
		"short system",
		strings.Repeat("You are an agent working with the user ", 50),
	)

	got := applyClaudeVersionSystemPrompt(body, p, "claude-sonnet-4-5")
	blocks := gjson.GetBytes(got, "system").Array()
	if !strings.HasPrefix(blocks[1].Get("text").String(), "OLD-GEN-PROMPT") {
		t.Errorf("最长块未替换: %.40q", blocks[1].Get("text").String())
	}
	if blocks[0].Get("text").String() != "short system" {
		t.Error("短块被误改")
	}
}

func TestApplyClaudeVersionSystemPromptHandlesStringSystem(t *testing.T) {
	p := testVersionProfile()
	body := []byte(`{"model":"claude-sonnet-4-5","system":"You are Claude Code, Anthropic's official CLI for Claude.","messages":[]}`)

	got := applyClaudeVersionSystemPrompt(body, p, "claude-sonnet-4-5")
	if !strings.HasPrefix(gjson.GetBytes(got, "system").String(), "OLD-GEN-PROMPT") {
		t.Errorf("字符串 system 未替换: %.40q", gjson.GetBytes(got, "system").String())
	}
}

func TestApplyClaudeVersionSystemPromptKeepsCustomSystem(t *testing.T) {
	p := testVersionProfile()
	// 管理员自定义的 system：既不是 CC 身份句也不是 CC 主 prompt，应原样保留。
	body := bodyWithSystem(t,
		"x-anthropic-billing-header: cc_version=2.1.323.1a2;",
		"custom identity from admin",
		strings.Repeat("admin wrote this prompt ", 100),
	)

	got := applyClaudeVersionSystemPrompt(body, p, "claude-sonnet-4-5")
	blocks := gjson.GetBytes(got, "system").Array()
	if blocks[1].Get("text").String() != "custom identity from admin" {
		t.Errorf("自定义身份句被覆盖: %q", blocks[1].Get("text").String())
	}
	if !strings.HasPrefix(blocks[2].Get("text").String(), "admin wrote this prompt") {
		t.Errorf("自定义 prompt 被覆盖: %.40q", blocks[2].Get("text").String())
	}
}

func TestApplyClaudeVersionSystemPromptNoopWhenAlreadyEqual(t *testing.T) {
	p := testVersionProfile()
	prompt := p.Variants[1].Prompt
	body := bodyWithSystem(t,
		"x-anthropic-billing-header: cc_version=2.1.323.1a2;",
		p.IdentityPrompt,
		prompt,
	)

	got := applyClaudeVersionSystemPrompt(body, p, "claude-sonnet-4-5")
	if !bytes.Equal(got, body) {
		t.Error("已一致时不应重写 body")
	}
}

func TestApplyClaudeVersionSystemPromptNoopWithoutTemplate(t *testing.T) {
	body := bodyWithSystem(t, "x-anthropic-billing-header: cc_version=2.1.323;", "identity", "prompt")
	got := applyClaudeVersionSystemPrompt(body, claude.VersionProfile{Version: "2.1.323"}, "claude-sonnet-4-5")
	if !bytes.Equal(got, body) {
		t.Error("没有模板时不应改动 body")
	}
}

func TestApplyClaudeVersionToolsOnlyWhenAbsent(t *testing.T) {
	p := testVersionProfile()

	without := []byte(`{"model":"claude-sonnet-4-5","messages":[]}`)
	got := applyClaudeVersionTools(without, p.Variants[1].Tools)
	if names := gjson.GetBytes(got, "tools.0.name").String(); names != "OldGen" {
		t.Errorf("缺失 tools 时未补: %q", names)
	}

	withOwn := []byte(`{"model":"x","tools":[{"name":"ClientOwn"}],"messages":[]}`)
	got = applyClaudeVersionTools(withOwn, p.Variants[1].Tools)
	if gjson.GetBytes(got, "tools.0.name").String() != "ClientOwn" {
		t.Error("已有 tools 时被覆盖了")
	}
}
