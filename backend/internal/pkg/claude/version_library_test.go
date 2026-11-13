package claude

import (
	"bytes"
	"strings"
	"testing"
)

// 本文件用真机抓包（2.1.323，OAuth 模式，逐模型）的原始 anthropic-beta 串做 golden。
// 任何规则改动导致与实测不符都必须让测试红掉——这是"请求体一致"的底线。
//
// 抓包命令见 cmd/ccversionprobe；原始记录：
//   claude-sonnet-4-5 → 7 项基础集
//   claude-opus-4-5   → 基础集 + advisor-tool + effort
//   claude-*-5-5      → 基础集 + per-turn + mid-conv + inline-tools + advisor + effort
//   claude-haiku-*    → 同上，但整串顺序不同（oauth 提前到首位）

const (
	goldenSonnet45 = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,thinking-token-count-2026-05-13,advanced-tool-use-2025-11-20,extended-cache-ttl-2025-04-11"
	goldenOpus45   = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,advisor-tool-2026-03-01,thinking-token-count-2026-05-13,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11"
	goldenSonnet55 = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,inline-tools-2026-09-15,advisor-tool-2026-03-01,thinking-token-count-2026-05-13,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11"
	goldenHaiku55  = "oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,claude-code-20250219,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,inline-tools-2026-09-15,advisor-tool-2026-03-01,thinking-token-count-2026-05-13,advanced-tool-use-2025-11-20,effort-2025-11-24,extended-cache-ttl-2025-04-11"
)

func TestBetasForModelMatchesCaptures(t *testing.T) {
	p, ok := LookupVersionProfile("2.1.323")
	if !ok {
		t.Fatalf("2.1.323 not in library; versions=%v", LibraryVersions())
	}
	cases := []struct{ model, want string }{
		{"claude-sonnet-4-5-20250929", goldenSonnet45},
		{"claude-opus-4-5-20251101", goldenOpus45},
		{"claude-sonnet-5-5", goldenSonnet55},
		{"claude-opus-5-5", goldenSonnet55},
		{"claude-fable-5-2", goldenSonnet55},
		{"claude-haiku-5-5", goldenHaiku55},
	}
	for _, c := range cases {
		got := strings.Join(p.BetasForModel(c.model), ",")
		if got != c.want {
			t.Errorf("model %s\n got=%s\nwant=%s", c.model, got, c.want)
		}
	}
}

func TestBetasForModelUnknownModelKeepsBase(t *testing.T) {
	p, _ := LookupVersionProfile("2.1.323")
	got := strings.Join(p.BetasForModel("claude-unknown-9"), ",")
	want := strings.Join(p.BaseBetas, ",")
	if got != want {
		t.Errorf("unknown model should keep base set\n got=%s\nwant=%s", got, want)
	}
	if strings.Contains(got, "per-turn-control") {
		t.Error("unknown model must not inherit 5th-gen betas")
	}
}

func TestModelBetaRuleMatch(t *testing.T) {
	// 命中即第一条规则生效，直接断言"实际选中的规则"而不是单条正则，
	// 才能覆盖规则声明顺序造成的遮蔽。
	want := map[string]string{
		"claude-haiku-5-5":          "^claude-haiku-[a-z]*-?5-[0-9]",
		"claude-haiku-4-5-20251001": "^claude-haiku-4-5",
		"claude-opus-4-5-20251101":  "^claude-opus-4-5",
		"claude-sonnet-5-5":         "^claude-[a-z]+-5-[0-9]",
		"claude-fable-5-2":          "^claude-[a-z]+-5-[0-9]",
	}
	for model, family := range want {
		r, ok := matchModelBetaRule(model)
		if !ok || r.Family != family {
			t.Errorf("model %q matched %q (ok=%v), want %q", model, r.Family, ok, family)
		}
	}
	// 4-5 代必须落不到 5 代规则上。
	r, _ := matchModelBetaRule("claude-sonnet-4-5-20250929")
	if r.Family == "^claude-[a-z]+-5-[0-9]" {
		t.Error("sonnet-4-5 must not match the 5th-gen rule")
	}
	// haiku-4-5 真机只有 advisor、没有 effort，不能落到 haiku-5 泛族上。
	h, _ := matchModelBetaRule("claude-haiku-4-5-20251001")
	if h.Family != "^claude-haiku-4-5" {
		t.Errorf("haiku-4-5 matched %q", h.Family)
	}
	if len(h.Extra) != 1 || h.Extra[0].Beta != "advisor-tool-2026-03-01" {
		t.Errorf("haiku-4-5 规则内容不符: %+v", h.Extra)
	}
}

func TestVersionProfileHeadersConsistent(t *testing.T) {
	p, _ := LookupVersionProfile("2.1.323")
	hdr := map[string]string{}
	for _, kv := range p.Headers() {
		hdr[kv[0]] = kv[1]
	}
	if got, want := hdr["User-Agent"], "claude-cli/2.1.323 (external, sdk-cli)"; got != want {
		t.Errorf("UA = %q, want %q", got, want)
	}
	if hdr["X-Stainless-Package-Version"] != p.StainlessPackageVersion {
		t.Error("stainless package version must come from the same profile as UA")
	}
	if hdr["X-Stainless-Runtime-Version"] != p.StainlessRuntimeVersion {
		t.Error("stainless runtime version must come from the same profile as UA")
	}
	if hdr["X-Stainless-Timeout"] != "300" || hdr["X-Stainless-Retry-Count"] != "0" {
		t.Error("fixed stainless headers missing")
	}
}

func TestLibraryTemplatesLoaded(t *testing.T) {
	p, ok := LookupVersionProfile("2.1.323")
	if !ok {
		t.Fatal("2.1.323 not in library")
	}
	if len(p.IdentityPrompt) == 0 {
		t.Fatal("identity template not loaded")
	}
	if len(p.Variants) < 2 {
		t.Fatalf("expected per-family prompt variants, got %d", len(p.Variants))
	}

	// 模型族分档必须真的分档：4-5 代与 5 代的 prompt 长度差一个量级。
	_, sonnet45, tools45 := p.PromptForModel("claude-sonnet-4-5-20250929")
	_, opus55, tools55 := p.PromptForModel("claude-opus-5-5")
	if len(sonnet45) < 20000 {
		t.Fatalf("sonnet-4-5 prompt too short (len=%d)", len(sonnet45))
	}
	if len(opus55) >= len(sonnet45) {
		t.Errorf("opus-5-5 prompt (%d) 应短于 sonnet-4-5 (%d)", len(opus55), len(sonnet45))
	}
	if bytes.Equal(tools45, tools55) {
		t.Error("4-5 代与 5 代 tools 相同，分档可能没生效")
	}
	if !strings.HasPrefix(sonnet45, "\nYou are an agent working with the user") {
		t.Errorf("prompt 内容不对: %.60q", sonnet45)
	}

	// 族外模型必须落到兜底档，而不是拿不到模板。
	_, unknown, _ := p.PromptForModel("claude-fable-9-9")
	if unknown == "" {
		t.Error("族外模型没有落到兜底档")
	}
}

func TestLibrarySchemaRejectsBadData(t *testing.T) {
	// 库内唯一一条记录必须能通过全部校验，否则说明数据文件已坏。
	if _, err := Library(); err != nil {
		t.Fatalf("library failed to load: %v", err)
	}
	if got := len(LibraryVersions()); got == 0 {
		t.Fatal("library is empty")
	}
}
