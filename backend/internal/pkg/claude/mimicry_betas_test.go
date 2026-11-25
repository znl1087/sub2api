package claude

import "testing"

func TestClaudeCodeMimicryBetasForModel(t *testing.T) {
	for _, model := range []string{
		"claude-haiku-4-5",
		"claude-sonnet-4-5-20250929",
		"claude-opus-4-5",
		"claude-haiku-5-5",
		"claude-opus-5-5",
		"claude-sonnet-5-5",
		"claude-fable-5-2",
	} {
		t.Run(model, func(t *testing.T) {
			betas := ClaudeCodeMimicryBetasForModel(model)
			// 2.1.330 抓包：所有代次都不带 per-turn-control，但仍带 mid-conversation-tool-changes。
			if contains(betas, BetaPerTurnControl) {
				t.Fatal("per-turn-control must be absent (2.1.330 wire)")
			}
			if !contains(betas, BetaMidConversationToolChanges) {
				t.Fatal("mid-conversation-tool-changes must stay")
			}
			if !contains(betas, BetaExtendedCacheTTL) {
				t.Fatal("extended-cache-ttl must stay")
			}
		})
	}
}

func TestClaudeCodeMimicryBetasKeepsWireOrder(t *testing.T) {
	got := ClaudeCodeMimicryBetasForModel("claude-haiku-4-5")
	want := []string{
		BetaClaudeCode,
		BetaOAuth,
		BetaInterleavedThinking,
		BetaContextManagement,
		BetaMidConversationToolChanges,
		BetaThinkingTokenCount,
		BetaAdvancedToolUse,
		BetaEffort,
		BetaDangerousToolUse,
		BetaAfkMode,
		BetaExtendedCacheTTL,
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("位置 %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
