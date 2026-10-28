package service

import "testing"

// `claude -p`（SDK 入口）的 system prompt 与官方 TUI 不同族，UA 校验器的相似度
// 判定会失败。带 billing attribution block 的 body 必须仍被认作真客户端，
// 否则真 CLI 会被全量 mimic：system 被替换、cc_version 指纹被按 body 重算。
func TestSystemHasBillingAttributionBlockRecognizesSDKPrefix(t *testing.T) {
	body := []byte(`{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.311.d47; cc_entrypoint=sdk-cli;"},{"type":"text","text":"You are a Claude agent, built on Anthropic's Claude Agent SDK."}],"messages":[{"role":"user","content":"hi"}]}`)
	if !systemHasBillingAttributionBlock(body) {
		t.Fatal("billing block not detected")
	}

	// 缺 entrypoint 标记（伪造/旧版）不算
	noMarker := []byte(`{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.311.d47;"}]}`)
	if systemHasBillingAttributionBlock(noMarker) {
		t.Fatal("marker-less billing block should not count")
	}

	// 官方 TUI 文案同样识别
	tui := []byte(`{"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.311.9cf; cc_entrypoint=cli;"}]}`)
	if !systemHasBillingAttributionBlock(tui) {
		t.Fatal("cli entrypoint not detected")
	}
}
