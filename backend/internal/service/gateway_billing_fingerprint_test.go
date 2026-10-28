package service

import (
	"strings"
	"testing"
)

// 算法必须与真机 CLI 一致：sha256("59cf53e54c78" + 首条 user 文本的码元 4/7/20 + 版本)[:3]。
// 期望值由真机抓包反推：prompt "say OK" → 9cf；prompt "0123…89" → d81。
func TestComputeClaudeCodeFingerprintVectors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"short prompt pads with zeros", `{"messages":[{"role":"user","content":"say OK"}]}`, "9cf"},
		{"digits at sample offsets", `{"messages":[{"role":"user","content":"0123456789012345678901234567890123456789"}]}`, "d81"},
		{"meta message skipped", `{"messages":[{"role":"user","isMeta":true,"content":"zzzzzzzzzzzzzzzzzzzzzzz"},{"role":"user","content":"say OK"}]}`, "9cf"},
		{"no user message", `{"messages":[]}`, "972"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := computeClaudeCodeFingerprint([]byte(c.body), "2.1.311"); got != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
}

// 真 CLI 的指纹按归一化前的 prompt 算，归一化插入 reminder 后 body 就与指纹对不上了。
// 转发时必须按最终 body 重算覆写，让上游复算能对上。
func TestRefreshBillingAttributionFingerprintRewritesStaleValue(t *testing.T) {
	body := []byte(`{"model":"claude-sonnet-5","system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.311.d47; cc_entrypoint=sdk-cli;"},{"type":"text","text":"You are a Claude agent."}],"messages":[{"role":"user","content":"<system-reminder>abc</system-reminder>"}]}`)
	out := refreshBillingAttributionFingerprint(body)

	got := gjsonGet(out, "system.0.text")
	want := "x-anthropic-billing-header: cc_version=2.1.311." + computeClaudeCodeFingerprint(out, "2.1.311") + "; cc_entrypoint=sdk-cli;"
	if got != want {
		t.Fatalf("fingerprint not refreshed\n got=%s\nwant=%s", got, want)
	}
	if want == "x-anthropic-billing-header: cc_version=2.1.311.d47; cc_entrypoint=sdk-cli;" {
		t.Fatal("fixture already consistent, test proves nothing")
	}
	// 幂等：再跑一次不再变化
	if again := string(refreshBillingAttributionFingerprint(out)); again != string(out) {
		t.Fatal("not idempotent")
	}
	// 版本号不能被改
	if !strings.Contains(got, "cc_version=2.1.311.") {
		t.Fatalf("version changed: %s", got)
	}
}

// 没有 billing 块时原样返回。
func TestRefreshBillingAttributionFingerprintNoBlock(t *testing.T) {
	body := []byte(`{"system":[{"type":"text","text":"plain"}],"messages":[]}`)
	if string(refreshBillingAttributionFingerprint(body)) != string(body) {
		t.Fatal("body changed without billing block")
	}
}
