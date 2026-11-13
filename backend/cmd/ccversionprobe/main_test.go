package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baseBetasFixture = "claude-code-20250219,oauth-2025-04-20,context-management-2025-06-27"

// rawFixture 造一份最小可解析的抓包：三个 system 块（billing / 身份句 / 主 prompt）。
func rawFixture(version, model, betas string) string {
	long := strings.Repeat("You are an agent working with the user. ", 60)
	body := `{"model":"` + model + `","system":[` +
		`{"type":"text","text":"x-anthropic-billing-header: cc_version=` + version + `.abc; cc_entrypoint=sdk-cli;"},` +
		`{"type":"text","text":"You are a Claude agent, built on Anthropic's Claude Agent SDK."},` +
		`{"type":"text","text":"` + long + `"}` +
		`],"tools":[{"name":"Bash","input_schema":{"type":"object"}}]}`
	return "POST /v1/messages?beta=true HTTP/1.1\r\n" +
		"User-Agent: claude-cli/" + version + " (external, sdk-cli)\r\n" +
		"X-Stainless-Arch: x64\r\n" +
		"X-Stainless-OS: Linux\r\n" +
		"X-Stainless-Package-Version: 0.128.0\r\n" +
		"X-Stainless-Runtime-Version: v26.12.1\r\n" +
		"anthropic-beta: " + betas + "\r\n" +
		"\r\n" + body
}

func writeCapture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".raw"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseCaptureFile(t *testing.T) {
	dir := t.TempDir()
	writeCapture(t, dir, "claude-sonnet-4-5", rawFixture("2.1.323", "claude-sonnet-4-5", baseBetasFixture))

	cap, err := parseCaptureFile(filepath.Join(dir, "claude-sonnet-4-5.raw"), "oauth")
	if err != nil {
		t.Fatalf("parseCaptureFile: %v", err)
	}
	if cap.Model != "claude-sonnet-4-5" {
		t.Errorf("model = %q", cap.Model)
	}
	if len(cap.Betas) != 3 || cap.Betas[1] != "oauth-2025-04-20" {
		t.Errorf("betas = %v", cap.Betas)
	}
	if cap.OS != "Linux" || cap.Arch != "x64" || cap.Runtime != "v26.12.1" {
		t.Errorf("stainless = %s/%s/%s", cap.OS, cap.Arch, cap.Runtime)
	}
	// 主 prompt 必须是那个长块，不能是 billing 头或身份句。
	if !strings.HasPrefix(cap.Prompt, "You are an agent working with the user.") {
		t.Errorf("prompt 选错: %.60q", cap.Prompt)
	}
	if cap.Tools == nil || !strings.Contains(string(cap.Tools), "\n ") {
		t.Errorf("tools 未按可读格式输出: %q", string(cap.Tools))
	}
}

func TestLoadCapturesRejectsVersionMismatch(t *testing.T) {
	root := t.TempDir()
	writeCapture(t, filepath.Join(root, "2.1.323", "oauth"), "claude-sonnet-4-5",
		rawFixture("2.1.322", "claude-sonnet-4-5", baseBetasFixture))

	if _, err := loadCaptures(root, "2.1.323", false); err == nil {
		t.Fatal("版本不一致应报错")
	}
	if _, err := loadCaptures(root, "2.1.323", true); err != nil {
		t.Fatalf("允许不一致时不应报错: %v", err)
	}
}

func TestBuildRecordDerivesIntersectionAndRules(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "2.1.323", "oauth")
	writeCapture(t, dir, "claude-sonnet-4-5", rawFixture("2.1.323", "claude-sonnet-4-5", baseBetasFixture))
	writeCapture(t, dir, "claude-haiku-5-5", rawFixture("2.1.323", "claude-haiku-5-5",
		"oauth-2025-04-20,"+baseBetasFixture+",effort-2025-11-24"))

	caps, err := loadCaptures(root, "2.1.323", false)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "profiles.json")
	p, rules, models, err := buildRecord("2.1.323", caps, nil, "2026-11-12", profile{}, false, out)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}

	// 基础集取交集：haiku 多出来的 effort 不能进 baseBetas。
	if strings.Contains(strings.Join(p.BaseBetas, ","), "effort") {
		t.Errorf("baseBetas 混入了模型专属项: %v", p.BaseBetas)
	}
	if len(p.BaseBetas) != 3 {
		t.Errorf("baseBetas = %v", p.BaseBetas)
	}
	if p.TLSVariant != "post-quantum" || p.CaptureKind != "oauth" {
		t.Errorf("tls=%q kind=%q", p.TLSVariant, p.CaptureKind)
	}
	if p.IdentitySHA256 == "" || p.IdentityFile == "" {
		t.Error("身份句模板未落盘")
	}
	// 模板必须真的落盘，且内容与哈希一致。
	if got := sha256Hex(mustRead(t, filepath.Join(filepath.Dir(out), p.IdentityFile))); got != p.IdentitySHA256 {
		t.Errorf("身份句哈希不匹配文件: %s", got)
	}
	// 每个模型各一档 + 兜底档；兜底档必须在最后。
	if len(p.Variants) != 2 {
		t.Fatalf("variants = %d, want 2", len(p.Variants))
	}
	if p.Variants[len(p.Variants)-1].Family != "" {
		t.Error("兜底档不在最后")
	}
	for _, v := range p.Variants {
		if got := sha256Hex(mustRead(t, filepath.Join(filepath.Dir(out), v.PromptFile))); got != v.PromptSHA256 {
			t.Errorf("%q 档 prompt 哈希不匹配文件: %s", v.Family, got)
		}
	}
	if len(rules) != 1 {
		t.Fatalf("规则数 = %d, want 1", len(rules))
	}
	if rules[0].Family != `^claude-haiku-5-5($|-)` {
		t.Errorf("family = %q", rules[0].Family)
	}
	// haiku 抓包顺序把 oauth 提到了最前，必须被识别为顺序特例。
	if len(rules[0].Order) == 0 {
		t.Error("顺序差异未记为 order 特例")
	}
	if sameOrder(applyRules(p.BaseBetas, rules, "claude-haiku-5-5"), models["claude-haiku-5-5"]) == false {
		t.Error("推导出的规则回放不出原抓包")
	}
}

func TestApplyRulesDoesNotLeakAcrossFamilies(t *testing.T) {
	rules := []rule{{Family: `^claude-[a-z]+-5-[0-9]`, Extra: []ruleExtra{{Beta: "inline-tools-2026-09-15"}}}}
	base := []string{"claude-code-20250219", "oauth-2025-04-20"}

	// sonnet-4-5 结尾也是 -5，不能被 5 代规则吃掉。
	if got := applyRules(base, rules, "claude-sonnet-4-5"); len(got) != len(base) {
		t.Errorf("sonnet-4-5 命中了 5 代规则: %v", got)
	}
	if got := applyRules(base, rules, "claude-sonnet-5-5"); len(got) != len(base)+1 {
		t.Errorf("sonnet-5-5 未命中规则: %v", got)
	}
}

func TestFamilyForStripsSnapshotDate(t *testing.T) {
	if got := familyFor("claude-sonnet-4-5-20250929"); got != `^claude-sonnet-4-5($|-)` {
		t.Errorf("familyFor = %q", got)
	}
}

func TestTLSVariantFor(t *testing.T) {
	cases := map[string]string{
		"v26.3.0":  "legacy",
		"v26.12.1": "post-quantum",
		"v27.0.0":  "post-quantum",
		"v25.9.0":  "legacy",
	}
	for in, want := range cases {
		if got := tlsVariantFor(in); got != want {
			t.Errorf("tlsVariantFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// 收敛后的族必须仍能命中同代任意快照，且不能吃掉 sonnet-4-5 这类「以 -5 结尾」的旧族。
func TestDedupeRulesBroadensFamilies(t *testing.T) {
	in := []rule{
		{Family: familyFor("claude-opus-4-5"), Extra: []ruleExtra{{Beta: "advisor-tool-2026-03-01"}}},
		{Family: familyFor("claude-haiku-5-5"), Extra: []ruleExtra{{Beta: "effort-2025-11-24"}}},
		{Family: familyFor("claude-opus-5-5"), Extra: []ruleExtra{{Beta: "effort-2025-11-24"}}},
		{Family: familyFor("claude-sonnet-5-5"), Extra: []ruleExtra{{Beta: "effort-2025-11-24"}}},
	}
	got := dedupeRules(in)

	want := []string{"^claude-opus-4-5", "^claude-haiku-[a-z]*-?5-[0-9]", "^claude-[a-z]+-5-[0-9]"}
	if len(got) != len(want) {
		t.Fatalf("dedupeRules 得到 %d 条，want %d：%+v", len(got), len(want), got)
	}
	for i, family := range want {
		if got[i].Family != family {
			t.Fatalf("第 %d 条 family = %q, want %q", i, got[i].Family, family)
		}
	}

	base := []string{"claude-code-20250219", "oauth-2025-04-20"}
	for _, model := range []string{"claude-haiku-5-5-20251001", "claude-opus-5-5", "claude-sonnet-5-5"} {
		if out := applyRules(base, got, model); len(out) != len(base)+1 {
			t.Errorf("%s 未命中 5 代规则: %v", model, out)
		}
	}
	if out := applyRules(base, got, "claude-sonnet-4-5"); len(out) != len(base) {
		t.Errorf("sonnet-4-5 被 5 代规则吃掉: %v", out)
	}
	// haiku-4-5 真机是 base+advisor（8 项），既不能落到 haiku-5 泛族，也不能完全没规则。
	if out := applyRules(base, got, "claude-haiku-4-5"); len(out) != len(base) {
		t.Errorf("haiku-4-5 被 haiku-5 泛族吃掉: %v", out)
	}
	withHaiku45 := append([]rule{{Family: "^claude-haiku-4-5", Extra: []ruleExtra{{Beta: "advisor-tool-2026-03-01"}}}}, got...)
	if out := applyRules(base, withHaiku45, "claude-haiku-4-5"); len(out) != len(base)+1 {
		t.Errorf("haiku-4-5 规则未生效: %v", out)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 抓包机的绝对路径必须归一，否则模板会暴露本机用户名与临时目录。
func TestNormalizePromptPath(t *testing.T) {
	win := "You have a persistent memory at `C://Users//Neil//AppData//Local//Temp//ccprobe//run//2.1.323//sonnet-4-5//.claude//projects//C--Users-Neil-AppData-Local-Temp-ccprobe-cwd//memory//`. Done."
	got := normalizePromptPath(win)
	if strings.Contains(got, "Neil") || strings.Contains(got, "ccprobe") {
		t.Fatalf("Windows 路径未归一: %q", got)
	}
	if !strings.Contains(got, canonicalWinMemoryPath) && !strings.Contains(got, canonicalWinMemoryPathAlt) {
		t.Fatalf("未替换成规范路径: %q", got)
	}

	posix := "memory at `/tmp/ccprobe/run/2.1.323/opus-5-5/.claude/projects/-tmp-ccprobe-cwd/memory/`. Done."
	got = normalizePromptPath(posix)
	if strings.Contains(got, "ccprobe") || !strings.Contains(got, canonicalPosixMemoryPath) {
		t.Fatalf("POSIX 路径未归一: %q", got)
	}

	// 不含抓包路径的文本必须原样返回。
	plain := "no path here"
	if normalizePromptPath(plain) != plain {
		t.Fatal("无关文本被改动")
	}
}

// 已落库的模板不能残留抓包机的任何本地信息。
func TestTemplatesHaveNoLocalPath(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "pkg", "claude", "versionprofiles")
	var files []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(p, "prompt.txt") || strings.HasSuffix(p, "identity.txt")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("没找到任何模板文件")
	}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, leak := range []string{"ccprobe", "AppData\\Local\\Temp", "C--Users-Neil"} {
			if strings.Contains(s, leak) {
				t.Errorf("%s 残留 %q", p, leak)
			}
		}
	}
}
