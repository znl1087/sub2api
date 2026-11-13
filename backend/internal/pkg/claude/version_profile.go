package claude

import (
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

// 本文件定义"按客户端版本区分的出站特征"。
//
// 为什么需要它：单一版本号被所有账号共用时，池子里几十个账号在 Anthropic 眼里
// 全是同一台机器的同一个客户端，版本号一起跳变本身就是不自然的信号；真实用户是
// 陆续升级的，升级前后并存多个版本。特征库（versionprofiles/profiles.json）保留最近
// 若干个版本，每个版本带一套自洽的可观测特征（UA / billing 版本 / stainless 头 /
// beta 集合 / 报文模板 / TLS 握手形态），由账号各自固定使用。
//
// 一致性铁律：同一个请求的 User-Agent、billing cc_version、beta 集合、X-Stainless-*
// 头、system 块、tools、TLS 握手必须来自同一个 VersionProfile，任何一处用了别的版本
// 都会被判成拼接痕迹。

// TLSVariant 表示该版本客户端底层运行时的握手形态。
type TLSVariant string

const (
	// TLSVariantLegacy 是旧运行时（Node 26.3 / OpenSSL 3.2）：经典曲线打头，
	// 签名算法少 rsa_pss_pss_sha256 与 rsa_pkcs1_sha224 两项。
	TLSVariantLegacy TLSVariant = "legacy"
	// TLSVariantPostQuantum 是新运行时（Node 26.12 / OpenSSL 3.5）：X25519MLKEM768
	// 打头，签名算法 11 项。2.1.311 起的真机抓包即此形态，且最近 10 个版本完全一致。
	TLSVariantPostQuantum TLSVariant = "post-quantum"
)

// ModelBetaExtra 是某模型族追加的一条 beta 及其插入位置。
type ModelBetaExtra struct {
	Beta  string `json:"beta"`
	After string `json:"after"`
}

// ModelBetaRule 描述一个模型族对 anthropic-beta 集合的影响。
//
// 实测事实（2.1.323 真机抓包，逐个模型）：
//   - claude-sonnet-4-5：7 项基础集，无附加；
//   - claude-opus-4-5：+advisor-tool、+effort；
//   - claude-{opus,sonnet,haiku}-5-5、claude-fable-5-2：+per-turn-control、
//     +mid-conversation-tool-changes、+inline-tools、+advisor-tool、+effort；
//   - haiku 整串顺序与前两者不同（oauth 提前到首位）。
//
// 所以 beta 由「版本基础集」+「模型族规则」共同决定，两者缺一都会露出破绽。
type ModelBetaRule struct {
	// Family 是模型 ID 的正则前缀（按声明顺序取第一条命中）。
	// 用正则而非通配：claude-*-5-* 会误配 claude-sonnet-4-5，必须按段锚定。
	Family string `json:"family"`
	// Extra 是追加项及插入锚点（空锚点表示追加到末尾）。
	Extra []ModelBetaExtra `json:"extra"`
	// Order 非空时整体覆盖最终顺序（用于 haiku 这类特例排序）。
	Order []string `json:"order"`

	re *regexp.Regexp
}

// VersionProfile 是单个客户端版本的完整出站特征。
// 字段全部来自该版本真实二进制与真机抓包，由 cmd/ccversionprobe 提取，不按版本区间推算。
type VersionProfile struct {
	// Version 三段 semver，同时用于 UA 与 billing cc_version。
	Version string `json:"version"`
	// PublishedAt 是该版本的 npm 发布时间（YYYY-MM-DD），用于错峰升级排期。
	PublishedAt string `json:"publishedAt"`
	// StainlessPackageVersion / StainlessRuntimeVersion / StainlessOS / StainlessArch
	// 是 X-Stainless-* 头取值。
	StainlessPackageVersion string `json:"stainlessPackageVersion"`
	StainlessRuntimeVersion string `json:"stainlessRuntimeVersion"`
	StainlessOS             string `json:"stainlessOS"`
	StainlessArch           string `json:"stainlessArch"`
	// BunVersion 是打包该版本所用的 Bun 版本，TLS 变体与运行时版本都由它派生，
	// 保留原始值便于复核。
	BunVersion string `json:"bunVersion"`
	// BaseBetas 是该版本真实携带的 anthropic-beta 基础集（有序，缺项即该版本没有）。
	// 模型族附加项由 ModelBetaRules 叠加，见 BetasForModel。
	BaseBetas []string `json:"baseBetas"`
	// TLSVariant 决定握手形态。
	TLSVariant TLSVariant `json:"tlsVariant"`

	// IdentityPrompt 是该版本 system[1] 身份句原文（版本快照）。
	IdentityPrompt string `json:"-"`
	// Variants 是按模型族分档的 system[2] 主 prompt 与 tools 快照。
	// 同一版本下这两项随模型代次变化，必须分档，见 PromptForModel。
	Variants []PromptVariant `json:"-"`
}

// PromptVariant 是某个模型族的 prompt/tools 快照；Family 为空表示兜底档。
type PromptVariant struct {
	Family string
	Prompt string
	Tools  []byte

	re *regexp.Regexp
}

// PromptForModel 返回该版本对指定模型应发出的身份句、主 prompt 与 tools。
//
// 命中族规则用该族的档；都没命中用兜底档。prompt 为空表示该版本没有模板，
// 调用方应保留客户端自带内容。tools 可能为空（抓包没带 tools）。
func (p VersionProfile) PromptForModel(modelID string) (identity, prompt string, tools []byte) {
	if len(p.Variants) == 0 {
		return p.IdentityPrompt, "", nil
	}
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	for _, v := range p.Variants {
		if v.re != nil && v.re.MatchString(modelID) {
			return p.IdentityPrompt, v.Prompt, v.Tools
		}
	}
	for _, v := range p.Variants {
		if v.Family == "" {
			return p.IdentityPrompt, v.Prompt, v.Tools
		}
	}
	return p.IdentityPrompt, "", nil
}

// UserAgent 返回该版本的 User-Agent。
func (p VersionProfile) UserAgent() string {
	return claudeCLIProduct + "/" + p.Version + " (external, sdk-cli)"
}

// BetasForModel 返回该版本对指定模型会发出的完整 anthropic-beta 列表（有序）。
//
// 未命中任何模型族规则时只返回基础集——这正是老模型的行为，不做兜底放大：
// 给 4-5 代模型多塞 5 代 beta 会被上游按"不该有的能力"识别。
func (p VersionProfile) BetasForModel(modelID string) []string {
	out := make([]string, len(p.BaseBetas))
	copy(out, p.BaseBetas)

	rule, ok := matchModelBetaRule(modelID)
	if !ok {
		return out
	}
	for _, e := range rule.Extra {
		if e.Beta == "" || containsBeta(out, e.Beta) {
			continue
		}
		out = insertBetaAfter(out, e.Beta, e.After)
	}
	if len(rule.Order) > 0 {
		out = orderBetas(out, rule.Order)
	}
	return out
}

// Headers 返回该版本完整的出站请求头（不含 Authorization 与 Host）。
//
// 顺序按真机抓包固定，Go 的 map 会丢顺序，所以返回有序切片。
// X-Stainless-Timeout / Retry-Count 是每次请求都带的固定值，随版本一起给。
func (p VersionProfile) Headers() [][2]string {
	return [][2]string{
		{"Accept", "application/json"},
		{"Content-Type", "application/json"},
		{"User-Agent", p.UserAgent()},
		{"X-Stainless-Arch", p.StainlessArch},
		{"X-Stainless-Lang", "js"},
		{"X-Stainless-OS", p.StainlessOS},
		{"X-Stainless-Package-Version", p.StainlessPackageVersion},
		{"X-Stainless-Retry-Count", "0"},
		{"X-Stainless-Runtime", "node"},
		{"X-Stainless-Runtime-Version", p.StainlessRuntimeVersion},
		{"X-Stainless-Timeout", "300"},
		{"anthropic-dangerous-direct-browser-access", "true"},
		{"anthropic-version", "2023-06-01"},
		{"x-app", "cli"},
	}
}

// TLSProfile 返回该版本对应的 TLS 指纹配置。
// 两个变体都建立在同一份 Bun/OpenSSL 基线之上，差异只在后量子组与签名算法两项。
func (p VersionProfile) TLSProfile() *tlsfingerprint.Profile {
	profile := &tlsfingerprint.Profile{
		Name: "Claude Code " + p.Version + " (external, sdk-cli)",
	}
	if p.TLSVariant == TLSVariantLegacy {
		// Node 26.3 / OpenSSL 3.2：只有经典曲线，且不带 0x0807 / 0x0603 两个签名算法。
		profile.Curves = []uint16{0x001d, 0x0017, 0x0018}
		profile.KeyShareGroups = []uint16{0x001d}
		profile.SignatureAlgorithms = []uint16{
			0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
		}
	}
	// 其余字段留空 = 使用 dialer 的内置默认（cipher / 扩展顺序 / ALPN / 版本等），
	// 该默认已由 TestClientHelloParityAgainstRealCapture 与真机抓包逐字节对齐。
	return profile
}

// claudeCLIProduct 是 UA 产品名。
const claudeCLIProduct = "claude-cli"

// BuildVersionProfile 返回指定版本的完整特征。
//
// 优先级：特征库精确命中 → 特征库最新记录（版本号仍用传入值，适用于库尚未收录的
// 新版本，保证 UA/cc_version 真实、其余特征跟随最新客户端）→ 内置兜底（特征库损坏）。
func BuildVersionProfile(version string) VersionProfile {
	version = strings.TrimSpace(version)
	if version != "" {
		if p, ok := LookupVersionProfile(version); ok {
			return p
		}
		if latest, err := LatestVersionProfile(); err == nil {
			latest.Version = version
			return latest
		}
		return builtinFallbackProfile(version)
	}
	if latest, err := LatestVersionProfile(); err == nil {
		return latest
	}
	return builtinFallbackProfile("")
}

// builtinFallbackProfile 是特征库不可用时的最后兜底，字段与最新库记录保持同一代。
func builtinFallbackProfile(version string) VersionProfile {
	return VersionProfile{
		Version:                 version,
		StainlessPackageVersion: "0.128.0",
		StainlessRuntimeVersion: "v26.12.1",
		StainlessOS:             "Windows",
		StainlessArch:           "x64",
		BaseBetas:               []string{"claude-code-20250219", "oauth-2025-04-20"},
		TLSVariant:              TLSVariantPostQuantum,
	}
}

// matchModelBetaRule 按声明顺序返回第一条命中的模型族规则。
func matchModelBetaRule(modelID string) (ModelBetaRule, bool) {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	if modelID == "" {
		return ModelBetaRule{}, false
	}
	rulesOnce.Do(loadModelBetaRules)
	for _, r := range modelBetaRules {
		if r.re != nil && r.re.MatchString(modelID) {
			return r, true
		}
	}
	return ModelBetaRule{}, false
}

var (
	rulesOnce      sync.Once
	modelBetaRules []ModelBetaRule
)

func loadModelBetaRules() {
	rules, err := LibraryModelBetaRules()
	if err != nil {
		return
	}
	modelBetaRules = rules
}

func containsBeta(list []string, beta string) bool {
	for _, b := range list {
		if b == beta {
			return true
		}
	}
	return false
}

// insertBetaAfter 把 beta 插到锚点之后；锚点缺失则追加到末尾。
func insertBetaAfter(list []string, beta, after string) []string {
	if after != "" {
		for i, b := range list {
			if b == after {
				out := make([]string, 0, len(list)+1)
				out = append(out, list[:i+1]...)
				out = append(out, beta)
				return append(out, list[i+1:]...)
			}
		}
	}
	return append(list, beta)
}

// orderBetas 按模板顺序重排，模板未覆盖的项保持原相对顺序追加在后。
func orderBetas(list []string, order []string) []string {
	present := make(map[string]struct{}, len(list))
	for _, b := range list {
		present[b] = struct{}{}
	}
	out := make([]string, 0, len(list))
	for _, b := range order {
		if _, ok := present[b]; ok {
			out = append(out, b)
			delete(present, b)
		}
	}
	for _, b := range list {
		if _, ok := present[b]; ok {
			out = append(out, b)
			delete(present, b)
		}
	}
	return out
}

// compareVersions 按三段 semver 比较，语义同 service.CompareVersions。
// claude 包不能引用 service（service 已引用 claude），故本地实现一份。
func compareVersions(a, b string) int {
	pa, pb := parseVersionParts(a), parseVersionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	return 0
}

func parseVersionParts(v string) [3]int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	out := [3]int{0, 0, 0}
	for i := 0; i < len(parts) && i < 3; i++ {
		if n, err := strconv.Atoi(parts[i]); err == nil {
			out[i] = n
		}
	}
	return out
}
