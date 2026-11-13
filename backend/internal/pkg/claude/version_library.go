package claude

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// 本文件是"客户端版本特征库"的加载层。
//
// 特征库是编译期资产，与业务代码完全解耦：新增版本只是重跑 cmd/ccversionprobe
// 产出新记录与报文模板 + 重新编译，不改任何判断逻辑。
//
// 目录结构：
//
//	versionprofiles/profiles.json                    版本索引（特征 + 模板文件引用）
//	versionprofiles/<version>/identity.txt           该版本 system[1] 身份句快照
//	versionprofiles/<version>/<model-slug>/prompt.txt    该模型族的 system[2] 主 prompt 快照
//	versionprofiles/<version>/<model-slug>/tools.json    该模型族的 tools 数组快照
//
// 模板按模型族分档是实测结论：同一版本下 prompt 与 tools 都随模型代次变化
// （2.1.323：sonnet-4-5 主 prompt 27082B / opus-5-5 6740B，4-5 代与 5 代 tools 不同），
// 只存一份会在换模型时立刻露馅。
//
// 设计约束：
//   - 只保留最近 MaxLibraryVersions 个版本。Claude Code 客户端会自动更新，用户机器上
//     实际并存的版本就是最近若干个；更老的版本没有拟真价值，反而拖长攻击面。
//   - 每条记录的特征必须来自该版本真实二进制与真机抓包，不允许按版本号区间推算
//     ——历史事实证明推算会错。
//   - 加载后按版本降序排列（最新在前），权重分配依赖这个顺序。
//   - 校验失败整体返回 error，不做静默降级：坏数据在编译期就该被发现。
//   - 报文模板缺失只降级不报错：模板用于"完整报文一致"，缺了仍可用头/体版本特征。

// MaxLibraryVersions 是特征库向运行期暴露的版本数上限。
const MaxLibraryVersions = 10

//go:embed versionprofiles
var versionProfilesFS embed.FS

const versionProfilesIndexPath = "versionprofiles/profiles.json"

// libraryFile 是 profiles.json 的顶层结构。
type libraryFile struct {
	SchemaVersion  int             `json:"schemaVersion"`
	GeneratedAt    string          `json:"generatedAt"`
	Source         string          `json:"source"`
	Profiles       []libraryEntry  `json:"profiles"`
	ModelBetaRules []ModelBetaRule `json:"modelBetaRules"`
}

type libraryEntry struct {
	Version                 string           `json:"version"`
	PublishedAt             string           `json:"publishedAt"`
	StainlessPackageVersion string           `json:"stainlessPackageVersion"`
	StainlessRuntimeVersion string           `json:"stainlessRuntimeVersion"`
	StainlessOS             string           `json:"stainlessOS"`
	StainlessArch           string           `json:"stainlessArch"`
	BunVersion              string           `json:"bunVersion"`
	TLSVariant              string           `json:"tlsVariant"`
	BaseBetas               []string         `json:"baseBetas"`
	IdentityFile            string           `json:"identityFile"`
	IdentitySHA256          string           `json:"identitySHA256"`
	Variants                []libraryVariant `json:"variants"`
}

// libraryVariant 是某个模型族的 prompt/tools 模板引用，family 为空表示兜底档。
type libraryVariant struct {
	Family       string `json:"family"`
	PromptFile   string `json:"promptFile"`
	PromptSHA256 string `json:"promptSHA256"`
	ToolsFile    string `json:"toolsFile"`
	ToolsSHA256  string `json:"toolsSHA256"`
}

var (
	libraryOnce sync.Once
	libraryList []VersionProfile
	libraryErr  error
	rulesList   []ModelBetaRule
)

// Library 返回按版本降序（最新在前）排列的特征库快照，最多 MaxLibraryVersions 条。
// 返回值是副本，调用方可自由持有。
func Library() ([]VersionProfile, error) {
	libraryOnce.Do(func() {
		libraryList, rulesList, libraryErr = parseLibrary()
	})
	if libraryErr != nil {
		return nil, libraryErr
	}
	out := make([]VersionProfile, len(libraryList))
	copy(out, libraryList)
	return out, nil
}

// LibraryModelBetaRules 返回模型族 beta 规则（按声明顺序，首条命中生效）。
func LibraryModelBetaRules() ([]ModelBetaRule, error) {
	if _, err := Library(); err != nil {
		return nil, err
	}
	out := make([]ModelBetaRule, len(rulesList))
	copy(out, rulesList)
	return out, nil
}

// LatestVersionProfile 返回特征库中最新的一条记录。
func LatestVersionProfile() (VersionProfile, error) {
	list, err := Library()
	if err != nil {
		return VersionProfile{}, err
	}
	if len(list) == 0 {
		return VersionProfile{}, fmt.Errorf("claude: version profile library is empty")
	}
	return list[0], nil
}

// LookupVersionProfile 按版本号精确查找记录。
func LookupVersionProfile(version string) (VersionProfile, bool) {
	list, err := Library()
	if err != nil {
		return VersionProfile{}, false
	}
	version = strings.TrimSpace(version)
	for _, p := range list {
		if p.Version == version {
			return p, true
		}
	}
	return VersionProfile{}, false
}

// LibraryVersions 返回特征库里的全部版本号，最新在前。
func LibraryVersions() []string {
	list, err := Library()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, p.Version)
	}
	return out
}

func parseLibrary() ([]VersionProfile, []ModelBetaRule, error) {
	raw, err := versionProfilesFS.ReadFile(versionProfilesIndexPath)
	if err != nil {
		return nil, nil, fmt.Errorf("claude: read version profile library: %w", err)
	}
	var file libraryFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, nil, fmt.Errorf("claude: parse version profile library: %w", err)
	}
	if file.SchemaVersion != 2 {
		return nil, nil, fmt.Errorf("claude: unsupported version profile schema %d", file.SchemaVersion)
	}
	if len(file.Profiles) == 0 {
		return nil, nil, fmt.Errorf("claude: version profile library has no entries")
	}

	seen := make(map[string]struct{}, len(file.Profiles))
	out := make([]VersionProfile, 0, len(file.Profiles))
	for _, e := range file.Profiles {
		version := strings.TrimSpace(e.Version)
		if err := validateProfileVersion(version); err != nil {
			return nil, nil, err
		}
		if _, dup := seen[version]; dup {
			return nil, nil, fmt.Errorf("claude: duplicate version profile %q", version)
		}
		seen[version] = struct{}{}

		variant := TLSVariant(strings.TrimSpace(e.TLSVariant))
		if variant != TLSVariantLegacy && variant != TLSVariantPostQuantum {
			return nil, nil, fmt.Errorf("claude: version %q has invalid tlsVariant %q", version, e.TLSVariant)
		}
		if !isDottedTriple(e.StainlessPackageVersion) {
			return nil, nil, fmt.Errorf("claude: version %q has invalid stainless package version %q", version, e.StainlessPackageVersion)
		}
		if !isRuntimeVersion(e.StainlessRuntimeVersion) {
			return nil, nil, fmt.Errorf("claude: version %q has invalid stainless runtime version %q", version, e.StainlessRuntimeVersion)
		}
		if len(e.BaseBetas) == 0 {
			return nil, nil, fmt.Errorf("claude: version %q has empty base beta set", version)
		}

		betas := make([]string, len(e.BaseBetas))
		copy(betas, e.BaseBetas)

		profile := VersionProfile{
			Version:                 version,
			PublishedAt:             strings.TrimSpace(e.PublishedAt),
			StainlessPackageVersion: e.StainlessPackageVersion,
			StainlessRuntimeVersion: e.StainlessRuntimeVersion,
			StainlessOS:             strings.TrimSpace(e.StainlessOS),
			StainlessArch:           strings.TrimSpace(e.StainlessArch),
			BunVersion:              e.BunVersion,
			BaseBetas:               betas,
			TLSVariant:              variant,
			IdentityPrompt:          readTemplate(e.IdentityFile),
		}
		variants, err := buildPromptVariants(version, e.Variants)
		if err != nil {
			return nil, nil, err
		}
		profile.Variants = variants
		out = append(out, profile)
	}

	// 降序：最新在前。权重表与"最新优先兜底"都依赖这个顺序。
	sort.Slice(out, func(i, j int) bool { return compareVersions(out[i].Version, out[j].Version) > 0 })
	if len(out) > MaxLibraryVersions {
		out = out[:MaxLibraryVersions]
	}
	return out, sanitizeModelBetaRules(file.ModelBetaRules), nil
}

// buildPromptVariants 编译并加载各模型族的模板档。
//
// 要求恰好有一个兜底档（family 为空）：没有兜底档时，族外模型只能退回客户端自带
// prompt，行为随调用方变化；多份兜底档则先到先得，都是不确定的。
func buildPromptVariants(version string, in []libraryVariant) ([]PromptVariant, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]PromptVariant, 0, len(in))
	defaults := 0
	for _, v := range in {
		family := strings.TrimSpace(v.Family)
		promptFile := strings.TrimSpace(v.PromptFile)
		if promptFile == "" {
			return nil, fmt.Errorf("claude: version %q has a variant without promptFile", version)
		}
		variant := PromptVariant{
			Family: family,
			Prompt: readTemplate(promptFile),
			Tools:  []byte(readTemplate(v.ToolsFile)),
		}
		if family == "" {
			defaults++
		} else {
			re, err := regexp.Compile("(?i)" + family)
			if err != nil {
				return nil, fmt.Errorf("claude: version %q has invalid variant family %q: %w", version, family, err)
			}
			variant.re = re
		}
		if variant.Prompt == "" {
			// 模板文件缺失：整档保留但记空，运行期会退到客户端自带内容。
			continue
		}
		out = append(out, variant)
	}
	if defaults == 0 && len(out) > 0 {
		return nil, fmt.Errorf("claude: version %q has no default prompt variant", version)
	}
	return out, nil
}

// readTemplate 读取模板文件；缺失返回空串，交由出站层走兜底。
func readTemplate(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	data, err := versionProfilesFS.ReadFile("versionprofiles/" + path)
	if err != nil {
		return ""
	}
	return string(data)
}

// sanitizeModelBetaRules 丢掉空 family / 空 beta 的脏规则，保持声明顺序。
func sanitizeModelBetaRules(in []ModelBetaRule) []ModelBetaRule {
	out := make([]ModelBetaRule, 0, len(in))
	for _, r := range in {
		family := strings.TrimSpace(r.Family)
		if family == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + family)
		if err != nil {
			continue
		}
		rule := ModelBetaRule{Family: family, re: re}
		for _, e := range r.Extra {
			if b := strings.TrimSpace(e.Beta); b != "" {
				rule.Extra = append(rule.Extra, ModelBetaExtra{Beta: b, After: strings.TrimSpace(e.After)})
			}
		}
		for _, b := range r.Order {
			if b = strings.TrimSpace(b); b != "" {
				rule.Order = append(rule.Order, b)
			}
		}
		out = append(out, rule)
	}
	return out
}

func validateProfileVersion(v string) error {
	if !isDottedTriple(v) {
		return fmt.Errorf("claude: invalid profile version %q", v)
	}
	return nil
}

// isDottedTriple 判断是否为恰好三段纯数字的版本号。
func isDottedTriple(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 6 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// isRuntimeVersion 判断是否为 vX.Y.Z 形态的运行时版本。
func isRuntimeVersion(v string) bool {
	return strings.HasPrefix(v, "v") && isDottedTriple(strings.TrimPrefix(v, "v"))
}
