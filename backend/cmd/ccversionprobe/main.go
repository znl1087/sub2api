// Command ccversionprobe 产出/更新客户端版本特征库
// internal/pkg/claude/versionprofiles/profiles.json 与每个版本的报文模板。
//
// 两条数据来源，分工明确：
//
//  1. 真机抓包（-capture，权威）：一个目录里放该版本对多个模型的完整 raw HTTP 请求
//     （<model>.raw，头部 + 空行 + body）。从这里读回 anthropic-beta、X-Stainless-*、
//     User-Agent、system 主 prompt、tools。baseBetas 取各模型 beta 集合的交集，
//     模型族附加项与特例排序推导为 modelBetaRules 候选。
//  2. npm 二进制（-no-binary 可跳过）：只用来补 bunVersion 并做交叉校验——二进制里
//     的 beta token 必须是抓包的超集，缺项说明 betaTokens 表过期了，会告警。
//
// 为什么不能按版本号推算：实测 2.1.200 已带 afk-mode 而 2.1.260 仍缺
// dangerous-tool-use，区间分界与真实流量对不上。
//
// 用法（在 backend 目录下）：
//
//	go run ./cmd/ccversionprobe -versions 2.1.323 -capture ../../captures
//	go run ./cmd/ccversionprobe -latest 10 -capture ../../captures -emit-rules
//	go run ./cmd/ccversionprobe -versions 2.1.323            # 无抓包，只出二进制特征
//
// 抓包目录约定：
//
//	<root>/<version>/<kind>/<model>.raw     kind 取 oauth 或 apikey
//
// 一个版本至少要抓到 4-5 代各一个模型：baseBetas 取各模型 beta 集合的交集，模型族
// 专属项推导成 modelBetaRules，prompt/tools 按模型族各存一档（实测两者都随代次变）。
//
// 生成的 profiles.json 与模板目录需要与代码一起提交；运行期只读，不联网。
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	registryBase  = "https://registry.npmjs.org"
	pkgName       = "@anthropic-ai/claude-code"
	schemaVersion = 2
	// maxKeep 与 claude.MaxLibraryVersions 保持一致：只留最近若干版本。
	maxKeep = 10
	// minPromptBytes 小于此长度的 system 块视为动态块（billing / 身份句），不当模板。
	minPromptBytes = 1024
)

// betaTokens 是二进制交叉校验用的探测集合，顺序即出站 beta header 的顺序。
var betaTokens = []string{
	"claude-code-20250219",
	"oauth-2025-04-20",
	"interleaved-thinking-2025-05-14",
	"context-management-2025-06-27",
	"per-turn-control-2026-07-01",
	"mid-conversation-tool-changes-2026-07-01",
	"inline-tools-2026-09-15",
	"thinking-token-count-2026-05-13",
	"advanced-tool-use-2025-11-20",
	"effort-2025-11-24",
	"dangerous-tool-use-2026-09-03",
	"afk-mode-2026-01-31",
	"extended-cache-ttl-2025-04-11",
}

var (
	reStainlessRef   = regexp.MustCompile(`"X-Stainless-Package-Version":([A-Za-z_$][A-Za-z0-9_$]*)`)
	reRuntimeLiteral = regexp.MustCompile(`"X-Stainless-Runtime-Version":globalThis\.process\.version\?\?"([^"]+)"`)
	reBunVersion     = regexp.MustCompile(`Bun v(\d+\.\d+\.\d+)`)
	reNodeVersion    = regexp.MustCompile(`v(2[0-9])\.(\d+)\.(\d+)`)
	reUserAgentVer   = regexp.MustCompile(`^claude-cli/(\d+\.\d+\.\d+) `)
	reSnapshotDate   = regexp.MustCompile(`-\d{8}$`)
	// reGen5Family 命中「第 5 代任意族」，用于把它们收敛成一条广义规则。
	reGen5Family = regexp.MustCompile(`^\^claude-[a-z]+-5-[0-9]+\(\$\|-\)$`)
	// 抓包机上的 memory 绝对路径：含用户名、临时目录、版本与模型，必须归一。
	// 分隔符两种都接受，避免抓包落到不同平台时漏归一。
	reWinCapturePath   = regexp.MustCompile(`[A-Za-z]:[\\/]+Users[\\/]+[^` + "`" + `]*ccprobe[^` + "`" + `]*[\\/]+memory[\\/]+`)
	rePosixCapturePath = regexp.MustCompile(`[\\/]+[^` + "`" + `]*ccprobe[^` + "`" + `]*[\\/]+memory[\\/]+`)
)

// profile 是 profiles.json 里的一条记录，字段名与 claude.libraryEntry 对齐。
type profile struct {
	Version                 string         `json:"version"`
	PublishedAt             string         `json:"publishedAt"`
	StainlessPackageVersion string         `json:"stainlessPackageVersion"`
	StainlessRuntimeVersion string         `json:"stainlessRuntimeVersion"`
	StainlessOS             string         `json:"stainlessOS"`
	StainlessArch           string         `json:"stainlessArch"`
	BunVersion              string         `json:"bunVersion"`
	TLSVariant              string         `json:"tlsVariant"`
	BaseBetas               []string       `json:"baseBetas"`
	IdentityFile            string         `json:"identityFile,omitempty"`
	IdentitySHA256          string         `json:"identitySHA256,omitempty"`
	Variants                []variantEntry `json:"variants,omitempty"`
	CaptureKind             string         `json:"captureKind,omitempty"`
	TemplateNote            string         `json:"templateNote,omitempty"`
}

// variantEntry 是某个模型族的 system[2] 主 prompt 与 tools 快照。
//
// 实测同一版本下这两项都随模型代次变化（2.1.323：4-5 代 tools 与 5 代不同，
// prompt 长度 sonnet-4-5 27002B / opus-5-5 6718B），所以模板必须按模型族分档，
// 一个版本只存一份会立刻露馅。
type variantEntry struct {
	// Family 是模型 ID 正则；空串表示兜底档（其余规则都没命中时使用）。
	Family       string `json:"family"`
	PromptFile   string `json:"promptFile"`
	PromptSHA256 string `json:"promptSHA256"`
	ToolsFile    string `json:"toolsFile,omitempty"`
	ToolsSHA256  string `json:"toolsSHA256,omitempty"`
}

// rule / ruleExtra 与 claude.ModelBetaRule 的 JSON 形态一致。
type ruleExtra struct {
	Beta  string `json:"beta"`
	After string `json:"after,omitempty"`
}

type rule struct {
	Family string      `json:"family"`
	Extra  []ruleExtra `json:"extra,omitempty"`
	Order  []string    `json:"order,omitempty"`
}

type library struct {
	SchemaVersion  int       `json:"schemaVersion"`
	GeneratedAt    string    `json:"generatedAt"`
	Source         string    `json:"source"`
	Profiles       []profile `json:"profiles"`
	ModelBetaRules []rule    `json:"modelBetaRules"`
}

func main() {
	var (
		versionsFlag  = flag.String("versions", "", "逗号分隔的版本号列表，显式指定要探测的版本")
		latestFlag    = flag.Int("latest", 0, "从 npm 取最近 N 个已发布版本")
		platformFlag  = flag.String("platform", "linux-x64", "原生包平台后缀（linux-x64 / linux-arm64 / darwin-arm64）")
		outFlag       = flag.String("out", filepath.Join("internal", "pkg", "claude", "versionprofiles", "profiles.json"), "特征库输出路径")
		captureFlag   = flag.String("capture", "", "抓包根目录，内部结构 <root>/<version>/<kind>/<model>.raw")
		forceFlag     = flag.Bool("force", false, "已存在的版本也重新探测")
		noBinaryFlag  = flag.Bool("no-binary", false, "不下载 npm 二进制（只用抓包，快）")
		emitRules     = flag.Bool("emit-rules", false, "打印从抓包推导出的 modelBetaRules 并与现有规则比对")
		writeRules    = flag.Bool("write-rules", false, "把推导出的规则写回 profiles.json（隐含 -emit-rules）")
		allowMismatch = flag.Bool("allow-version-mismatch", false, "抓包 UA 版本与目标版本不一致时仍继续")
	)
	flag.Parse()

	if *versionsFlag == "" && *latestFlag == 0 {
		fmt.Fprintln(os.Stderr, "need -versions or -latest")
		os.Exit(2)
	}
	if *writeRules {
		*emitRules = true
	}

	lib, err := loadLibrary(*outFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load library: %v\n", err)
		os.Exit(1)
	}
	have := make(map[string]profile, len(lib.Profiles))
	for _, p := range lib.Profiles {
		have[p.Version] = p
	}

	var published map[string]string
	if !*noBinaryFlag {
		published, err = fetchPublishTimes()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: fetch publish times: %v\n", err)
			published = map[string]string{}
		}
	} else {
		published = map[string]string{}
	}

	targets, err := resolveTargets(*versionsFlag, *latestFlag, published)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	var derived []rule
	var cases []replayCase

	for _, v := range targets {
		caps, capErr := loadCaptures(*captureFlag, v, *allowMismatch)
		if capErr != nil {
			fmt.Fprintf(os.Stderr, "capture %s: %v\n", v, capErr)
			os.Exit(1)
		}
		if len(caps) == 0 {
			if _, ok := have[v]; ok && !*forceFlag {
				fmt.Printf("skip %s (already in library, no capture)\n", v)
				continue
			}
			if *noBinaryFlag {
				fmt.Fprintf(os.Stderr, "skip %s: 没有抓包且指定了 -no-binary\n", v)
				continue
			}
		} else if _, ok := have[v]; ok && !*forceFlag && !*emitRules {
			fmt.Printf("skip %s (already in library)\n", v)
			continue
		}

		fmt.Printf("probe %s ...\n", v)

		var bin *binaryInfo
		if !*noBinaryFlag {
			bin, err = probeBinary(v, *platformFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  warn: binary probe: %v\n", err)
			}
		}

		prev, hadPrev := have[v]
		p, rules, models, err := buildRecord(v, caps, bin, published[v], prev, hadPrev, *outFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  fail: %v\n", err)
			continue
		}
		replaceProfile(&lib.Profiles, *p)
		derived = append(derived, rules...)
		cases = append(cases, replayCase{version: v, base: p.BaseBetas, models: models})
		fmt.Printf("  ok betas=%d models=%d tls=%s variants=%d identity=%v\n",
			len(p.BaseBetas), len(caps), p.TLSVariant, len(p.Variants), p.IdentityFile != "")
	}

	if *emitRules {
		derived = dedupeRules(derived)
		reportRules(derived, cases, lib.ModelBetaRules, *writeRules)
		if *writeRules {
			lib.ModelBetaRules = derived
		}
	}

	sort.Slice(lib.Profiles, func(i, j int) bool {
		return compareVersions(lib.Profiles[i].Version, lib.Profiles[j].Version) > 0
	})
	if len(lib.Profiles) > maxKeep {
		lib.Profiles = lib.Profiles[:maxKeep]
	}
	fillMissingBun(lib.Profiles)
	lib.SchemaVersion = schemaVersion
	lib.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	lib.Source = "真机抓包（每版本独立账号 token，oauth 形态）+ npm 二进制交叉校验；模板在 versionprofiles/{version}/"
	if *noBinaryFlag {
		lib.Source = "真机抓包（每版本独立账号 token，oauth 形态；未跑二进制交叉校验）；模板在 versionprofiles/{version}/"
	}

	if err := writeLibrary(*outFlag, lib); err != nil {
		fmt.Fprintf(os.Stderr, "write library: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d profiles to %s\n", len(lib.Profiles), *outFlag)
}

// ---------------------------------------------------------------- 抓包解析

// capture 是一份真机抓包的解析结果。
type capture struct {
	Path      string
	Kind      string
	Model     string
	UserAgent string
	OS        string
	Arch      string
	PkgVer    string
	Runtime   string
	Betas     []string
	Prompt    string
	Identity  string
	Tools     []byte
}

// loadCaptures 读出某版本目录下所有抓包；目录不存在返回空。
func loadCaptures(root, version string, allowMismatch bool) ([]*capture, error) {
	if root == "" {
		return nil, nil
	}
	verDir := filepath.Join(root, version)
	if st, err := os.Stat(verDir); err != nil || !st.IsDir() {
		return nil, nil
	}
	kinds, err := os.ReadDir(verDir)
	if err != nil {
		return nil, err
	}
	var out []*capture
	for _, k := range kinds {
		if !k.IsDir() {
			continue
		}
		kindDir := filepath.Join(verDir, k.Name())
		files, err := os.ReadDir(kindDir)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".raw") {
				continue
			}
			cap, err := parseCaptureFile(filepath.Join(kindDir, f.Name()), k.Name())
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f.Name(), err)
			}
			if err := checkCaptureVersion(cap, version, allowMismatch); err != nil {
				return nil, err
			}
			out = append(out, cap)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	// 小集合在前：第一条即基础集来源。
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Betas) != len(out[j].Betas) {
			return len(out[i].Betas) < len(out[j].Betas)
		}
		return out[i].Model < out[j].Model
	})
	return out, nil
}

func checkCaptureVersion(cap *capture, version string, allow bool) error {
	got := ""
	if m := reUserAgentVer.FindStringSubmatch(cap.UserAgent); m != nil {
		got = m[1]
	}
	if got == "" {
		return fmt.Errorf("%s: 抓包缺少可用 User-Agent", filepath.Base(cap.Path))
	}
	if got != version && !allow {
		return fmt.Errorf("%s: UA 版本 %s 与目标版本 %s 不符（可用 -allow-version-mismatch）",
			filepath.Base(cap.Path), got, version)
	}
	return nil
}

// parseCaptureFile 解析一份 raw HTTP 请求（头部 + 空行 + body）。
func parseCaptureFile(path, kind string) (*capture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	head, body, ok := splitHTTPMessage(raw)
	if !ok {
		return nil, errors.New("缺少头部/正文分隔空行")
	}
	hdr := parseHeaderBlock(head)

	cap := &capture{
		Path:      path,
		Kind:      kind,
		UserAgent: hdr.get("user-agent"),
		OS:        hdr.get("x-stainless-os"),
		Arch:      hdr.get("x-stainless-arch"),
		PkgVer:    hdr.get("x-stainless-package-version"),
		Runtime:   hdr.get("x-stainless-runtime-version"),
	}
	for _, v := range hdr["anthropic-beta"] {
		for _, b := range strings.Split(v, ",") {
			if b = strings.TrimSpace(b); b != "" && !containsStr(cap.Betas, b) {
				cap.Betas = append(cap.Betas, b)
			}
		}
	}
	if len(cap.Betas) == 0 {
		return nil, errors.New("anthropic-beta 为空")
	}
	if cap.OS == "" || cap.Arch == "" || cap.PkgVer == "" || cap.Runtime == "" {
		return nil, errors.New("X-Stainless-* 头不完整")
	}

	var doc struct {
		Model  string          `json:"model"`
		System json.RawMessage `json:"system"`
		Tools  json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("body 不是 JSON: %w", err)
	}
	if doc.Model == "" {
		doc.Model = strings.TrimSuffix(filepath.Base(path), ".raw")
	}
	if doc.Model == "" {
		return nil, errors.New("无法确定 model")
	}
	cap.Model = doc.Model

	prompt, identity, err := splitSystemBlocks(doc.System)
	if err != nil {
		return nil, err
	}
	cap.Prompt = normalizePromptPath(prompt)
	cap.Identity = identity

	if len(doc.Tools) > 0 && string(doc.Tools) != "null" {
		var buf bytes.Buffer
		if err := json.Indent(&buf, doc.Tools, "", " "); err != nil {
			return nil, fmt.Errorf("tools 无法格式化: %w", err)
		}
		buf.WriteByte('\n')
		cap.Tools = buf.Bytes()
	}
	return cap, nil
}

// splitHTTPMessage 按第一个空行切开头部与正文。
func splitHTTPMessage(raw []byte) (head []byte, body []byte, ok bool) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i], raw[i+4:], true
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i], raw[i+2:], true
	}
	return nil, nil, false
}

type headerBlock map[string][]string

func (h headerBlock) get(name string) string {
	if v := h[name]; len(v) > 0 {
		return strings.TrimSpace(v[0])
	}
	return ""
}

func parseHeaderBlock(head []byte) headerBlock {
	out := headerBlock{}
	for _, line := range strings.Split(string(head), "\n") {
		line = strings.TrimRight(line, "\r")
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:idx]))
		out[name] = append(out[name], strings.TrimSpace(line[idx+1:]))
	}
	return out
}

// splitSystemBlocks 从 system 里分出主 prompt 与身份句。
//
// 真机报文固定是三个块：[billing 头][身份句][主 prompt]。billing 头每次请求都变，
// 由出站层按账号重建；身份句与主 prompt 是版本快照，必须原样保存。
func splitSystemBlocks(system json.RawMessage) (prompt, identity string, err error) {
	if len(system) == 0 || string(system) == "null" {
		return "", "", errors.New("body 缺少 system")
	}
	var asString string
	if err := json.Unmarshal(system, &asString); err == nil {
		return asString, "", nil
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(system, &blocks); err != nil {
		return "", "", fmt.Errorf("system 形态未知: %w", err)
	}
	for _, b := range blocks {
		text := b.Text
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "x-anthropic-billing-header") {
			continue
		}
		if len(text) >= minPromptBytes {
			if len(text) > len(prompt) {
				prompt = text
			}
			continue
		}
		// 短块即身份句（"You are a Claude agent, built on ..."），取最长的一个。
		if len(text) > len(identity) {
			identity = text
		}
	}
	if prompt == "" {
		return "", identity, errors.New("system 里找不到主 prompt 块")
	}
	return prompt, identity, nil
}

// ---------------------------------------------------------------- 记录构建

// buildRecord 用抓包（+ 可选二进制）拼出一条记录并落盘模板。
func buildRecord(version string, caps []*capture, bin *binaryInfo, publishedAt string, prev profile, hadPrev bool, outPath string) (*profile, []rule, map[string][]string, error) {
	if len(caps) == 0 {
		return buildRecordFromBinary(version, bin, publishedAt, prev, hadPrev)
	}

	base := caps[0]
	for _, c := range caps[1:] {
		if c.Kind != base.Kind || c.OS != base.OS || c.Arch != base.Arch ||
			c.PkgVer != base.PkgVer || c.Runtime != base.Runtime || c.UserAgent != base.UserAgent {
			return nil, nil, nil, fmt.Errorf("抓包之间头不一致：%s 与 %s 不是同一客户端环境", filepath.Base(base.Path), filepath.Base(c.Path))
		}
		// 身份句应当与模型无关，不一致说明其中一份抓包被中间层改写过。
		if c.Identity != base.Identity {
			fmt.Fprintf(os.Stderr, "  warn: %s 的身份句与 %s 不同\n", filepath.Base(c.Path), filepath.Base(base.Path))
		}
	}

	baseSet := make(map[string]struct{}, len(base.Betas))
	for _, b := range base.Betas {
		baseSet[b] = struct{}{}
	}
	// 交集：任何模型都带的那部分才是"基础集"。
	for _, c := range caps[1:] {
		for b := range baseSet {
			if !containsStr(c.Betas, b) {
				delete(baseSet, b)
			}
		}
	}
	baseBetas := make([]string, 0, len(base.Betas))
	for _, b := range base.Betas {
		if _, ok := baseSet[b]; ok {
			baseBetas = append(baseBetas, b)
		}
	}
	if len(baseBetas) == 0 {
		return nil, nil, nil, errors.New("各模型 beta 交集为空")
	}

	if bin != nil {
		for _, b := range base.Betas {
			if !containsStr(bin.Betas, b) {
				fmt.Fprintf(os.Stderr, "  warn: 二进制里找不到 beta %q，betaTokens 表可能过期\n", b)
			}
		}
	}

	p := &profile{
		Version:                 version,
		PublishedAt:             pickPublished(publishedAt, bin),
		StainlessPackageVersion: base.PkgVer,
		StainlessRuntimeVersion: base.Runtime,
		StainlessOS:             base.OS,
		StainlessArch:           base.Arch,
		TLSVariant:              tlsVariantFor(base.Runtime),
		BaseBetas:               baseBetas,
		CaptureKind:             base.Kind,
		TemplateNote: fmt.Sprintf("模板取自 %s 抓包（%d 个模型，按模型族分档）；system[0] billing 头由出站层按账号版本重建，identity.txt 与各档 prompt/tools 为版本快照。",
			base.Kind, len(caps)),
	}
	if bin != nil && bin.BunVersion != "" {
		p.BunVersion = bin.BunVersion
	} else if hadPrev && prev.BunVersion != "" {
		// 二进制探测失败（压缩形态变化等）时不要把上次的记录抹空。
		p.BunVersion = prev.BunVersion
	}
	if bin == nil && hadPrev {
		// 没跑二进制时不要把上次的记录抹空。
		p.PublishedAt = pickPublished(p.PublishedAt, nil)
		if p.PublishedAt == "" {
			p.PublishedAt = prev.PublishedAt
		}
	}

	dir, err := writeIdentity(outPath, version, base)
	if err != nil {
		return nil, nil, nil, err
	}
	if base.Identity == "" {
		fmt.Fprintf(os.Stderr, "  warn: %s 没有身份句块\n", filepath.Base(base.Path))
	} else {
		p.IdentityFile = dir + "/identity.txt"
		p.IdentitySHA256 = sha256Hex([]byte(base.Identity))
	}

	variants, err := writeVariants(outPath, version, caps, base)
	if err != nil {
		return nil, nil, nil, err
	}
	p.Variants = variants

	// 逐模型推导规则，并顺便校验。
	rules := make([]rule, 0, len(caps))
	models := make(map[string][]string, len(caps))
	for _, c := range caps {
		models[c.Model] = c.Betas
		if len(c.Betas) <= len(baseBetas) && sameOrder(c.Betas, baseBetas) {
			continue
		}
		rules = append(rules, deriveRule(c, baseBetas))
	}
	return p, rules, models, nil
}

// buildRecordFromBinary 在无抓包时只能给出头/体版本特征，模板沿用旧记录。
func buildRecordFromBinary(version string, bin *binaryInfo, publishedAt string, prev profile, hadPrev bool) (*profile, []rule, map[string][]string, error) {
	if bin == nil {
		return nil, nil, nil, errors.New("既没有抓包也没有二进制特征")
	}
	if !isDottedTriple(bin.StainlessPackageVersion) {
		return nil, nil, nil, fmt.Errorf("stainless 包版本非法：%q", bin.StainlessPackageVersion)
	}
	osName, arch := stainlessPlatform(bin.Platform)
	p := &profile{
		Version:                 version,
		PublishedAt:             publishedAt,
		StainlessPackageVersion: bin.StainlessPackageVersion,
		StainlessRuntimeVersion: bin.RuntimeVersion,
		StainlessOS:             osName,
		StainlessArch:           arch,
		BunVersion:              bin.BunVersion,
		TLSVariant:              tlsVariantFor(bin.RuntimeVersion),
		BaseBetas:               bin.Betas,
	}
	if hadPrev {
		p.IdentityFile, p.IdentitySHA256 = prev.IdentityFile, prev.IdentitySHA256
		p.Variants = prev.Variants
		if p.IdentityFile != "" || len(p.Variants) > 0 {
			p.TemplateNote = "模板沿用上一次抓包结果（本次无抓包），需重跑 -capture 校验。"
		}
	}
	fmt.Fprintf(os.Stderr, "  warn: %s 无抓包，baseBetas 来自二进制（可能包含未启用的 token）\n", version)
	return p, nil, nil, nil
}

func pickPublished(publishedAt string, bin *binaryInfo) string {
	if publishedAt != "" {
		return publishedAt
	}
	if bin != nil {
		return bin.PublishedAt
	}
	return ""
}

// deriveRule 由单个模型的抓包反推规则：多出来的 beta 与顺序特例。
func deriveRule(c *capture, baseBetas []string) rule {
	baseSet := make(map[string]struct{}, len(baseBetas))
	for _, b := range baseBetas {
		baseSet[b] = struct{}{}
	}
	r := rule{Family: familyFor(c.Model)}
	prev := ""
	for _, b := range c.Betas {
		if _, ok := baseSet[b]; ok {
			prev = b
			continue
		}
		r.Extra = append(r.Extra, ruleExtra{Beta: b, After: prev})
		prev = b
	}
	baseOrder := filterTo(c.Betas, baseSet)
	if !sameOrder(baseOrder, baseBetas) {
		r.Order = append([]string(nil), c.Betas...)
	}
	return r
}

func filterTo(list []string, keep map[string]struct{}) []string {
	out := make([]string, 0, len(list))
	for _, b := range list {
		if _, ok := keep[b]; ok {
			out = append(out, b)
		}
	}
	return out
}

// 归一后的 memory 路径：不暴露抓包机用户名与临时目录，也不带版本/模型，
// 与真实客户端（配置目录就是 ~/.claude）的形状一致。
const (
	canonicalWinMemoryPath    = `C:\Users\user\.claude\projects\C--Users-user-projects\memory\`
	canonicalWinMemoryPathAlt = `C:/Users/user/.claude/projects/C--Users-user-projects/memory/`
	canonicalPosixMemoryPath  = `/home/user/.claude/projects/-home-user-projects/memory/`
)

// normalizePromptPath 把 prompt 里抓包机的绝对路径换成规范路径。
// 不归一的话模板会带出本机用户名，且每个版本都会因路径含版本号而多一行假差异。
func normalizePromptPath(prompt string) string {
	prompt = reWinCapturePath.ReplaceAllStringFunc(prompt, func(m string) string {
		if strings.Contains(m, `\`) {
			return canonicalWinMemoryPath
		}
		return canonicalWinMemoryPathAlt
	})
	return rePosixCapturePath.ReplaceAllLiteralString(prompt, canonicalPosixMemoryPath)
}

// familyFor 把具体模型 ID 收敛成正则族：去掉快照日期，锚定段边界。
func familyFor(model string) string {
	model = reSnapshotDate.ReplaceAllString(strings.ToLower(strings.TrimSpace(model)), "")
	return "^" + regexp.QuoteMeta(model) + `($|-)`
}

// writeIdentity 落盘身份句模板，返回相对 versionprofiles 的版本目录名。
func writeIdentity(outPath, version string, base *capture) (string, error) {
	dir := filepath.Join(filepath.Dir(outPath), version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if base.Identity != "" {
		if err := os.WriteFile(filepath.Join(dir, "identity.txt"), []byte(base.Identity), 0o644); err != nil {
			return "", err
		}
	}
	return version, nil
}

// writeVariants 按模型族落盘 prompt/tools 模板：base 那份作为兜底档（family 为空），
// 其余各自成档。返回的切片兜底档在最后。
func writeVariants(outPath, version string, caps []*capture, base *capture) ([]variantEntry, error) {
	root := filepath.Join(filepath.Dir(outPath), version)
	var out []variantEntry
	var def *variantEntry
	for _, c := range caps {
		slug, family := slugFor(c.Model), familyFor(c.Model)
		if c == base {
			slug, family = "default", ""
		}
		dir := filepath.Join(root, slug)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		promptPath := filepath.Join(dir, "prompt.txt")
		if err := os.WriteFile(promptPath, []byte(c.Prompt), 0o644); err != nil {
			return nil, err
		}
		v := variantEntry{
			Family:       family,
			PromptFile:   version + "/" + slug + "/prompt.txt",
			PromptSHA256: sha256Hex([]byte(c.Prompt)),
		}
		if len(c.Tools) > 0 {
			if err := os.WriteFile(filepath.Join(dir, "tools.json"), c.Tools, 0o644); err != nil {
				return nil, err
			}
			v.ToolsFile = version + "/" + slug + "/tools.json"
			v.ToolsSHA256 = sha256Hex(c.Tools)
		} else {
			fmt.Fprintf(os.Stderr, "  warn: %s 没有 tools，该档不含 tools 模板\n", filepath.Base(c.Path))
		}
		if family == "" {
			def = &v
			continue
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	if def != nil {
		out = append(out, *def)
	}
	return out, nil
}

// slugFor 把模型 ID 变成目录名。
func slugFor(model string) string {
	model = strings.ToLower(reSnapshotDate.ReplaceAllString(strings.TrimSpace(model), ""))
	model = strings.TrimPrefix(model, "claude-")
	var b strings.Builder
	for _, r := range model {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func sameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fillMissingBun 给 bunVersion 空缺的记录补上最近邻的值。
// 同一代版本用同一条打包链，个别版本二进制压缩形态变化会让正则失效，不该因此留空。
func fillMissingBun(profiles []profile) {
	fallback := ""
	for _, p := range profiles {
		if p.BunVersion != "" {
			fallback = p.BunVersion
			break
		}
	}
	if fallback == "" {
		return
	}
	for i := range profiles {
		if profiles[i].BunVersion == "" {
			fmt.Fprintf(os.Stderr, "  warn: %s 缺 bunVersion，沿用 %s\n", profiles[i].Version, fallback)
			profiles[i].BunVersion = fallback
		}
	}
}

// ---------------------------------------------------------------- 规则比对

// replayCase 是某个版本的一次规则回放：base 为该版本的基础集，models 为各模型实测 beta。
type replayCase struct {
	version string
	base    []string
	models  map[string][]string
}

// broadenFamily 把具体模型族收敛成广义族，让新增同代模型不必新增规则。
// 返回原值表示该族已足够宽，无需收敛。
func broadenFamily(family string) string {
	switch {
	case strings.HasPrefix(family, "^claude-haiku-4-"):
		// 4 代 haiku 只有 advisor、没有 effort，与 5 代不同，不能并进 haiku 泛族。
		return "^claude-haiku-4-5"
	case strings.HasPrefix(family, "^claude-haiku-"):
		return "^claude-haiku-[a-z]*-?5-[0-9]"
	case reGen5Family.MatchString(family):
		return "^claude-[a-z]+-5-[0-9]"
	case strings.HasPrefix(family, "^claude-opus-4-5"):
		return "^claude-opus-4-5"
	}
	return family
}

// dedupeRules 先按广义族收敛再按族去重（多版本抓包会重复推导同一族），
// 保留首次出现的顺序 —— 顺序即优先级，haiku 族必须先于泛 5 代族，否则会被后者吞掉。
// 同族内若各模型的额外 beta 不一致，说明收敛不安全，打 warn 但不合并。
func dedupeRules(in []rule) []rule {
	seen := make(map[string]int, len(in))
	out := make([]rule, 0, len(in))
	for _, r := range in {
		family := broadenFamily(r.Family)
		if i, ok := seen[family]; ok {
			if !sameRule(out[i], r) {
				fmt.Fprintf(os.Stderr, "  warn: 族 %s 收敛冲突（%s vs %s），保留前者\n",
					family, out[i].Family, r.Family)
			}
			continue
		}
		r.Family = family
		seen[family] = len(out)
		out = append(out, r)
	}
	return out
}

// sameRule 判断两条规则推导结果是否等价（忽略 family 本身）。
func sameRule(a, b rule) bool {
	if len(a.Extra) != len(b.Extra) || len(a.Order) != len(b.Order) {
		return false
	}
	for i := range a.Extra {
		if a.Extra[i] != b.Extra[i] {
			return false
		}
	}
	for i := range a.Order {
		if a.Order[i] != b.Order[i] {
			return false
		}
	}
	return true
}

// reportRules 打印推导出的规则，并用规则回放校验抓包结果。
func reportRules(derived []rule, cases []replayCase, current []rule, willWrite bool) {
	if len(derived) == 0 && len(cases) > 0 {
		fmt.Println("no model-specific beta differences captured")
		return
	}
	if len(derived) > 0 {
		fmt.Println("--- derived modelBetaRules ---")
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("  ", "  ")
		_ = enc.Encode(derived)
	}

	rules, label := current, "current"
	if willWrite {
		rules, label = derived, "derived"
	}
	fmt.Printf("--- replay with %s rules ---\n", label)
	reportReplay(rules, cases)
}

func reportReplay(rules []rule, cases []replayCase) {
	bad := 0
	for _, c := range cases {
		names := make([]string, 0, len(c.models))
		for m := range c.models {
			names = append(names, m)
		}
		sort.Strings(names)
		for _, m := range names {
			got := applyRules(c.base, rules, m)
			if sameOrder(got, c.models[m]) {
				fmt.Printf("  ok   %s %s (%d)\n", c.version, m, len(got))
				continue
			}
			bad++
			fmt.Printf("  MISMATCH %s %s\n    want %v\n    got  %v\n", c.version, m, c.models[m], got)
		}
	}
	if bad > 0 {
		fmt.Printf("%d model(s) mismatch\n", bad)
	}
}

// applyRules 复刻 claude.VersionProfile.BetasForModel 的语义，用于自检。
func applyRules(base []string, rules []rule, model string) []string {
	out := append([]string(nil), base...)
	model = strings.ToLower(model)
	var hit *rule
	for i := range rules {
		re, err := regexp.Compile("(?i)" + rules[i].Family)
		if err != nil {
			continue
		}
		if re.MatchString(model) {
			hit = &rules[i]
			break
		}
	}
	if hit == nil {
		return out
	}
	for _, e := range hit.Extra {
		if e.Beta == "" || containsStr(out, e.Beta) {
			continue
		}
		out = insertAfter(out, e.Beta, e.After)
	}
	if len(hit.Order) > 0 {
		out = orderBy(out, hit.Order)
	}
	return out
}

func insertAfter(list []string, beta, after string) []string {
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

func orderBy(list, order []string) []string {
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

// ---------------------------------------------------------------- 库读写

func loadLibrary(path string) (library, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return library{SchemaVersion: schemaVersion}, nil
	}
	if err != nil {
		return library{}, err
	}
	var lib library
	if err := json.Unmarshal(raw, &lib); err != nil {
		return library{}, err
	}
	return lib, nil
}

func writeLibrary(path string, lib library) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(lib, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func replaceProfile(list *[]profile, p profile) {
	for i := range *list {
		if (*list)[i].Version == p.Version {
			(*list)[i] = p
			return
		}
	}
	*list = append(*list, p)
}

// ---------------------------------------------------------------- npm 探测

// binaryInfo 是从二进制里读到的特征。
type binaryInfo struct {
	Platform                string
	StainlessPackageVersion string
	RuntimeVersion          string
	BunVersion              string
	PublishedAt             string
	Betas                   []string
}

// fetchPublishTimes 取各版本的发布时间，用于升级排期参考。
func fetchPublishTimes() (map[string]string, error) {
	body, err := httpGet(registryBase + "/" + pkgName)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Time map[string]string `json:"time"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(doc.Time))
	for v, ts := range doc.Time {
		if len(ts) >= 10 {
			out[v] = ts[:10]
		}
	}
	return out, nil
}

func resolveTargets(explicit string, latest int, published map[string]string) ([]string, error) {
	if explicit != "" {
		var out []string
		for _, v := range strings.Split(explicit, ",") {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if !isDottedTriple(v) {
				return nil, fmt.Errorf("invalid version %q", v)
			}
			out = append(out, v)
		}
		return out, nil
	}

	all := make([]string, 0, len(published))
	for v := range published {
		if isDottedTriple(v) {
			all = append(all, v)
		}
	}
	if len(all) == 0 {
		return nil, errors.New("no versions found in registry")
	}
	sort.Slice(all, func(i, j int) bool { return compareVersions(all[i], all[j]) > 0 })
	if latest < len(all) {
		all = all[:latest]
	}
	return all, nil
}

// probeBinary 下载并解析单个版本二进制，返回交叉校验用的特征。
func probeBinary(version, platform string) (*binaryInfo, error) {
	url := fmt.Sprintf("%s/@anthropic-ai/claude-code-%s/-/claude-code-%s-%s.tgz", registryBase, platform, platform, version)

	resp, err := httpGetRaw(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: http %d", version, resp.StatusCode)
	}

	bin, err := extractLargestFile(resp.Body)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp("", "ccbin-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()
	if _, err := f.Write(bin); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	info, err := scanBinary(f)
	if err != nil {
		return nil, err
	}
	info.Platform = platform
	return info, nil
}

// extractLargestFile 从 tgz 流里取出体积最大的成员（即原生二进制）。
func extractLargestFile(r io.Reader) ([]byte, error) {
	gz, err := gzip.NewReader(bufio.NewReaderSize(r, 1<<20))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var best []byte
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size < 5<<20 {
			continue
		}
		buf := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, buf); err != nil {
			return nil, err
		}
		if len(buf) > len(best) {
			best = buf
		}
	}
	if len(best) == 0 {
		return nil, errors.New("no binary found in tarball")
	}
	return best, nil
}

// scanBinary 流式扫描二进制中的可打印串并提取特征。
func scanBinary(r io.Reader) (*binaryInfo, error) {
	info := &binaryInfo{}
	betasFound := make([]bool, len(betaTokens))
	stainlessVar := ""
	stainlessValues := map[string]string{}
	nodeCounter := map[string]int{}

	br := bufio.NewReaderSize(r, 1<<20)
	var token []byte
	flush := func() {
		if len(token) < 6 {
			token = token[:0]
			return
		}
		s := string(token)
		token = token[:0]

		if m := reStainlessRef.FindStringSubmatch(s); m != nil && stainlessVar == "" {
			stainlessVar = m[1]
		}
		if m := reRuntimeLiteral.FindStringSubmatch(s); m != nil && info.RuntimeVersion == "" {
			info.RuntimeVersion = m[1]
		}
		if m := reBunVersion.FindStringSubmatch(s); m != nil && info.BunVersion == "" {
			info.BunVersion = "v" + m[1]
		}
		for _, m := range reNodeVersion.FindAllStringSubmatch(s, -1) {
			nodeCounter["v"+m[1]+"."+m[2]+"."+m[3]]++
		}
		for i, b := range betaTokens {
			if !betasFound[i] && strings.Contains(s, b) {
				betasFound[i] = true
			}
		}
		if stainlessVar != "" {
			needle := "var " + stainlessVar + `="`
			if idx := strings.Index(s, needle); idx >= 0 {
				rest := s[idx+len(needle):]
				if end := strings.IndexByte(rest, '"'); end > 0 {
					// 压缩后同名变量会在不同作用域复用，首个定义未必是版本号，
					// 优先保留形如 x.y.z 的那个。
					cur, ok := stainlessValues[stainlessVar]
					if v := rest[:end]; !ok || (!isDottedTriple(cur) && isDottedTriple(v)) {
						stainlessValues[stainlessVar] = v
					}
				}
			}
		}
	}

	for {
		b, err := br.ReadByte()
		if err != nil {
			flush()
			break
		}
		if b >= 0x20 && b < 0x7f {
			token = append(token, b)
			if len(token) > 4<<20 {
				flush()
			}
			continue
		}
		flush()
	}

	if stainlessVar != "" {
		if cur, ok := stainlessValues[stainlessVar]; !ok || !isDottedTriple(cur) {
			if _, err := r.(io.Seeker).Seek(0, io.SeekStart); err == nil {
				if v := findVarDefinition(bufio.NewReaderSize(r, 1<<20), stainlessVar); v != "" {
					stainlessValues[stainlessVar] = v
				}
			}
		}
	}
	if stainlessVar == "" {
		return nil, errors.New("stainless package version reference not found")
	}
	info.StainlessPackageVersion = stainlessValues[stainlessVar]
	if !isDottedTriple(info.StainlessPackageVersion) {
		return nil, fmt.Errorf("stainless package version unresolved (var %s)", stainlessVar)
	}

	if info.RuntimeVersion == "" || info.RuntimeVersion == "unknown" {
		info.RuntimeVersion = dominantNodeVersion(nodeCounter)
	}
	if info.RuntimeVersion == "" {
		return nil, errors.New("runtime version not found")
	}

	for i, b := range betaTokens {
		if betasFound[i] {
			info.Betas = append(info.Betas, b)
		}
	}
	if len(info.Betas) == 0 {
		return nil, errors.New("no beta tokens found")
	}
	return info, nil
}

// findVarDefinition 在流里查找 `var NAME="..."` 的定义值。
func findVarDefinition(r io.Reader, name string) string {
	needle := "var " + name + `="`
	br := bufio.NewReaderSize(r, 1<<20)
	var token []byte
	first := ""
	for {
		b, err := br.ReadByte()
		if err != nil {
			return first
		}
		if b >= 0x20 && b < 0x7f {
			token = append(token, b)
			if len(token) > 1<<20 {
				token = token[:0]
			}
			continue
		}
		if idx := strings.Index(string(token), needle); idx >= 0 {
			rest := string(token)[idx+len(needle):]
			if end := strings.IndexByte(rest, '"'); end > 0 {
				// 同名变量会被压缩器跨作用域复用，遇到形如 x.y.z 的才算命中。
				if v := rest[:end]; isDottedTriple(v) {
					return v
				} else if first == "" {
					first = v
				}
			}
		}
		token = token[:0]
	}
}

// tlsVariantFor 由运行时版本决定握手形态：Node 26.3 是 OpenSSL 3.2 时代，
// Node 26.10 起随 OpenSSL 3.5 引入后量子混合组。实测断层在 2.1.301~2.1.311。
// 大版本超过 26 一律视为新形态，避免 Node 27 上线后被误判回 legacy。
func tlsVariantFor(runtimeVersion string) string {
	parts := strings.Split(strings.TrimPrefix(runtimeVersion, "v"), ".")
	if len(parts) < 2 {
		return "post-quantum"
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil {
		return "post-quantum"
	}
	if major != 26 {
		if major > 26 {
			return "post-quantum"
		}
		return "legacy"
	}
	if minor >= 10 {
		return "post-quantum"
	}
	return "legacy"
}

// stainlessPlatform 把 npm 平台后缀映射为 X-Stainless-OS / Arch 取值。
func stainlessPlatform(platform string) (osName, arch string) {
	osName, arch = "Linux", "x64"
	parts := strings.SplitN(platform, "-", 2)
	switch parts[0] {
	case "darwin":
		osName = "MacOS"
	case "win32":
		osName = "Windows"
	case "linux":
		osName = "Linux"
	}
	if len(parts) == 2 {
		switch parts[1] {
		case "arm64":
			arch = "arm64"
		case "x64":
			arch = "x64"
		}
	}
	return osName, arch
}

// dominantNodeVersion 取出现次数最多的 Node 版本串（二进制里 process.version 被固化）。
func dominantNodeVersion(counter map[string]int) string {
	best, bestN := "", 0
	for v, n := range counter {
		if n > bestN || (n == bestN && compareVersions(v, best) > 0) {
			best, bestN = v, n
		}
	}
	return best
}

func httpGet(url string) ([]byte, error) {
	resp, err := httpGetRaw(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func httpGetRaw(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")
	return client.Do(req)
}

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

func compareVersions(a, b string) int {
	pa, pb := parseParts(a), parseParts(b)
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

func parseParts(v string) [3]int {
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	out := [3]int{}
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}
