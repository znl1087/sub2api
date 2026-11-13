package service

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"log/slog"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
)

const (
	// AccountExtraCLIVersion 是账号绑定的 Claude Code 客户端版本（extra 键）。
	AccountExtraCLIVersion = "cli_version"
	// AccountExtraCLIVersionNextAt 是该账号下次允许升级的时间（extra 键，unix 秒）。
	// 每个账号各自持有、彼此错开，升级才会像真机那样陆续发生。
	AccountExtraCLIVersionNextAt = "cli_version_next_at"

	// claudeVersionListTTL 版本列表缓存时长。热路径按请求读，必须命中内存。
	claudeVersionListTTL = 60 * time.Second
	// claudeVersionMaintainInterval 维护周期：补绑缺失版本、处理到期的升级。
	claudeVersionMaintainInterval = 10 * time.Minute
	// claudeVersionUpgradeMaxPerRun 单轮升级上限，避免一次性写太多行。
	claudeVersionUpgradeMaxPerRun = 20
	// claudeVersionBindDelayMin/Max 首次绑定后到第一次升级的等待区间。
	// 留出这段窗口，新绑定的账号不会在下一轮就跟着动。
	claudeVersionBindDelayMin = 2 * time.Hour
	claudeVersionBindDelayMax = 14 * time.Hour
	// claudeVersionUpgradeDelayMin/Max 每次升级后到下一次升级的等待区间。
	// 一天一到两个新版本，8~36 小时一档大致跟得上，且天然分散。
	claudeVersionUpgradeDelayMin = 8 * time.Hour
	claudeVersionUpgradeDelayMax = 36 * time.Hour
)

// 版本分配权重：下标越靠前（越新）权重越高。真实用户里绝大多数跑最新版，
// 少数人停留在旧版；固定长尾分布比均匀分布更像真机。
var claudeVersionAssignWeights = []int{30, 20, 14, 10, 8, 6, 5, 4, 2, 1}

// claudeVersionList 是版本列表的不可变快照。
type claudeVersionList struct {
	versions  []string // 最新在前
	expiresAt time.Time
}

// ClaudeVersionService 维护"最近 N 个客户端版本"的可用版本集，并把版本绑到账号上。
//
// 版本特征本身来自编译期特征库（claude.Library / versionprofiles/profiles.json），
// 本服务只负责"谁用哪个版本"以及"什么时候换"，不参与特征构造。
//
// 职责边界：
//   - 可用版本集：特征库版本 ∪ 运行期补充版本（同步服务发现、库里尚未收录的新版本）。
//   - 分配：新账号/未绑定账号按下标权重确定性分配，不抖动。
//   - 升级排期：每个账号带一个 next_at，到期才升一档并重排，账号之间彼此错开。
//   - 热路径解析：按账号返回 claude.VersionProfile（UA / beta / TLS 一起给出，保证自洽）。
type ClaudeVersionService struct {
	settingRepo SettingRepository
	accountRepo AccountRepository

	list atomic.Pointer[claudeVersionList]
	mu   sync.Mutex // 串行化列表重建与维护

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	interval time.Duration
}

func NewClaudeVersionService(settingRepo SettingRepository, accountRepo AccountRepository) *ClaudeVersionService {
	return &ClaudeVersionService{
		settingRepo: settingRepo,
		accountRepo: accountRepo,
		stopCh:      make(chan struct{}),
		interval:    claudeVersionMaintainInterval,
	}
}

func (s *ClaudeVersionService) Start() {
	if s == nil || s.settingRepo == nil || s.accountRepo == nil || s.interval <= 0 {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		s.maintain()
		for {
			select {
			case <-ticker.C:
				s.maintain()
			case <-s.stopCh:
				return
			}
		}
	}()
}

func (s *ClaudeVersionService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()
}

// Versions 返回当前可用版本列表（最新在前）。
// 来源是特征库 + 运行期补充；列表为空时回落到全局生效版本。
func (s *ClaudeVersionService) Versions(ctx context.Context) []string {
	if snapshot := s.list.Load(); snapshot != nil && time.Now().Before(snapshot.expiresAt) {
		return snapshot.versions
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if snapshot := s.list.Load(); snapshot != nil && time.Now().Before(snapshot.expiresAt) {
		return snapshot.versions
	}
	versions := s.loadVersions(ctx)
	s.list.Store(&claudeVersionList{versions: versions, expiresAt: time.Now().Add(claudeVersionListTTL)})
	return versions
}

// loadVersions 合并特征库与运行期补充版本，去重、降序、截断。
// 特征库是编译期资产，正常不会为空；为空时用全局生效版本兜底，避免整条链路退化成单版本。
func (s *ClaudeVersionService) loadVersions(ctx context.Context) []string {
	versions := claude.LibraryVersions()
	if len(versions) == 0 {
		if seed := claude.EffectiveCLIVersion(); claude.IsSupportedCLIVersion(seed) {
			versions = []string{seed}
		}
	}

	raw, err := s.settingRepo.GetValue(ctx, SettingKeyClaudeCodeVersionHistory)
	if err != nil && !isSettingNotFound(err) {
		slog.Warn("claude_version_history_read_failed", "error", err)
	}
	for _, v := range parseClaudeVersionHistory(raw) {
		if !containsString(versions, v) {
			versions = append(versions, v)
		}
	}

	sort.SliceStable(versions, func(i, j int) bool { return compareClaudeVersions(versions[i], versions[j]) > 0 })
	if len(versions) > claude.MaxLibraryVersions {
		versions = versions[:claude.MaxLibraryVersions]
	}
	return versions
}

// parseClaudeVersionHistory 解析运行期补充版本：去空、去重、只留合法 semver、按新到旧排序。
func parseClaudeVersionHistory(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil
	}
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] || !claude.IsSupportedCLIVersion(v) {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return compareClaudeVersions(out[i], out[j]) > 0 })
	return out
}

// NoteVersion 记录一个特征库尚未收录的新版本，让它立刻可被分配。
// 已存在时不动（避免重复写库）。
func (s *ClaudeVersionService) NoteVersion(ctx context.Context, version string) {
	version = strings.TrimSpace(version)
	if version == "" || !claude.IsSupportedCLIVersion(version) {
		return
	}
	if containsString(claude.LibraryVersions(), version) {
		return // 已在特征库里，无需补充
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	versions := parseClaudeVersionHistory(mustSettingValue(ctx, s.settingRepo, SettingKeyClaudeCodeVersionHistory))
	if containsString(versions, version) {
		return
	}
	versions = append([]string{version}, versions...)
	encoded, err := json.Marshal(versions)
	if err != nil {
		return
	}
	if err := s.settingRepo.Set(ctx, SettingKeyClaudeCodeVersionHistory, string(encoded)); err != nil {
		slog.Warn("claude_version_history_write_failed", "version", version, "error", err)
		return
	}
	s.list.Store(&claudeVersionList{versions: s.loadVersionsLocked(string(encoded)), expiresAt: time.Now().Add(claudeVersionListTTL)})
	slog.Info("claude_version_noted", "version", version)
}

// loadVersionsLocked 在已持锁的前提下用刚写入的原始值重建快照，省一次读库。
func (s *ClaudeVersionService) loadVersionsLocked(rawHistory string) []string {
	versions := claude.LibraryVersions()
	if len(versions) == 0 {
		if seed := claude.EffectiveCLIVersion(); claude.IsSupportedCLIVersion(seed) {
			versions = []string{seed}
		}
	}
	for _, v := range parseClaudeVersionHistory(rawHistory) {
		if !containsString(versions, v) {
			versions = append(versions, v)
		}
	}
	sort.SliceStable(versions, func(i, j int) bool { return compareClaudeVersions(versions[i], versions[j]) > 0 })
	if len(versions) > claude.MaxLibraryVersions {
		versions = versions[:claude.MaxLibraryVersions]
	}
	return versions
}

// VersionForAccount 返回账号应当使用的版本 profile。
//
// 解析顺序：账号绑定值（且在可用集内）→ 按账号 ID 确定性分配 → 最新版本。
// 热路径不写库，未绑定的账号由 maintain 在后台补写。
func (s *ClaudeVersionService) VersionForAccount(ctx context.Context, account *Account) claude.VersionProfile {
	versions := s.Versions(ctx)
	if account != nil {
		if pinned := strings.TrimSpace(account.GetExtraString(AccountExtraCLIVersion)); pinned != "" && containsString(versions, pinned) {
			return claude.BuildVersionProfile(pinned)
		}
	}
	if len(versions) == 0 {
		return claude.BuildVersionProfile(claude.EffectiveCLIVersion())
	}
	if account == nil {
		return claude.BuildVersionProfile(versions[0])
	}
	return claude.BuildVersionProfile(pickClaudeVersion(account.ID, versions))
}

// pickClaudeVersion 按账号 ID 与下标权重确定性地挑一个版本。
func pickClaudeVersion(accountID int64, versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	weighted := make([]int, len(versions))
	total := 0
	for i := range versions {
		w := 1
		if i < len(claudeVersionAssignWeights) {
			w = claudeVersionAssignWeights[i]
		}
		weighted[i] = w
		total += w
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte{byte(accountID), byte(accountID >> 8), byte(accountID >> 16), byte(accountID >> 24)})
	point := int(h.Sum32() % uint32(total))
	for i, w := range weighted {
		if point < w {
			return versions[i]
		}
		point -= w
	}
	return versions[0]
}

// maintain 是后台维护：先补绑缺失/失效的账号，再处理到期的一档升级。
//
// 升级节奏完全由每个账号自己的 next_at 决定，所以同一轮里只有少数账号会动，
// 整池的版本号是陆续变化而非集体跳变。
func (s *ClaudeVersionService) maintain() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	versions := s.Versions(ctx)
	if len(versions) == 0 {
		return
	}
	accounts, err := s.accountRepo.ListByPlatform(ctx, PlatformAnthropic)
	if err != nil {
		slog.Warn("claude_version_maintain_list_failed", "error", err)
		return
	}

	now := time.Now()
	upgraded := 0
	for i := range accounts {
		account := &accounts[i]
		if account.Type != AccountTypeOAuth && account.Type != AccountTypeSetupToken {
			continue
		}
		pinned := strings.TrimSpace(account.GetExtraString(AccountExtraCLIVersion))

		// 1) 未绑定，或绑定的版本已被淘汰出可用集 → 重新分配并排第一次升级时间。
		if pinned == "" || !containsString(versions, pinned) {
			target := pickClaudeVersion(account.ID, versions)
			if err := s.accountRepo.UpdateExtra(ctx, account.ID, map[string]any{
				AccountExtraCLIVersion:       target,
				AccountExtraCLIVersionNextAt: nextClaudeUpgradeAt(account.ID, now, claudeVersionBindDelayMin, claudeVersionBindDelayMax),
			}); err != nil {
				slog.Debug("claude_version_bind_failed", "account_id", account.ID, "error", err)
				continue
			}
			slog.Info("claude_version_bound", "account_id", account.ID, "version", target, "previous", pinned)
			continue
		}

		// 2) 已是最新 → 只需保证有个 next_at，不必升级。
		idx := indexOfString(versions, pinned)
		if idx <= 0 {
			if account.GetExtraString(AccountExtraCLIVersionNextAt) == "" {
				_ = s.accountRepo.UpdateExtra(ctx, account.ID, map[string]any{
					AccountExtraCLIVersionNextAt: nextClaudeUpgradeAt(account.ID, now, claudeVersionUpgradeDelayMin, claudeVersionUpgradeDelayMax),
				})
			}
			continue
		}

		// 3) 落后但未到期 → 等自己的时间点。
		if upgraded >= claudeVersionUpgradeMaxPerRun {
			continue
		}
		if due := claudeVersionNextUpgradeAt(account); due.After(now) {
			continue
		}

		// 4) 到期 → 只往前挪一档（不是直接跳最新），并重排下一次。
		//    逐档跟进比一次性追到最新更像真机：真机是一次更新升一个版本。
		target := versions[idx-1]
		if err := s.accountRepo.UpdateExtra(ctx, account.ID, map[string]any{
			AccountExtraCLIVersion:       target,
			AccountExtraCLIVersionNextAt: nextClaudeUpgradeAt(account.ID, now, claudeVersionUpgradeDelayMin, claudeVersionUpgradeDelayMax),
		}); err != nil {
			slog.Debug("claude_version_upgrade_failed", "account_id", account.ID, "error", err)
			continue
		}
		slog.Info("claude_version_upgraded", "account_id", account.ID, "from", pinned, "to", target)
		upgraded++
	}
}

// claudeVersionNextUpgradeAt 读账号自己的下次升级时间；缺失或无法解析视为已到期。
func claudeVersionNextUpgradeAt(account *Account) time.Time {
	raw := strings.TrimSpace(account.GetExtraString(AccountExtraCLIVersionNextAt))
	if raw == "" {
		return time.Time{}
	}
	if sec, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(sec, 0)
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return time.Time{}
}

// nextClaudeUpgradeAt 生成下次升级时间（unix 秒）。
// 以账号 ID 派生随机种子再叠加时间抖动：同一账号的间隔每次都不同，账号之间也不同。
func nextClaudeUpgradeAt(accountID int64, now time.Time, minDelay, maxDelay time.Duration) string {
	span := int64(maxDelay - minDelay)
	if span <= 0 {
		return strconv.FormatInt(now.Add(minDelay).Unix(), 10)
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte{byte(accountID), byte(accountID >> 8), byte(accountID >> 16), byte(accountID >> 24), byte(now.Unix())})
	r := rand.New(rand.NewSource(int64(h.Sum64())))
	return strconv.FormatInt(now.Add(minDelay+time.Duration(r.Int63n(span))).Unix(), 10)
}

func indexOfString(list []string, target string) int {
	for i, v := range list {
		if v == target {
			return i
		}
	}
	return -1
}

func containsString(list []string, target string) bool {
	return indexOfString(list, target) >= 0
}

func mustSettingValue(ctx context.Context, repo SettingRepository, key string) string {
	raw, err := repo.GetValue(ctx, key)
	if err != nil {
		return ""
	}
	return raw
}

// compareClaudeVersions 比较两个版本号，语义同 claude 包内部比较。
func compareClaudeVersions(a, b string) int {
	return CompareVersions(a, b)
}

// isSettingNotFound 判定设置项缺失。缺失是正常情况（首次部署还没有补充版本），
// 不能当成读取失败。
func isSettingNotFound(err error) bool {
	return errors.Is(err, ErrSettingNotFound)
}
