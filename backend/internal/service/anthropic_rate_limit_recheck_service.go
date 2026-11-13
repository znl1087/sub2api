package service

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	// anthropicRateLimitRecheckInterval 复查间隔。
	anthropicRateLimitRecheckInterval = 2 * time.Minute
	// anthropicRateLimitRecheckMinRemaining 只复查剩余冷却仍长于该值的账号：
	// 秒级兜底冷却本来就会自己过期，不值得为它打一次上游。
	anthropicRateLimitRecheckMinRemaining = 10 * time.Minute
	// anthropicRateLimitRecheckPerRun 单轮最多复查的账号数。
	anthropicRateLimitRecheckPerRun = 10
	// anthropicRateLimitRecheckPerAccount 同一账号两次复查的最小间隔。
	anthropicRateLimitRecheckPerAccount = 10 * time.Minute
	// anthropicRateLimitRecheckTimeout 单轮整体超时。
	anthropicRateLimitRecheckTimeout = 90 * time.Second
	// anthropicRateLimitRecheckConcurrency 并发上限，避免一次打太多 usage 请求。
	anthropicRateLimitRecheckConcurrency = 2
	// anthropicRateLimitRecheckClearBelow 用量低于该百分比（0-100）视为仍有容量。
	// 留 0.5 的余量，避免 99.6% 这种"差一点满"被反复解封又撞 429。
	anthropicRateLimitRecheckClearBelow = 99.5
)

// AnthropicRateLimitRecheckService 定期核实被限流账号的真实上游用量。
//
// 存在理由：429 响应带全套 anthropic-ratelimit-unified-* 头，其中 reset 时间在
// "并发超限 / 瞬时频率限制" 这类非窗口耗尽的 429 上同样存在。一旦把它当成窗口耗尽，
// 账号会被封到几小时后；而账号不可调度就再也拿不到成功响应，UpdateSessionWindow
// 的自动清除逻辑永远没有机会执行——误判一旦落库就是"死封"。
//
// 本任务对长冷却账号主动查 /api/oauth/usage：真实 utilization 没满就解封，
// 满了就保持（并按上游 reset 校正）。这是限流判定的安全网，不是主路径。
type AnthropicRateLimitRecheckService struct {
	accountRepo AccountRepository
	usage       *AccountUsageService
	interval    time.Duration

	mu        sync.Mutex
	lastProbe map[int64]time.Time

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func NewAnthropicRateLimitRecheckService(accountRepo AccountRepository, usage *AccountUsageService) *AnthropicRateLimitRecheckService {
	return &AnthropicRateLimitRecheckService{
		accountRepo: accountRepo,
		usage:       usage,
		interval:    anthropicRateLimitRecheckInterval,
		lastProbe:   make(map[int64]time.Time),
		stopCh:      make(chan struct{}),
	}
}

func (s *AnthropicRateLimitRecheckService) Start() {
	if s == nil || s.accountRepo == nil || s.usage == nil || s.interval <= 0 {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.runOnce()
			case <-s.stopCh:
				return
			}
		}
	}()
}

func (s *AnthropicRateLimitRecheckService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
	s.wg.Wait()
}

func (s *AnthropicRateLimitRecheckService) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), anthropicRateLimitRecheckTimeout)
	defer cancel()

	accounts, err := s.accountRepo.ListAnthropicRateLimitedForRecheck(
		ctx, anthropicRateLimitRecheckMinRemaining, anthropicRateLimitRecheckPerRun*3)
	if err != nil {
		slog.Warn("anthropic_rate_limit_recheck_list_failed", "error", err)
		return
	}
	if len(accounts) == 0 {
		return
	}

	sem := make(chan struct{}, anthropicRateLimitRecheckConcurrency)
	var wg sync.WaitGroup
	probed := 0
	for i := range accounts {
		account := accounts[i]
		if !s.claimProbe(account.ID) {
			continue
		}
		if probed >= anthropicRateLimitRecheckPerRun {
			break
		}
		probed++
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s.recheckOne(ctx, &account)
		}()
	}
	wg.Wait()
}

// claimProbe 判断该账号本轮是否值得复查，并记录时间戳。
func (s *AnthropicRateLimitRecheckService) claimProbe(accountID int64) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.lastProbe[accountID]; ok && now.Sub(last) < anthropicRateLimitRecheckPerAccount {
		return false
	}
	s.lastProbe[accountID] = now
	return true
}

func (s *AnthropicRateLimitRecheckService) recheckOne(ctx context.Context, account *Account) {
	usage, err := s.usage.GetUsage(ctx, account.ID, true)
	if err != nil || usage == nil {
		slog.Debug("anthropic_rate_limit_recheck_usage_failed", "account_id", account.ID, "error", err)
		return
	}

	// 任一窗口仍处于满额状态 → 这是真实限流，保持封禁。
	// 用量缺失时保守起见也保持，宁可晚解封也不要放进一个真的满了的账号。
	if usage.FiveHour == nil && usage.SevenDay == nil {
		return
	}
	if windowAtLimit(usage.FiveHour) || windowAtLimit(usage.SevenDay) || windowAtLimit(usage.SevenDayFable) {
		slog.Info("anthropic_rate_limit_recheck_still_limited",
			"account_id", account.ID,
			"util_5h", utilizationOf(usage.FiveHour),
			"util_7d", utilizationOf(usage.SevenDay))
		return
	}

	if err := s.accountRepo.ClearRateLimit(ctx, account.ID); err != nil {
		slog.Warn("anthropic_rate_limit_recheck_clear_failed", "account_id", account.ID, "error", err)
		return
	}
	slog.Info("anthropic_rate_limit_recheck_cleared",
		"account_id", account.ID,
		"util_5h", utilizationOf(usage.FiveHour),
		"util_7d", utilizationOf(usage.SevenDay),
		"previous_reset_at", account.RateLimitResetAt)
}

func windowAtLimit(w *UsageProgress) bool {
	return w != nil && w.Utilization >= anthropicRateLimitRecheckClearBelow
}

func utilizationOf(w *UsageProgress) float64 {
	if w == nil {
		return -1
	}
	return w.Utilization
}
