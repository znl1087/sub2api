//go:build unit

package service

import (
	"context"
	"time"
)

// Existing account repository fakes predate the background Anthropic recheck.
// These tests do not schedule rechecks, so their candidate list is empty.

func (*accountRepoStub) ListAnthropicRateLimitedForRecheck(context.Context, time.Duration, int) ([]Account, error) {
	return nil, nil
}

func (*claudeVersionAccountRepoStub) ListAnthropicRateLimitedForRecheck(context.Context, time.Duration, int) ([]Account, error) {
	return nil, nil
}

func (*clineAccountRepo) ListAnthropicRateLimitedForRecheck(context.Context, time.Duration, int) ([]Account, error) {
	return nil, nil
}

func (*commandCodeCheckRepo) ListAnthropicRateLimitedForRecheck(context.Context, time.Duration, int) ([]Account, error) {
	return nil, nil
}

func (*fakeCNCheckRepo) ListAnthropicRateLimitedForRecheck(context.Context, time.Duration, int) ([]Account, error) {
	return nil, nil
}

func (*mockAccountRepoForGemini) ListAnthropicRateLimitedForRecheck(context.Context, time.Duration, int) ([]Account, error) {
	return nil, nil
}

func (*mockAccountRepoForPlatform) ListAnthropicRateLimitedForRecheck(context.Context, time.Duration, int) ([]Account, error) {
	return nil, nil
}

func (*pluginDirRepoStub) ListAnthropicRateLimitedForRecheck(context.Context, time.Duration, int) ([]Account, error) {
	return nil, nil
}

func (*teamLinkedAccountRepoStub) ListAnthropicRateLimitedForRecheck(context.Context, time.Duration, int) ([]Account, error) {
	return nil, nil
}
