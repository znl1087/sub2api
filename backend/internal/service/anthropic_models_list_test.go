package service

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestAnthropicModelsListRefreshDiscoversNewModel(t *testing.T) {
	var calls atomic.Int32
	s := &GatewayService{
		cfg: &config.Config{},
		httpUpstream: &codexModelsHTTPUpstreamStub{do: func(_ *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
			if calls.Add(1) == 1 {
				return ordinaryModelsUpstreamResponse(`{"data":[{"id":"claude-existing"}]}`), nil
			}
			return ordinaryModelsUpstreamResponse(`{"data":[{"id":"claude-existing"},{"id":"claude-new"}]}`), nil
		}},
	}
	account := &Account{ID: 1, Platform: PlatformAnthropic, Type: AccountTypeOAuth,
		Credentials: map[string]any{"access_token": "fixture-token"}}
	ctx := context.Background()
	first, err := s.fetchAnthropicModelsList(ctx, account)
	require.NoError(t, err)
	require.NotContains(t, string(first.Body), "claude-new")

	cache := &s.anthropicModelsCache
	cache.mu.Lock()
	for key, entry := range cache.entries {
		entry.expiresAt = time.Now().Add(-time.Second)
		entry.staleUntil = time.Now().Add(-time.Second)
		cache.entries[key] = entry
	}
	cache.mu.Unlock()

	refreshed, err := s.fetchAnthropicModelsList(ctx, account)
	require.NoError(t, err)
	require.Contains(t, string(refreshed.Body), "claude-new")
	require.EqualValues(t, 2, calls.Load())
}
