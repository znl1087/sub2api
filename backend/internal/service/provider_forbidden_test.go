//go:build unit

package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestProviderForbiddenClassification(t *testing.T) {
	for _, platform := range []string{PlatformAnthropic, PlatformOpenAI} {
		for _, test := range []struct {
			name string
			body string
			want providerForbiddenClass
		}{
			{"empty", "", providerForbiddenUnknown},
			{"generic JSON", `{"error":{"type":"permission_error","message":"Forbidden"}}`, providerForbiddenUnknown},
			{"edge rejection", `{"error":{"message":"temporary edge rejection"}}`, providerForbiddenUnknown},
			{"HTML", `<html>Forbidden</html>`, providerForbiddenUnknown},
			{"plain text", "Forbidden", providerForbiddenUnknown},
			{"truncated JSON", `{"error":{"code":"account_disabled"`, providerForbiddenUnknown},
			{"echoed request", `{"error":{"message":"request rejected"},"request":{"error":{"code":"account_disabled"}}}`, providerForbiddenUnknown},
			{"credentials", `{"error":{"type":"authentication_error","message":"invalid API key"}}`, providerForbiddenAccount},
			{"revoked token", `{"error":{"code":"token_revoked"}}`, providerForbiddenAccount},
			{"workspace", `{"detail":{"code":"deactivated_workspace"}}`, providerForbiddenAccount},
			{"disabled account", `{"error":{"code":"account_disabled"}}`, providerForbiddenAccount},
			{"content refusal", `{"error":{"code":"content_policy_violation"}}`, providerForbiddenContent},
			{"cyber refusal", `{"response":{"error":{"code":"cyber_policy"}}}`, providerForbiddenContent},
			{"model permission", `{"error":{"code":"model_access_denied"}}`, providerForbiddenModel},
			{"quota", `{"error":{"code":"insufficient_quota"}}`, providerForbiddenQuota},
		} {
			t.Run(platform+"/"+test.name, func(t *testing.T) {
				account := &Account{Platform: platform}
				require.Equal(t, test.want, classifyProviderForbidden(account, 403, []byte(test.body)))
				require.Equal(t, providerForbiddenNone, classifyProviderForbidden(account, 401, []byte(test.body)))
			})
		}
	}
	for _, platform := range []string{PlatformGrok, PlatformGemini, PlatformAntigravity, PlatformKimi} {
		require.Equal(t, providerForbiddenNone, classifyProviderForbidden(&Account{Platform: platform}, 403, nil))
	}
}

func TestProviderUnknownForbiddenRepeatedNeverPenalizes(t *testing.T) {
	for _, platform := range []string{PlatformAnthropic, PlatformOpenAI} {
		for _, accountType := range []string{AccountTypeOAuth, AccountTypeAPIKey} {
			t.Run(platform+"/"+accountType, func(t *testing.T) {
				repo := &rateLimitAccountRepoStub{}
				counter := &countingOpenAI403CounterCache{}
				blocker := &runtimeBlockRecorder{}
				svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
				svc.SetOpenAI403CounterCache(counter)
				svc.SetAccountRuntimeBlocker(blocker)
				account := &Account{ID: 42001, Platform: platform, Type: accountType, Status: StatusActive, Schedulable: true}
				for attempt := 0; attempt < 6; attempt++ {
					require.False(t, svc.HandleUpstreamError(context.Background(), account, 403, http.Header{}, []byte(`{"error":{"message":"Forbidden"}}`)))
				}
				require.Zero(t, counter.increments)
				require.Zero(t, repo.setErrorCalls)
				require.Zero(t, repo.tempCalls)
				require.Zero(t, repo.rateLimitedCalls)
				require.Zero(t, repo.updateCredentialsCalls)
				require.Empty(t, blocker.accounts)
				require.True(t, account.IsSchedulable())
			})
		}
	}
}

func TestProviderForbiddenBudgetAndStreamTurnIsolation(t *testing.T) {
	for _, platform := range []string{PlatformAnthropic, PlatformOpenAI} {
		t.Run(platform, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			makeFailure := func(id int64) *UpstreamFailoverError {
				return decorateProviderForbiddenFailover(c, &Account{ID: id, Platform: platform}, &UpstreamFailoverError{StatusCode: 403, RetryableOnSameAccount: true})
			}
			first := makeFailure(1)
			require.True(t, first.ShouldRetryNextAccount())
			require.True(t, first.RequestScopedTransient)
			require.False(t, first.RetryableOnSameAccount)
			require.False(t, first.ShouldReportAccountScheduleFailure())
			require.True(t, makeFailure(1).ShouldRetryNextAccount())
			require.False(t, makeFailure(2).ShouldRetryNextAccount())
			BeginOpsStreamTurn(c, 2)
			require.True(t, makeFailure(2).ShouldRetryNextAccount())
			other, _ := gin.CreateTestContext(httptest.NewRecorder())
			require.True(t, decorateProviderForbiddenFailover(other, &Account{ID: 1, Platform: platform}, &UpstreamFailoverError{StatusCode: 403}).ShouldRetryNextAccount())
		})
	}
}

type providerModelForbiddenRepo struct {
	rateLimitAccountRepoStub
	account    *Account
	model      string
	modelCalls int
}

func (r *providerModelForbiddenRepo) SetModelRateLimit(_ context.Context, _ int64, model string, until time.Time, _ ...string) error {
	r.modelCalls++
	r.model = model
	r.account.Extra = map[string]any{"model_rate_limits": map[string]any{model: map[string]any{"rate_limit_reset_at": until.Format(time.RFC3339)}}}
	return nil
}

func TestProviderModelForbiddenPreservesSiblingModels(t *testing.T) {
	for _, platform := range []string{PlatformAnthropic, PlatformOpenAI} {
		account := &Account{ID: 42002, Platform: platform, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true}
		repo := &providerModelForbiddenRepo{account: account}
		svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		body := []byte(`{"error":{"code":"model_access_denied"}}`)
		require.False(t, svc.HandleUpstreamError(context.Background(), account, 403, http.Header{}, body, "mapped-model"))
		require.Equal(t, 1, repo.modelCalls)
		require.Equal(t, "mapped-model", repo.model)
		require.Zero(t, repo.tempCalls)
		require.Zero(t, repo.setErrorCalls)
		require.False(t, account.IsSchedulableForModel("mapped-model"))
		require.True(t, account.IsSchedulableForModel("other-model"))
	}
}

func TestProviderContentForbiddenStopsWithoutAccountMutation(t *testing.T) {
	for _, platform := range []string{PlatformAnthropic, PlatformOpenAI} {
		repo := &rateLimitAccountRepoStub{}
		svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		account := &Account{ID: 42003, Platform: platform, Type: AccountTypeOAuth, Credentials: map[string]any{
			"temp_unschedulable_enabled": true,
			"temp_unschedulable_rules":   []any{map[string]any{"error_code": float64(403), "keywords": []any{"content_policy"}, "duration_minutes": float64(30)}},
		}}
		body := []byte(`{"error":{"code":"content_policy_violation"}}`)
		require.False(t, svc.HandleUpstreamError(context.Background(), account, 403, nil, body))
		require.Equal(t, ErrorPolicySkipped, svc.CheckErrorPolicy(context.Background(), account, 403, body))
		gateway := &OpenAIGatewayService{rateLimitService: svc}
		require.False(t, gateway.handleOpenAIAccountUpstreamError(context.Background(), account, 403, nil, body, "test-model"))
		require.Zero(t, repo.setErrorCalls)
		require.Zero(t, repo.tempCalls)
		failure := decorateProviderForbiddenFailover(nil, account, &UpstreamFailoverError{StatusCode: 403, ResponseBody: body})
		require.False(t, failure.ShouldRetryNextAccount())
		require.False(t, failure.ShouldReportAccountScheduleFailure())
		require.Equal(t, 403, failure.ClientStatusCode)
	}
}

func TestProviderQuotaForbiddenUsesRecoverableRateLimit(t *testing.T) {
	for _, platform := range []string{PlatformAnthropic, PlatformOpenAI} {
		repo := &rateLimitAccountRepoStub{}
		svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		account := &Account{ID: 42004, Platform: platform, Type: AccountTypeAPIKey}
		body := []byte(`{"error":{"code":"insufficient_quota"}}`)
		require.False(t, svc.HandleUpstreamError(context.Background(), account, 403, http.Header{"Retry-After": {"60"}}, body))
		require.Equal(t, 1, repo.rateLimitedCalls)
		require.Zero(t, repo.setErrorCalls)
	}
}

func TestProviderUnknownForbiddenHonorsExplicitTemporaryRule(t *testing.T) {
	for _, platform := range []string{PlatformAnthropic, PlatformOpenAI} {
		repo := &rateLimitAccountRepoStub{}
		svc := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		account := &Account{ID: 42005, Platform: platform, Type: AccountTypeOAuth, Credentials: map[string]any{
			"temp_unschedulable_enabled": true,
			"temp_unschedulable_rules": []any{map[string]any{
				"error_code": float64(403), "keywords": []any{"temporary edge rejection"}, "duration_minutes": float64(23),
			}},
		}}
		require.True(t, svc.HandleUpstreamError(context.Background(), account, 403, nil, []byte(`{"error":{"message":"temporary edge rejection"}}`)))
		require.Equal(t, 1, repo.tempCalls)
		require.Zero(t, repo.setErrorCalls)
	}
}

func TestProviderForbiddenCodexOAuthForwardUsesRequestBudget(t *testing.T) {
	for _, poolMode := range []bool{false, true} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
		c.Request.Header.Set("User-Agent", "codex_cli_rs/0.144.1")
		c.Request.Header.Set("originator", "codex_cli_rs")
		upstream := &httpUpstreamRecorder{}
		for range 2 {
			upstream.responses = append(upstream.responses, &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":{"type":"permission_error","message":"Forbidden"}}`)),
			})
		}
		repo := &rateLimitAccountRepoStub{}
		counter := &countingOpenAI403CounterCache{}
		rateLimits := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
		rateLimits.SetOpenAI403CounterCache(counter)
		svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream, rateLimitService: rateLimits, toolCorrector: NewCodexToolCorrector()}
		for id := int64(1); id <= 2; id++ {
			account := &Account{ID: id, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Concurrency: 1, Status: StatusActive, Schedulable: true,
				Credentials: map[string]any{"access_token": "oauth-token", "chatgpt_account_id": "chatgpt-acc", "pool_mode": poolMode}}
			_, err := svc.Forward(context.Background(), c, account, []byte(`{"model":"gpt-5.1","input":"hello","stream":false}`))
			var failure *UpstreamFailoverError
			require.ErrorAs(t, err, &failure)
			require.Equal(t, ProviderUnknownForbiddenReason, failure.Reason)
			require.Equal(t, id < 2, failure.ShouldRetryNextAccount())
			require.False(t, failure.RetryableOnSameAccount)
			require.False(t, failure.ShouldReportAccountScheduleFailure())
		}
		require.Len(t, upstream.requests, 2)
		require.Zero(t, counter.increments)
		require.Zero(t, repo.setErrorCalls)
		require.Zero(t, repo.tempCalls)
		require.False(t, c.Writer.Written())
	}
}

type providerForbiddenAnthropicUpstream struct {
	*anthropicHTTPUpstreamRecorder
	calls int
}

func (u *providerForbiddenAnthropicUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, concurrency int, profile *tlsfingerprint.Profile) (*http.Response, error) {
	u.calls++
	return u.anthropicHTTPUpstreamRecorder.DoWithTLS(req, proxyURL, accountID, concurrency, profile)
}

func TestProviderForbiddenClaudeOAuthForwardSkipsSameAccountRetry(t *testing.T) {
	for _, code := range []string{"permission_error", "content_policy_violation", "model_access_denied"} {
		t.Run(code, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			parsed, err := ParseGatewayRequest(NewRequestBodyRef([]byte(`{"model":"claude-3-5-sonnet-latest","max_tokens":128,"messages":[{"role":"user","content":"hello"}]}`)), PlatformAnthropic)
			require.NoError(t, err)
			upstream := &providerForbiddenAnthropicUpstream{anthropicHTTPUpstreamRecorder: &anthropicHTTPUpstreamRecorder{resp: &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"` + code + `","message":"Forbidden"}}`)),
			}}}
			account := newAnthropicOAuthAccountForPartialUsageTest()
			repo := &providerModelForbiddenRepo{account: account}
			svc := newForwardPartialUsageServiceForTest(upstream.anthropicHTTPUpstreamRecorder)
			svc.httpUpstream = upstream
			svc.rateLimitService = NewRateLimitService(repo, nil, svc.cfg, nil, nil)
			_, err = svc.Forward(context.Background(), c, account, parsed)
			var failure *UpstreamFailoverError
			require.ErrorAs(t, err, &failure)
			require.Equal(t, 1, upstream.calls)
			require.False(t, failure.RetryableOnSameAccount)
			require.False(t, failure.ShouldReportAccountScheduleFailure())
			require.Zero(t, repo.setErrorCalls)
			require.Zero(t, repo.tempCalls)
		})
	}
}
