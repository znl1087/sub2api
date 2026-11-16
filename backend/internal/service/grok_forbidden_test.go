//go:build unit

package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGrokUnknownForbiddenClassification(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		unknown bool
	}{
		{"empty", "", true},
		{"generic permission", `{"code":"permission-denied","err":"Access to the chat endpoint is denied"}`, true},
		{"HTML", `<html>Forbidden</html>`, true},
		{"content", `{"code":"permission-denied","err":"Content violates usage guidelines"}`, false},
		{"subscription", `{"err":"subscription required"}`, false},
		{"suspended", `{"error":{"code":"account_suspended"}}`, false},
		{"revoked", `{"error":{"code":"token_revoked"}}`, false},
		{"quota", `{"code":"personal-team-blocked:spending-limit","error":"spending limit reached"}`, false},
		{"model", `{"error":{"code":"model_access_denied","model":"grok-4.7"}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.unknown, isGrokUnknownForbidden(http.StatusForbidden, []byte(test.body)))
			require.False(t, isGrokUnknownForbidden(http.StatusUnauthorized, []byte(test.body)))
		})
	}
}

func TestGrokUnknownForbiddenLeavesAccountAndQuotaStateUntouched(t *testing.T) {
	for _, body := range []string{"", `{"code":"permission-denied","err":"Forbidden"}`, `<html>Forbidden</html>`} {
		repo := &grokQuotaAccountRepo{}
		svc := &OpenAIGatewayService{accountRepo: repo}
		account := healthyGrokOAuthGatewayTestAccount(32001, "test-token")
		headers := http.Header{"X-Ratelimit-Remaining-Requests": {"0"}, "Retry-After": {"3600"}}
		svc.handleGrokAccountUpstreamError(context.Background(), account, http.StatusForbidden, headers, []byte(body))
		require.Zero(t, repo.tempUnschedCalls)
		require.Zero(t, repo.rateLimitedCalls)
		require.Zero(t, repo.updateCalls)
		require.True(t, account.IsSchedulable())
		require.False(t, svc.isOpenAIAccountRuntimeBlocked(account))
	}
}

func TestGrokForbiddenBudgetIsRequestLocalAndCountsDistinctAccounts(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	body := []byte(`{"code":"permission-denied","err":"Forbidden"}`)
	account := healthyGrokOAuthGatewayTestAccount(32002, "test-token")
	account.Credentials["pool_mode"] = true
	first := NewGrokUpstreamFailoverError(c, account, 403, nil, body)
	require.True(t, first.ShouldRetryNextAccount())
	require.False(t, first.RetryableOnSameAccount)
	require.False(t, first.ShouldReportAccountScheduleFailure())
	require.True(t, first.RequestScopedTransient)
	require.Equal(t, GrokUnknownForbiddenReason, first.Reason)
	require.True(t, NewGrokUpstreamFailoverError(c, account, 403, nil, body).ShouldRetryNextAccount())
	account2 := healthyGrokOAuthGatewayTestAccount(32003, "test-token")
	second := NewGrokUpstreamFailoverError(c, account2, 403, nil, body)
	require.False(t, second.ShouldRetryNextAccount())
	require.False(t, second.ShouldReportAccountScheduleFailure())
	otherRequest, _ := gin.CreateTestContext(httptest.NewRecorder())
	require.True(t, NewGrokUpstreamFailoverError(otherRequest, account2, 403, nil, body).ShouldRetryNextAccount())
	BeginOpsStreamTurn(c, 2)
	require.True(t, NewGrokUpstreamFailoverError(c, account2, 403, nil, body).ShouldRetryNextAccount())
	require.False(t, NewGrokUpstreamFailoverError(nil, account, 403, nil, body).ShouldRetryNextAccount())
}

func TestGrokModelForbiddenOnlyBlocksRequestedModel(t *testing.T) {
	repo := &grokQuotaAccountRepo{}
	svc := &OpenAIGatewayService{accountRepo: repo}
	account := healthyGrokOAuthGatewayTestAccount(32004, "test-token")
	body := []byte(`{"error":{"code":"model_access_denied","model":"grok-4.7"}}`)
	svc.handleGrokAccountUpstreamError(context.Background(), account, 403, nil, body)
	require.Zero(t, repo.tempUnschedCalls)
	require.Zero(t, repo.rateLimitedCalls)
	require.Zero(t, repo.updateCalls)
	require.True(t, isGrokModelQuotaBlocked(account.ID, "grok-4.7", time.Now()))
	require.False(t, isGrokModelQuotaBlocked(account.ID, "grok-4.6", time.Now()))
	require.True(t, account.IsSchedulable())
	failure := NewGrokUpstreamFailoverError(nil, account, 403, nil, body)
	require.False(t, failure.ShouldReportAccountScheduleFailure())
	require.True(t, failure.ShouldRetryNextAccount())
	ctx := withGrokTeamRateLimitModel(context.Background(), "grok-mapped-model")
	svc.handleGrokAccountUpstreamError(ctx, account, 403, nil, []byte(`{"code":"model_access_denied"}`))
	require.True(t, isGrokModelQuotaBlocked(account.ID, "grok-mapped-model", time.Now()))
	require.False(t, isGrokModelQuotaBlocked(account.ID, "grok-4.6", time.Now()))
}

func TestGrokUnknownForbiddenSharedFallbackDoesNotPenalize(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	rateLimits := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	svc := &OpenAIGatewayService{rateLimitService: rateLimits}
	account := healthyGrokOAuthGatewayTestAccount(32006, "test-token")
	body := []byte(`{"error":{"message":"temporary edge rejection"}}`)
	require.False(t, svc.handleOpenAIAccountUpstreamError(context.Background(), account, 403, http.Header{}, body, "grok-4.7"))
	require.Zero(t, repo.setErrorCalls)
	require.Zero(t, repo.tempCalls)
	require.False(t, svc.isOpenAIAccountRuntimeBlocked(account))
}

func TestGrokForbiddenDiagnosticsRedactAndHonorCaptureSetting(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	cfg := &config.Config{}
	cfg.Gateway.LogUpstreamErrorBody = true
	cfg.Gateway.LogUpstreamErrorBodyMaxBytes = 2048
	svc := &OpenAIGatewayService{cfg: cfg}
	request := httptest.NewRequest(http.MethodPost, "https://upstream.example/v1/chat/completions?token=secret-query", nil)
	body := []byte(`{"code":"permission-denied","err":"Forbidden access_token=secret-access refresh_token=secret-refresh"}`)
	svc.appendGrokUpstreamError(c, &http.Response{Request: request}, body, OpsUpstreamErrorEvent{UpstreamStatusCode: 403})
	value, _ := c.Get(OpsUpstreamErrorsKey)
	events := value.([]*OpsUpstreamErrorEvent)
	require.Len(t, events, 1)
	raw, err := json.Marshal(events)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "secret-access")
	require.NotContains(t, string(raw), "secret-refresh")
	require.NotContains(t, string(raw), "secret-query")
	require.Equal(t, "https://upstream.example/v1/chat/completions", events[0].UpstreamURL)
	require.Contains(t, events[0].Message, "Forbidden")
	require.NotEmpty(t, events[0].Detail)
	cfg.Gateway.LogUpstreamErrorBody = false
	svc.appendGrokUpstreamError(c, nil, body, OpsUpstreamErrorEvent{UpstreamStatusCode: 403})
	value, _ = c.Get(OpsUpstreamErrorsKey)
	require.Empty(t, value.([]*OpsUpstreamErrorEvent)[1].Detail)
}

func TestGrokRawChatUnknownForbiddenThenHealthyRequest(t *testing.T) {
	account := healthyGrokOAuthGatewayTestAccount(32005, "test-token")
	repo := &grokQuotaAccountRepo{mockAccountRepoForPlatform: &mockAccountRepoForPlatform{accountsByID: map[int64]*Account{account.ID: account}}}
	upstream := &httpUpstreamRecorder{responses: []*http.Response{
		{StatusCode: 403, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"code":"permission-denied","err":"Forbidden"}`))},
		{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"id":"chat-healthy","model":"grok-4.7","choices":[{"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))},
	}}
	svc := &OpenAIGatewayService{accountRepo: repo, httpUpstream: upstream, grokTokenProvider: NewGrokTokenProvider(repo, nil)}
	body := []byte(`{"model":"grok-4.7","messages":[{"role":"user","content":"test"}],"stop":"end"}`)
	newContext := func() (*gin.Context, *httptest.ResponseRecorder) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
		return c, recorder
	}
	c, _ := newContext()
	_, err := svc.ForwardAsChatCompletions(context.Background(), c, account, body, "", "")
	var failure *UpstreamFailoverError
	require.ErrorAs(t, err, &failure)
	require.Equal(t, GrokUnknownForbiddenReason, failure.Reason)
	require.True(t, failure.ShouldRetryNextAccount())
	require.Zero(t, repo.tempUnschedCalls)
	c, recorder := newContext()
	result, err := svc.ForwardAsChatCompletions(context.Background(), c, account, body, "", "")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 200, recorder.Code)
	require.Contains(t, recorder.Body.String(), "OK")
	require.Zero(t, repo.tempUnschedCalls)
}
