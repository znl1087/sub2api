package service

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

type providerForbiddenClass uint8

const (
	providerForbiddenNone providerForbiddenClass = iota
	providerForbiddenUnknown
	providerForbiddenContent
	providerForbiddenModel
	providerForbiddenAccount
	providerForbiddenQuota
)

const (
	ProviderUnknownForbiddenReason GatewayFailureReason = "provider_unknown_forbidden"
	ProviderContentForbiddenReason GatewayFailureReason = "provider_content_forbidden"
	ProviderModelForbiddenReason   GatewayFailureReason = "provider_model_forbidden"
	providerForbiddenAccountsKey                        = "provider_unknown_forbidden_accounts"
)

// classifyProviderForbidden reads authoritative error fields from Claude and
// OpenAI responses. Request payloads echoed elsewhere in JSON carry no verdict.
func classifyProviderForbidden(account *Account, status int, body []byte) providerForbiddenClass {
	if account == nil || status != http.StatusForbidden ||
		(account.Platform != PlatformAnthropic && account.Platform != PlatformOpenAI) {
		return providerForbiddenNone
	}
	if isHTMLResponse(body) || isCloudflareBotBlockResponse(body) {
		return providerForbiddenUnknown
	}
	trimmed := strings.TrimSpace(string(body))
	if !gjson.ValidBytes(body) && (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) {
		return providerForbiddenUnknown
	}
	codes := make([]string, 0, 7)
	for _, path := range []string{"error.code", "error.type", "response.error.code", "response.error.type", "detail.code", "code", "type"} {
		field := gjson.GetBytes(body, path)
		if field.Type == gjson.String {
			codes = append(codes, normalizeGrokErrorMarker(field.String()))
		}
	}
	for _, code := range codes {
		if isOpenAIUpstreamAccessStateCode(code) {
			return providerForbiddenAccount
		}
		switch code {
		case "authentication_error", "invalid_api_key", "invalid_token", "invalid_access_token", "token_revoked", "token_invalidated", "credentials_revoked":
			return providerForbiddenAccount
		}
	}
	for _, code := range codes {
		switch code {
		case "cyber_policy", "content_policy", "content_policy_violation", "content_filter", "content_filter_error", "content_moderation", "safety_violation":
			return providerForbiddenContent
		case "model_access_denied", "model_not_allowed", "model_not_entitled", "model_not_found", "model_permission_denied":
			return providerForbiddenModel
		case "insufficient_quota", "billing_hard_limit_reached", "credit_balance_too_low", "usage_limit_exceeded", "spending_limit_reached", "rate_limit_exceeded":
			return providerForbiddenQuota
		}
	}
	messages := make([]string, 0, 8)
	for _, path := range []string{"error.message", "response.error.message", "message", "err", "detail", "error"} {
		field := gjson.GetBytes(body, path)
		if field.Type == gjson.String {
			messages = append(messages, strings.ToLower(field.String()))
		}
	}
	if !gjson.ValidBytes(body) {
		messages = append(messages, strings.ToLower(strings.TrimSpace(string(body))))
	}
	for _, message := range messages {
		for _, phrase := range []string{"account has been disabled", "account has been suspended", "account is suspended", "organization has been disabled", "organization has been suspended", "workspace has been deactivated", "api key has been revoked", "invalid api key"} {
			if strings.Contains(message, phrase) {
				return providerForbiddenAccount
			}
		}
		for _, phrase := range []string{"content policy violation", "content violates usage guidelines", "request blocked by content moderation", "request rejected by content moderation", "prompt violates policy"} {
			if strings.Contains(message, phrase) {
				return providerForbiddenContent
			}
		}
		for _, phrase := range []string{"do not have access to model", "do not have access to the model", "not authorized to use this model", "not entitled to this model"} {
			if strings.Contains(message, phrase) {
				return providerForbiddenModel
			}
		}
		for _, phrase := range []string{"credit balance is too low", "insufficient quota", "usage limit exceeded", "spending limit reached"} {
			if strings.Contains(message, phrase) {
				return providerForbiddenQuota
			}
		}
	}
	return providerForbiddenUnknown
}

func decorateProviderForbiddenFailover(c *gin.Context, account *Account, failure *UpstreamFailoverError) *UpstreamFailoverError {
	if failure == nil {
		return nil
	}
	classification := classifyProviderForbidden(account, failure.StatusCode, failure.ResponseBody)
	switch classification {
	case providerForbiddenUnknown:
		failure.Reason = ProviderUnknownForbiddenReason
		failure.ClientStatusCode = http.StatusBadGateway
		failure.ClientMessage = "Upstream rejected this request (403)"
	case providerForbiddenContent:
		failure.Reason = ProviderContentForbiddenReason
		failure.ClientStatusCode = http.StatusForbidden
		failure.ClientMessage = "Upstream rejected this request due to content policy"
		failure.NextAccountAction = NextAccountStop
	case providerForbiddenModel:
		failure.Reason = ProviderModelForbiddenReason
		failure.Scope = GatewayFailureScopeRequest
		failure.RetryableOnSameAccount = false
		return failure
	case providerForbiddenQuota:
		failure.RetryableOnSameAccount = false
		return failure
	default:
		return failure
	}
	failure.Scope = GatewayFailureScopeRequest
	failure.RequestScopedTransient = true
	failure.RetryableOnSameAccount = false
	if c != nil {
		if raw, ok := c.Get(OpsUpstreamErrorsKey); ok {
			if events, ok := raw.([]*OpsUpstreamErrorEvent); ok && len(events) > 0 {
				event := events[len(events)-1]
				if event.AccountID == account.ID && event.UpstreamStatusCode == failure.StatusCode {
					event.Scope = string(failure.Scope)
					event.Reason = string(failure.Reason)
				}
			}
		}
	}
	if classification == providerForbiddenContent {
		return failure
	}
	if c == nil {
		failure.NextAccountAction = NextAccountStop
		return failure
	}
	accounts, _ := c.Get(providerForbiddenAccountsKey)
	seen, _ := accounts.(map[int64]struct{})
	if seen == nil {
		seen = make(map[int64]struct{})
	}
	seen[account.ID] = struct{}{}
	c.Set(providerForbiddenAccountsKey, seen)
	if len(seen) >= 2 {
		failure.NextAccountAction = NextAccountStop
	}
	return failure
}

// IsRequestScopedForbidden identifies the fixed client response for a rejected
// request after its permitted account attempts have completed.
func (e *UpstreamFailoverError) IsRequestScopedForbidden() bool {
	return e != nil && (e.Reason == ProviderUnknownForbiddenReason || e.Reason == ProviderContentForbiddenReason)
}
