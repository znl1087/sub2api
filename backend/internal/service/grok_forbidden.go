package service

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/util/logredact"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const (
	GrokUnknownForbiddenReason        GatewayFailureReason = "grok_unknown_forbidden"
	GrokModelAccessDeniedReason       GatewayFailureReason = "grok_model_access_denied"
	grokForbiddenAccountsKey                               = "grok_unknown_forbidden_accounts"
	grokForbiddenMaxAccounts                               = 2
	GrokUnknownForbiddenClientMessage                      = "Grok rejected this request (403)"
)

// grokModelAccessDenied requires explicit model permission evidence. A bare
// permission-denied code does not establish either account or model health.
func grokModelAccessDenied(body []byte) bool {
	code := strings.ToLower(firstNonEmpty(gjson.GetBytes(body, "error.code").String(), gjson.GetBytes(body, "code").String()))
	switch normalizeGrokErrorMarker(code) {
	case "model_access_denied", "model_not_allowed", "model_not_entitled":
		return true
	}
	for _, message := range grokStructuredErrorMessageCandidates(body) {
		low := strings.ToLower(message)
		for _, phrase := range []string{"access to model", "access to the model", "permission to use model", "permission to use the model", "model is not available for your", "model is not available to your"} {
			if strings.Contains(low, phrase) && (strings.Contains(low, "denied") || strings.Contains(low, "not have") || strings.Contains(low, "not available")) {
				return true
			}
		}
	}
	return false
}

func grokForbiddenIsAccountScoped(body []byte) bool {
	if grokModelAccessDenied(body) {
		return false
	}
	decision := classifyGrokUpstreamFailure(http.StatusForbidden, body, "")
	if decision.Class == GrokFailureFreeUsage || decision.Class == GrokFailureBilling {
		return true
	}
	var payload any
	if json.Unmarshal(body, &payload) == nil && grokStructuredAccountAccessMarker(payload) {
		return true
	}
	for _, message := range grokStructuredErrorMessageCandidates(body) {
		if grokAccountAccessMessage(message) {
			return true
		}
	}
	return false
}

func isGrokUnknownForbidden(status int, body []byte) bool {
	return status == http.StatusForbidden && !isGrokContentPolicyRejection(status, body) &&
		!grokModelAccessDenied(body) && !grokForbiddenIsAccountScoped(body)
}

// decorateGrokForbiddenFailover uses the Gin request's state so the budget is
// shared by every account attempt, including protocol and image bridges. It
// never installs cross-request account state or counts same-account replays.
func decorateGrokForbiddenFailover(c *gin.Context, account *Account, failure *UpstreamFailoverError) *UpstreamFailoverError {
	if account == nil || !account.IsGrok() || failure == nil || failure.StatusCode != http.StatusForbidden {
		return failure
	}
	if grokModelAccessDenied(failure.ResponseBody) {
		failure.Scope = GatewayFailureScopeRequest
		failure.Reason = GrokModelAccessDeniedReason
		failure.RetryableOnSameAccount = false
		return failure
	}
	if !isGrokUnknownForbidden(failure.StatusCode, failure.ResponseBody) {
		return failure
	}
	failure.Scope = GatewayFailureScopeRequest
	failure.Reason = GrokUnknownForbiddenReason
	failure.RequestScopedTransient = true
	failure.RetryableOnSameAccount = false
	failure.ClientStatusCode = http.StatusBadGateway
	failure.ClientMessage = GrokUnknownForbiddenClientMessage
	if c == nil {
		failure.NextAccountAction = NextAccountStop
		return failure
	}
	accounts := make(map[int64]struct{})
	if value, exists := c.Get(grokForbiddenAccountsKey); exists {
		accounts, _ = value.(map[int64]struct{})
	}
	if accounts == nil {
		accounts = make(map[int64]struct{})
	}
	accounts[account.ID] = struct{}{}
	c.Set(grokForbiddenAccountsKey, accounts)
	if len(accounts) >= grokForbiddenMaxAccounts {
		failure.NextAccountAction = NextAccountStop
	}
	return failure
}

// NewGrokUpstreamFailoverError preserves Grok retry metadata and applies the
// request-local forbidden budget to HTTP and pre-accept WebSocket failures.
func NewGrokUpstreamFailoverError(c *gin.Context, account *Account, status int, headers http.Header, body []byte) *UpstreamFailoverError {
	retryable, delay, deadline, maximum := grokSameAccountRetryMetadata(account, status, body)
	failure := decorateGrokForbiddenFailover(c, account, &UpstreamFailoverError{
		StatusCode:               status,
		ResponseBody:             body,
		ResponseHeaders:          headers.Clone(),
		RetryableOnSameAccount:   retryable,
		RequestScopedTransient:   retryable && status == http.StatusTooManyRequests,
		SameAccountRetryDelay:    delay,
		SameAccountRetryDeadline: deadline,
		SameAccountRetryMax:      maximum,
	})
	if isGrokContentPolicyRejection(status, body) {
		failure.NextAccountAction = NextAccountStop
		failure.RetryableOnSameAccount = false
	}
	return failure
}

// appendGrokUpstreamError captures a bounded diagnostic body using the existing
// operator setting. Redaction happens before truncation to preserve token matches.
func (s *OpenAIGatewayService) appendGrokUpstreamError(c *gin.Context, response *http.Response, body []byte, event OpsUpstreamErrorEvent) {
	if s != nil && s.cfg != nil && s.cfg.Gateway.LogUpstreamErrorBody {
		maximum := s.cfg.Gateway.LogUpstreamErrorBodyMaxBytes
		if maximum <= 0 {
			maximum = 2048
		}
		detail := logredact.RedactText(string(body))
		var decoded any
		if json.Unmarshal(body, &decoded) == nil {
			if encoded, err := json.Marshal(redactGrokDiagnosticValue(decoded, 0)); err == nil {
				detail = string(encoded)
			}
		}
		event.Detail = truncateString(detail, maximum)
	}
	if message := firstNonEmpty(grokStructuredErrorMessageCandidates(body)...); message != "" {
		event.Message = truncateString(sanitizeUpstreamErrorMessage(logredact.RedactText(message, "authorization", "api_key", "cookie")), 2048)
	}
	if response != nil && response.Request != nil && response.Request.URL != nil {
		upstreamURL := *response.Request.URL
		upstreamURL.User = nil
		upstreamURL.RawQuery = ""
		upstreamURL.Fragment = ""
		event.UpstreamURL = upstreamURL.String()
	}
	if isGrokUnknownForbidden(event.UpstreamStatusCode, body) {
		event.Scope = string(GatewayFailureScopeRequest)
		event.Reason = string(GrokUnknownForbiddenReason)
	}
	appendOpsUpstreamError(c, event)
}

func redactGrokDiagnosticValue(value any, depth int) any {
	if depth > 16 {
		return "[truncated]"
	}
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			if isSensitiveKey(key) {
				node[key] = "[REDACTED]"
			} else {
				node[key] = redactGrokDiagnosticValue(child, depth+1)
			}
		}
	case []any:
		for index, child := range node {
			node[index] = redactGrokDiagnosticValue(child, depth+1)
		}
	case string:
		return logredact.RedactText(node, "authorization", "api_key", "cookie")
	}
	return value
}
