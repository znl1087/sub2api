//go:build unit

package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestProviderForbiddenClientResponse(t *testing.T) {
	claude := &GatewayHandler{}
	openai := &OpenAIGatewayHandler{}
	for name, handle := range map[string]func(*gin.Context, *service.UpstreamFailoverError){
		"claude": func(c *gin.Context, failure *service.UpstreamFailoverError) {
			claude.handleFailoverExhausted(c, failure, service.PlatformAnthropic, false)
		},
		"claude chat completions": func(c *gin.Context, failure *service.UpstreamFailoverError) {
			claude.handleCCFailoverExhausted(c, failure, false)
		},
		"claude responses": func(c *gin.Context, failure *service.UpstreamFailoverError) {
			claude.handleResponsesFailoverExhausted(c, failure, false)
		},
		"openai": func(c *gin.Context, failure *service.UpstreamFailoverError) {
			openai.handleFailoverExhausted(c, failure, false)
		},
		"openai messages": func(c *gin.Context, failure *service.UpstreamFailoverError) {
			openai.handleAnthropicFailoverExhausted(c, failure, false)
		},
	} {
		for _, test := range []struct {
			reason service.GatewayFailureReason
			status int
		}{
			{service.ProviderUnknownForbiddenReason, 502},
			{service.ProviderContentForbiddenReason, 403},
		} {
			t.Run(name+"/"+string(test.reason), func(t *testing.T) {
				writer := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(writer)
				c.Request = httptest.NewRequest("POST", "/v1/messages", nil)
				handle(c, &service.UpstreamFailoverError{StatusCode: 403, Reason: test.reason, ClientStatusCode: test.status, ClientMessage: "Rejected request"})
				require.Equal(t, test.status, writer.Code)
				require.Contains(t, writer.Body.String(), "Rejected request")
			})
		}
	}
}
