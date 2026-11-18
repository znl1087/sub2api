package handler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type anthropicCatalogTransport struct {
	service.HTTPUpstream
	calls atomic.Int32
}

func (u *anthropicCatalogTransport) DoWithTLS(req *http.Request, _ string, accountID int64, _ int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	u.calls.Add(1)
	if accountID == 2 {
		return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	}
	if accountID != 1 || req.Method != http.MethodGet ||
		req.URL.Host != "api.anthropic.com" || req.URL.Path != "/v1/models" ||
		req.Header.Get("Authorization") != "Bearer fixture-token" {
		return nil, fmt.Errorf("unexpected Claude catalog request")
	}
	body := `{"data":[{"id":"claude-new","display_name":"Claude New"}],"has_more":true,"last_id":"claude-new"}`
	if req.URL.Query().Get("after_id") == "claude-new" {
		body = `{"data":[{"id":"claude-older","display_name":"Claude Older"}]}`
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func TestGatewayAnthropicPinnedModelsCatalog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	repo := codexModelsFailoverAccountRepo{accounts: []service.Account{
		{ID: 1, Platform: service.PlatformAnthropic, Type: service.AccountTypeOAuth, Status: service.StatusActive, Schedulable: true,
			Credentials: map[string]any{"access_token": "fixture-token", "model_mapping": map[string]any{
				"claude-public": "claude-new", "claude-older": "claude-older",
			}}},
		{ID: 2, Platform: service.PlatformAnthropic, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true,
			Credentials: map[string]any{"api_key": "fixture-key"}},
	}}
	transport := &anthropicCatalogTransport{}
	handler := &GatewayHandler{gatewayService: service.NewGatewayService(
		repo, nil, nil, nil, nil, nil, nil, nil, &config.Config{},
		nil, nil, nil, nil, nil, nil, transport, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	)}
	group := &service.Group{ID: 7, Platform: service.PlatformAnthropic, CodexModelsManifestConfig: service.GroupCodexModelsManifestConfig{
		Enabled: true, AccountIDs: []int64{2, 1},
	}, ModelAllowlist: service.GroupModelAllowlist{Enabled: true, Models: []string{"claude-public"}}}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{Group: group})
	})
	router.GET("/v1/models", func(c *gin.Context) {
		if c.Query("client_version") != "" {
			handler.CodexModels(c)
			return
		}
		handler.Models(c)
	})
	router.GET("/v1/models/:model", handler.Models)
	call := func(path, etag string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("If-None-Match", etag)
		router.ServeHTTP(w, req)
		return w
	}

	list := call("/v1/models", "")
	require.Equal(t, 200, list.Code, list.Body.String())
	require.JSONEq(t, `{"object":"list","data":[{"id":"claude-public","type":"model","display_name":"claude-public","created_at":""}]}`, list.Body.String())
	manifest := call("/v1/models?client_version=0.169.0", "")
	require.Equal(t, 200, manifest.Code, manifest.Body.String())
	require.Contains(t, manifest.Body.String(), `"slug":"claude-public"`)
	require.NotContains(t, manifest.Body.String(), `"slug":"claude-older"`)
	require.NotEmpty(t, list.Header().Get("ETag"))
	require.Equal(t, 304, call("/v1/models", list.Header().Get("ETag")).Code)
	require.Equal(t, 200, call("/v1/models/claude-public", list.Header().Get("ETag")).Code)
	require.Equal(t, int32(6), transport.calls.Load(), "four attempts on the failing account, two cached pages on the successful account")

	group.ModelAllowlist.Models = []string{"claude-missing"}
	require.JSONEq(t, `{"object":"list","data":[]}`, call("/v1/models", "").Body.String())
	require.JSONEq(t, `{"models":[]}`, call("/v1/models?client_version=0.169.0", "").Body.String())

	group.ModelAllowlist.Enabled = false
	group.CodexModelsManifestConfig.AccountIDs = []int64{2}
	require.Equal(t, 503, call("/v1/models", "").Code)
	require.Equal(t, 503, call("/v1/models?client_version=0.169.0", "").Code)
	group.CodexModelsManifestConfig.FallbackToScheduler = true
	require.Equal(t, 200, call("/v1/models", "").Code)
	require.Equal(t, 200, call("/v1/models?client_version=0.169.0", "").Code)
}
