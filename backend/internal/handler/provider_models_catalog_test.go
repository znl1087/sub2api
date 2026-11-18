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
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type providerModelsCatalogTransport struct {
	service.HTTPUpstream
	endpoint string
	body     string
	calls    atomic.Int32
}

func (u *providerModelsCatalogTransport) Do(req *http.Request, _ string, accountID int64, _ int) (*http.Response, error) {
	u.calls.Add(1)
	if accountID != 1 || req.Method != http.MethodGet || req.URL.String() != u.endpoint ||
		req.Header.Get("Authorization") != "Bearer fixture-key" {
		return nil, fmt.Errorf("unexpected provider model discovery request")
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(u.body))}, nil
}

func TestGatewayPinnedAPIKeyProviderModelsCatalog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		platform, protocol, baseURL, endpoint, model, newModel string
	}{
		{service.PlatformKimi, "adaptive", "https://api.kimi.com/coding/v1", "https://api.kimi.com/coding/v1/models", "k3.1-pro", "k3.1-pro-highspeed"},
		{service.PlatformZhipu, "anthropic", "https://open.bigmodel.cn/api/anthropic", "https://open.bigmodel.cn/api/coding/paas/v4/models", "glm-5.3", "glm-5.3-flashx"},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			repo := codexModelsFailoverAccountRepo{accounts: []service.Account{
				{ID: 1, Platform: tc.platform, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true,
					Credentials: map[string]any{"api_key": "fixture-key", "base_url": tc.baseURL, "api_protocol": tc.protocol,
						"account_mode": "coding", "model_mapping": map[string]any{
							tc.model: tc.model, "my-model": tc.model, "stale": "unavailable",
						}}},
				{ID: 2, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true},
			}}
			transport := &providerModelsCatalogTransport{
				endpoint: tc.endpoint,
				body:     fmt.Sprintf(`{"data":[{"id":%q},{"id":%q}]}`, tc.model, tc.newModel),
			}
			h := newGatewayModelsHandlerForTest(repo)
			h.openAIGatewayService = service.NewOpenAIGatewayService(repo,
				nil, nil, nil, nil, nil, nil, &config.Config{}, nil, nil, nil, nil, nil,
				transport, nil, nil, nil, nil, nil, nil, nil, nil)

			group := &service.Group{ID: 7, Platform: tc.platform, CodexModelsManifestConfig: service.GroupCodexModelsManifestConfig{
				Enabled: true, AccountIDs: []int64{1, 2},
			}}
			call := func(path string, handler gin.HandlerFunc, etag string) *httptest.ResponseRecorder {
				router := gin.New()
				router.GET(path, func(c *gin.Context) {
					c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{Group: group})
					handler(c)
				})
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
				if strings.HasSuffix(path, "/:model") {
					req = httptest.NewRequest(http.MethodGet, "/v1/models/my-model", nil)
				}
				req.Header.Set("If-None-Match", etag)
				router.ServeHTTP(w, req)
				return w
			}
			list := call("/v1/models", h.Models, "")
			require.Equal(t, http.StatusOK, list.Code, list.Body.String())
			require.Contains(t, list.Body.String(), fmt.Sprintf(`"id":%q`, tc.model))
			require.Contains(t, list.Body.String(), `"id":"my-model"`)
			require.NotContains(t, list.Body.String(), tc.newModel)
			require.NotContains(t, list.Body.String(), "stale")
			require.NotEmpty(t, list.Header().Get("ETag"))
			require.Equal(t, http.StatusNotModified, call("/v1/models", h.Models, list.Header().Get("ETag")).Code)

			item := call("/v1/models/:model", h.Models, list.Header().Get("ETag"))
			require.Equal(t, http.StatusOK, item.Code)
			require.Contains(t, item.Body.String(), `"type":"model"`)
			manifest := call("/v1/models", h.CodexModels, "")
			require.Equal(t, http.StatusOK, manifest.Code, manifest.Body.String())
			require.Contains(t, manifest.Body.String(), `"slug":"my-model"`)
			require.NotContains(t, manifest.Body.String(), tc.newModel)
			require.EqualValues(t, 1, transport.calls.Load())

			group.ModelAllowlist = service.GroupModelAllowlist{Enabled: true, Models: []string{"my-model"}}
			allowed := call("/v1/models", h.Models, "")
			require.Equal(t, http.StatusOK, allowed.Code)
			require.NotContains(t, allowed.Body.String(), fmt.Sprintf(`"id":%q`, tc.model))
			require.Contains(t, allowed.Body.String(), `"id":"my-model"`)

			group.CodexModelsManifestConfig.AccountIDs = []int64{2}
			require.Equal(t, http.StatusServiceUnavailable, call("/v1/models", h.Models, "").Code)
			require.Equal(t, http.StatusServiceUnavailable, call("/v1/models", h.CodexModels, "").Code)
			group.CodexModelsManifestConfig.FallbackToScheduler = true
			require.Equal(t, http.StatusOK, call("/v1/models", h.Models, "").Code)
			require.Equal(t, http.StatusOK, call("/v1/models", h.CodexModels, "").Code)
		})
	}
}
