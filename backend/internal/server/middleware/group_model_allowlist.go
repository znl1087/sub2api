package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/pkg/httputil"
	"github.com/Wei-Shaw/sub2api/internal/pkg/requestmodel"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// GroupModelCatalogResolver supplies the public IDs for the authenticated group
// and endpoint. An empty catalog is authoritative.
type GroupModelCatalogResolver func(c *gin.Context, group *service.Group) ([]string, error)

const groupModelCatalogResolverKey = "group_model_catalog_resolver"

// GroupModelAllowlist checks client-facing model IDs after authentication and
// before route rewriting or scheduling. Responses WebSocket checks its frames
// in the handler using the same resolver.
func GroupModelAllowlist(resolvers ...GroupModelCatalogResolver) gin.HandlerFunc {
	var resolver GroupModelCatalogResolver
	if len(resolvers) > 0 {
		resolver = resolvers[0]
	}
	return func(c *gin.Context) {
		apiKey, ok := GetAPIKeyFromContext(c)
		if !ok || apiKey == nil || apiKey.Group == nil || c.Request == nil {
			c.Next()
			return
		}
		allowlist := apiKey.Group.ModelAllowlist
		if resolver != nil && usesGroupModelCatalog(c) {
			c.Set(groupModelCatalogResolverKey, resolver)
		} else if !allowlist.Enabled {
			c.Next()
			return
		}

		if isResponsesWebSocketRoute(c) {
			// Responses WS 长连接由 ResponsesWebSocket 校验首帧与每个 response.create。
			c.Next()
			return
		}
		// models 收集该请求全部可被下游解析器绑定到的模型值（路径参数/查询参数
		// 单值；请求体候选集含重复键与大小写变体），逐一校验，任一未命中即拒绝。
		var models []string
		if model := groupModelAllowlistModelFromParams(c); model != "" {
			models = []string{model}
		} else {
			switch c.Request.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch:
				candidates, done := groupModelAllowlistModelsFromBody(c)
				if !done {
					// 请求体读取失败（如超限 413）已写出响应。
					return
				}
				models = candidates
			}
			if len(models) == 0 {
				// Grok Realtime 升级请求把模型固定在查询参数里。
				if model := strings.TrimSpace(c.Query("model")); model != "" {
					models = []string{model}
				}
			}
		}

		blocked := ""
		for _, candidate := range models {
			if !allowlist.Allows(candidate) {
				blocked = candidate
				break
			}
		}
		if blocked == "" {
			var err error
			blocked, err = CheckGroupModelCatalog(c, models)
			if err != nil {
				writeGroupModelCatalogUnavailable(c)
				c.Abort()
				return
			}
		}
		if blocked == "" {
			c.Next()
			return
		}

		service.MarkOpsClientBusinessLimited(c, service.OpsClientBusinessLimitedReasonLocalModelConfiguration)
		MarkIngressRejected(c, IngressRejectModelNotAllowed)
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), ctxkey.Model, blocked))
		groupModelAllowlistErrorWriter(c)(c, http.StatusNotFound, fmt.Sprintf("Model %q is not available for this group", blocked))
		c.Abort()
	}
}

func usesGroupModelCatalog(c *gin.Context) bool {
	switch c.Request.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	case http.MethodGet:
		return isResponsesWebSocketRoute(c) || c.FullPath() == "/v1/realtime" || c.FullPath() == "/realtime"
	}
	return false
}

// CheckGroupModelCatalog checks all possible wire model values against one
// catalog snapshot. It also serves WebSocket frames after the HTTP upgrade.
func CheckGroupModelCatalog(c *gin.Context, candidates []string) (string, error) {
	if len(candidates) == 0 {
		return "", nil
	}
	value, _ := c.Get(groupModelCatalogResolverKey)
	resolver, ok := value.(GroupModelCatalogResolver)
	if !ok || resolver == nil {
		return "", nil
	}
	apiKey, _ := GetAPIKeyFromContext(c)
	if apiKey == nil || apiKey.Group == nil {
		return "", nil
	}
	ids, err := resolver(c, apiKey.Group)
	if err != nil {
		return "", err
	}
	path := c.FullPath()
	for _, candidate := range candidates {
		if !service.PublicModelCatalogAllows(ids, candidate, apiKey.Group.Platform, strings.Contains(path, "/messages")) {
			return candidate, nil
		}
	}
	return "", nil
}

func writeGroupModelCatalogUnavailable(c *gin.Context) {
	const message = "Model catalog is temporarily unavailable"
	path := c.FullPath()
	switch {
	case strings.HasPrefix(path, "/v1beta") || strings.HasPrefix(path, "/antigravity/v1beta"):
		GoogleErrorWriter(c, http.StatusServiceUnavailable, message)
	case strings.Contains(path, "/messages"):
		AnthropicErrorWriter(c, http.StatusServiceUnavailable, message)
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": gin.H{
			"type": "api_error", "code": "model_catalog_unavailable", "message": message,
		}})
	}
}

// isResponsesWebSocketRoute 判断当前请求是否命中 OpenAI Responses WebSocket
// 入口。只有这三条路由的模型在升级后的帧里，交给 handler 逐帧校验；其他路由
// 即使携带 WebSocket Upgrade 头也必须经过本中间件校验。
func isResponsesWebSocketRoute(c *gin.Context) bool {
	if c.Request == nil || c.Request.Method != http.MethodGet {
		return false
	}
	switch c.FullPath() {
	case "/v1/responses", "/responses", "/backend-api/codex/responses":
		return true
	}
	return false
}

// groupModelAllowlistModelsFromBody 读取请求体并提取客户端模型名，随后把请求体
// 回填（PrereadBody），保证后续 handler 零拷贝重读。读取失败按现有合成中间件
// 的方式返回 400/413（返回 false 表示已写出响应并 Abort）。
//
// 下游同时存在 gjson（首个、大小写敏感）、encoding/json 绑定（末值、大小写
// 不敏感）与 multipart 表单（首/末字段）三类解析器，这里返回「任一解析器可能
// 绑定到的全部模型值」，调用方必须逐一校验，任一未命中即拒绝。
func groupModelAllowlistModelsFromBody(c *gin.Context) ([]string, bool) {
	body, err := httputil.ReadRequestBodyWithPrealloc(c.Request)
	if err != nil {
		if RejectRequestBodyReadError(c, "middleware.group_model_allowlist", err) {
			return nil, false
		}
		AbortWithRequestBodyReadFailure(c, "middleware.group_model_allowlist", err)
		return nil, false
	}
	requestmodel.ResetRequestBody(c.Request, body)
	return requestmodel.FromBodyCandidates(c.FullPath(), c.GetHeader("Content-Type"), body), true
}

// groupModelAllowlistModelFromParams 从路由参数提取模型名：Gemini 原生 URL 的
// `model` / `modelAction`（去掉 `:action` 后缀）。提取不到返回空串，
// 由调用方决定是否继续读请求体或查询参数。
func groupModelAllowlistModelFromParams(c *gin.Context) string {
	if model := strings.TrimSpace(c.Param("model")); model != "" {
		return model
	}
	if modelAction := strings.TrimSpace(c.Param("modelAction")); modelAction != "" {
		modelAction = strings.TrimPrefix(modelAction, "/")
		if idx := strings.Index(modelAction, ":"); idx > 0 {
			return strings.TrimSpace(modelAction[:idx])
		}
		if idx := strings.Index(modelAction, "/"); idx > 0 {
			return strings.TrimSpace(modelAction[:idx])
		}
		return modelAction
	}
	return ""
}

// groupModelAllowlistErrorWriter 按入口协议选择错误格式：
// Gemini 原生（/v1beta、/antigravity/v1beta）用 Google 格式；
// Messages 入口（含根路径别名与 /antigravity/v1）用 Anthropic 格式；
// 其余（OpenAI 兼容入口）用 OpenAI 格式。
func groupModelAllowlistErrorWriter(c *gin.Context) GatewayErrorWriter {
	path := ""
	if c.Request != nil && c.Request.URL != nil {
		path = c.Request.URL.Path
	}
	switch {
	case strings.HasPrefix(path, "/v1beta") || strings.HasPrefix(path, "/antigravity/v1beta"):
		return GoogleErrorWriter
	case strings.Contains(path, "/messages"):
		return AnthropicErrorWriter
	default:
		return OpenAIErrorWriter
	}
}
