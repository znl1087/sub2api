package handler

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/xai"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// GroupModelCatalogIDs resolves the public catalog before request routing can
// rewrite the client model. Discovery does not use the request's cache validators.
func (h *GatewayHandler) GroupModelCatalogIDs(c *gin.Context, group *service.Group) ([]string, error) {
	ctx := c.Request.Context()
	platform := publicModelCatalogPlatform(c, group)
	path := c.FullPath()
	switch {
	case strings.HasPrefix(path, "/v1beta/"), strings.HasPrefix(path, "/antigravity/v1beta/"):
		if platform == service.PlatformComposite {
			ids, _ := h.localPublicModelIDs(ctx, group, platform)
			return ids, nil
		}
		return h.nativeGeminiCatalogIDs(c)
	case platform == service.PlatformAntigravity && strings.HasPrefix(path, "/antigravity/v1/"):
		return defaultModelIDsForPlatform(platform), nil
	case platform == service.PlatformGrok && (path == "/v1/realtime" || path == "/realtime"):
		return []string{xai.DefaultVoiceModel}, nil
	}

	if usesPinnedOpenAIModelCatalog(group, platform) {
		if h.openAIGatewayService == nil {
			return nil, errors.New("OpenAI model discovery is not configured")
		}
		return h.pinnedOpenAICatalogIDs(c, group)
	}
	if group.UsesPinnedProviderModelsCatalog(platform) {
		_, ids, err := h.fetchPinnedProviderModels(ctx, group, "")
		if err == nil || !group.CodexModelsManifestConfig.FallbackToScheduler || ctx.Err() != nil {
			return ids, err
		}
	}
	ids, _ := h.localPublicModelIDs(ctx, group, platform)
	return ids, nil
}

func (h *GatewayHandler) pinnedOpenAICatalogIDs(c *gin.Context, group *service.Group) ([]string, error) {
	ctx := c.Request.Context()
	path := c.FullPath()
	isCodex := strings.Contains(path, "/responses") && (strings.HasPrefix(path, "/backend-api/codex/") ||
		openai.IsCodexOfficialClientByHeaders(c.GetHeader("User-Agent"), c.GetHeader("originator")))
	if isCodex {
		manifest, _, err := h.openAIGatewayService.FetchPinnedCodexModelsManifest(ctx, group, "")
		if err == nil {
			err = h.openAIGatewayService.MergeGroupConfiguredCodexModels(ctx, group, manifest, "")
		}
		if err == nil {
			return openAIAdmissionCatalogIDs(manifest.Body)
		}
		if !group.CodexModelsManifestConfig.FallbackToScheduler || ctx.Err() != nil {
			return nil, err
		}
	}
	response, _, err := h.openAIGatewayService.FetchPinnedOpenAIModelsList(ctx, group, h.maxAccountSwitches, "")
	if err != nil {
		return nil, err
	}
	return openAIAdmissionCatalogIDs(response.Body)
}

func openAIAdmissionCatalogIDs(body []byte) ([]string, error) {
	var catalog struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			Slug string `json:"slug"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(catalog.Data)+len(catalog.Models))
	for _, model := range catalog.Data {
		ids = append(ids, model.ID)
	}
	for _, model := range catalog.Models {
		ids = append(ids, model.Slug)
	}
	return ids, nil
}
