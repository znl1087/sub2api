package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

// FetchPinnedAnthropicModelsList returns both the public list and its IDs for
// the Codex picker. The endpoints share the cached upstream responses.
func (s *GatewayService) FetchPinnedAnthropicModelsList(ctx context.Context, group *Group, ifNoneMatch string) (*OpenAIModelsResponse, []string, error) {
	if s == nil || group == nil || group.Platform != PlatformAnthropic {
		return nil, nil, ErrNoPinnedCodexModelsAccounts
	}
	results, err := fetchPinnedModels(ctx, s.accountRepo, group, func(ctx context.Context, account *Account) (*OpenAIModelsResponse, error) {
		response, err := s.fetchAnthropicModelsList(ctx, account)
		if err != nil {
			return nil, err
		}
		response.Body, err = projectAccountModelAliases(response.Body, account, group, false)
		return response, err
	})
	if err != nil {
		return nil, nil, err
	}
	return mergePinnedModelsLists(results, group, ifNoneMatch)
}

func (s *GatewayService) fetchAnthropicModelsList(ctx context.Context, account *Account) (*OpenAIModelsResponse, error) {
	if s.httpUpstream == nil {
		return nil, errors.New("Anthropic model catalog HTTP client is not configured")
	}
	req, err := buildAnthropicUpstreamModelsRequest(ctx, account, s.claudeTokenProvider, s.cfg)
	if err != nil {
		return nil, err
	}
	proxyURL := upstreamModelsProxyURL(account)
	cacheKey := buildOpenAIModelsCacheKey(openAIModelsRequest{
		url: req.URL.String(), headers: req.Header, proxyURL: proxyURL,
		accountID: account.ID, credentialAccountID: account.ID, standardModelsList: true,
	})
	return s.anthropicModelsCache.fetch(ctx, cacheKey, func(ctx context.Context, etag string) (*OpenAIModelsResponse, error) {
		return s.fetchAnthropicModelPages(req.Clone(ctx), account, proxyURL, etag)
	}, "")
}

func (s *GatewayService) fetchAnthropicModelPages(req *http.Request, account *Account, proxyURL, etag string) (*OpenAIModelsResponse, error) {
	const maxPages = 20
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	var profile *tlsfingerprint.Profile
	if s.tlsFPProfileService != nil {
		profile = s.tlsFPProfileService.ResolveTLSProfile(account)
	}
	var models []claude.Model
	seen := make(map[string]struct{})
	cursors := make(map[string]struct{})
	for page := 0; page < maxPages; page++ {
		resp, requestErr := s.httpUpstream.DoWithTLS(req, proxyURL, account.ID, account.Concurrency, profile)
		if requestErr == nil && page == 0 && etag != "" && resp.StatusCode == http.StatusNotModified {
			_ = resp.Body.Close()
			return &OpenAIModelsResponse{NotModified: true}, nil
		}
		body, err := readUpstreamModelsBody(resp, requestErr, resolveModelsListReadLimit(s.cfg))
		if err != nil {
			return nil, err
		}
		var listing struct {
			Data    []claude.Model `json:"data"`
			HasMore bool           `json:"has_more"`
			LastID  string         `json:"last_id"`
		}
		if err := json.Unmarshal(body, &listing); err != nil || listing.Data == nil {
			return nil, errors.New("invalid Anthropic model catalog")
		}
		for _, model := range listing.Data {
			model.ID = strings.TrimSpace(model.ID)
			if model.ID == "" || strings.Contains(model.ID, "*") {
				continue
			}
			if _, exists := seen[model.ID]; exists {
				continue
			}
			seen[model.ID] = struct{}{}
			model.Type = "model"
			if model.DisplayName == "" {
				model.DisplayName = model.ID
			}
			models = append(models, model)
		}
		if !listing.HasMore {
			if len(models) == 0 {
				return nil, errors.New("Anthropic model catalog is empty")
			}
			merged, err := json.Marshal(struct {
				Data []claude.Model `json:"data"`
			}{Data: models})
			if err != nil {
				return nil, err
			}
			response := &OpenAIModelsResponse{Body: merged}
			if page == 0 {
				response.upstreamETag = resp.Header.Get("ETag")
			}
			return response, nil
		}
		cursor := strings.TrimSpace(listing.LastID)
		if _, exists := cursors[cursor]; cursor == "" || exists {
			return nil, errors.New("invalid Anthropic model catalog cursor")
		}
		cursors[cursor] = struct{}{}
		query := req.URL.Query()
		query.Set("after_id", cursor)
		req.URL.RawQuery = query.Encode()
		req.Header.Del("If-None-Match")
	}
	return nil, errors.New("Anthropic model catalog exceeded page limit")
}

func (s *GatewayService) ExpandAnthropicLongContextModels(ctx context.Context, group *Group, models []string) []string {
	if s == nil || s.accountRepo == nil || len(models) == 0 {
		return models
	}
	var accounts []Account
	var err error
	if group != nil {
		accounts, err = s.accountRepo.ListSchedulableByGroupID(ctx, group.ID)
	} else {
		accounts, err = s.accountRepo.ListSchedulable(ctx)
	}
	if err != nil {
		return models
	}
	result := cloneStringSlice(models)
	seen := make(map[string]bool, len(models))
	for _, model := range models {
		seen[strings.ToLower(model)] = true
	}
	for _, model := range models {
		if strings.HasSuffix(strings.ToLower(model), claudeCodeLongContextModelSuffix) || strings.Contains(model, "*") {
			continue
		}
		var routedAccountIDs []int64
		if group != nil {
			routedAccountIDs = group.GetRoutingAccountIDs(model)
		}
		for _, account := range accounts {
			if !account.IsAnthropic() || !account.IsModelSupported(model) ||
				(len(routedAccountIDs) > 0 && !slices.Contains(routedAccountIDs, account.ID)) {
				continue
			}
			metadata, ok := account.GetUpstreamModelMetadata(account.GetMappedModel(model))
			variant := model + claudeCodeLongContextModelSuffix
			if ok && metadata.ContextWindow >= 900_000 && !seen[strings.ToLower(variant)] {
				result = append(result, variant)
				seen[strings.ToLower(variant)] = true
			}
		}
	}
	return result
}
