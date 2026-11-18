package domain

// GroupCodexModelsManifestConfig controls which accounts fetch the Codex
// models catalog for an OpenAI, Anthropic, Kimi or Zhipu group. When enabled,
// discovery uses the accounts selected for the group.
type GroupCodexModelsManifestConfig struct {
	Enabled bool `json:"enabled"`
	// AccountIDs is the ordered list of pinned account IDs. Order decides
	// merge precedence for duplicate model slugs.
	AccountIDs []int64 `json:"account_ids,omitempty"`
	// FallbackToScheduler controls the behavior when no pinned account is
	// usable or all upstream fetches fail: use scheduler-based discovery for
	// OpenAI or the local catalog for other supported platforms when true.
	FallbackToScheduler bool `json:"fallback_to_scheduler,omitempty"`
}
