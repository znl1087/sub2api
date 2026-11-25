package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/stretchr/testify/require"
)

// --- mock ---

type claudeVersionAccountRepoStub struct {
	AccountRepository
	accounts []Account
	updates  map[int64]map[string]any
}

func newClaudeVersionAccountRepoStub(accounts ...Account) *claudeVersionAccountRepoStub {
	return &claudeVersionAccountRepoStub{accounts: accounts, updates: map[int64]map[string]any{}}
}

func (r *claudeVersionAccountRepoStub) ListByPlatform(_ context.Context, platform string) ([]Account, error) {
	out := make([]Account, 0, len(r.accounts))
	for _, a := range r.accounts {
		if a.Platform == platform {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *claudeVersionAccountRepoStub) UpdateExtra(_ context.Context, id int64, extra map[string]any) error {
	merged, ok := r.updates[id]
	if !ok {
		merged = map[string]any{}
		r.updates[id] = merged
	}
	for k, v := range extra {
		merged[k] = v
	}
	return nil
}

func newTestVersionService(t *testing.T, repo *claudeVersionAccountRepoStub) *ClaudeVersionService {
	t.Helper()
	return NewClaudeVersionService(newClaudeCodeVersionSyncSettingRepoStub(nil), repo)
}

// --- parseClaudeVersionHistory ---

func TestParseClaudeVersionHistory(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"not json", "nope", nil},
		{"dedupe and sort", `["2.1.333","2.1.332","2.1.333"]`, []string{"2.1.333", "2.1.332"}},
		{"drop blanks and junk", `["","2.1.333","abc","2.1.333"]`, []string{"2.1.333"}},
		{"drop below baseline", `["1.0.0","2.1.333"]`, []string{"2.1.333"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, parseClaudeVersionHistory(c.raw))
		})
	}
}

// --- pickClaudeVersion ---

func TestPickClaudeVersionIsDeterministic(t *testing.T) {
	versions := []string{"2.1.323", "2.1.322", "2.1.321"}
	first := pickClaudeVersion(42, versions)
	for i := 0; i < 20; i++ {
		require.Equal(t, first, pickClaudeVersion(42, versions), "same account must keep the same version")
	}
}

func TestPickClaudeVersionPrefersNewer(t *testing.T) {
	versions := []string{"2.1.323", "2.1.322", "2.1.321"}
	counts := map[string]int{}
	const n = 3000
	for id := int64(1); id <= n; id++ {
		counts[pickClaudeVersion(id, versions)]++
	}
	// 权重是长尾分布：最新必须最多，最旧必须最少。
	require.Greater(t, counts["2.1.323"], counts["2.1.322"])
	require.Greater(t, counts["2.1.322"], counts["2.1.321"])
	require.NotZero(t, counts["2.1.321"], "oldest version must still be used by someone")
}

func TestPickClaudeVersionSingleVersion(t *testing.T) {
	require.Equal(t, "2.1.323", pickClaudeVersion(7, []string{"2.1.323"}))
	require.Equal(t, "", pickClaudeVersion(7, nil))
}

// --- Versions / VersionForAccount ---

func TestVersionsIncludesLibrary(t *testing.T) {
	svc := newTestVersionService(t, newClaudeVersionAccountRepoStub())
	versions := svc.Versions(context.Background())
	require.NotEmpty(t, versions, "compiled-in library must always yield at least one version")
	require.Equal(t, claude.LibraryVersions(), versions[:len(claude.LibraryVersions())])
}

func TestVersionsMergesRuntimeHistory(t *testing.T) {
	repo := newClaudeCodeVersionSyncSettingRepoStub(map[string]string{
		SettingKeyClaudeCodeVersionHistory: `["2.1.400"]`,
	})
	svc := NewClaudeVersionService(repo, newClaudeVersionAccountRepoStub())
	versions := svc.Versions(context.Background())
	require.Equal(t, "2.1.400", versions[0], "runtime version newer than library must lead")
}

func TestVersionForAccountUsesBinding(t *testing.T) {
	latest := claude.LibraryVersions()[0]
	account := &Account{ID: 1, Platform: PlatformAnthropic}
	account.Extra = map[string]any{AccountExtraCLIVersion: latest}

	svc := newTestVersionService(t, newClaudeVersionAccountRepoStub())
	got := svc.VersionForAccount(context.Background(), account)
	require.Equal(t, latest, got.Version)
	require.NotEmpty(t, got.UserAgent())
}

func TestVersionForAccountFallsBackWhenBindingStale(t *testing.T) {
	account := &Account{ID: 2, Platform: PlatformAnthropic}
	account.Extra = map[string]any{AccountExtraCLIVersion: "9.9.9"}

	svc := newTestVersionService(t, newClaudeVersionAccountRepoStub())
	got := svc.VersionForAccount(context.Background(), account)
	require.NotEqual(t, "9.9.9", got.Version)
	require.Contains(t, claude.LibraryVersions(), got.Version)
}

// --- maintain ---

func TestMaintainBindsUnboundAccount(t *testing.T) {
	account := Account{ID: 10, Platform: PlatformAnthropic, Type: AccountTypeOAuth, Status: StatusActive}
	repo := newClaudeVersionAccountRepoStub(account)
	svc := newTestVersionService(t, repo)

	svc.maintain()

	update, ok := repo.updates[10]
	require.True(t, ok, "unbound account must be bound")
	require.Contains(t, claude.LibraryVersions(), update[AccountExtraCLIVersion])
	require.NotEmpty(t, update[AccountExtraCLIVersionNextAt], "binding must schedule the first upgrade")
}

func TestMaintainSkipsNonAnthropicAccount(t *testing.T) {
	repo := newClaudeVersionAccountRepoStub(
		Account{ID: 11, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive},
	)
	svc := newTestVersionService(t, repo)
	svc.maintain()
	require.Empty(t, repo.updates)
}

func TestMaintainRebindsEvictedVersion(t *testing.T) {
	// 失效版本重绑走的是加权分配，不一定是"最新"，只要落在库内即可。
	account := Account{ID: 12, Platform: PlatformAnthropic, Type: AccountTypeOAuth, Status: StatusActive}
	account.Extra = map[string]any{AccountExtraCLIVersion: "9.9.9"}

	repo := newClaudeVersionAccountRepoStub(account)
	svc := newTestVersionService(t, repo)
	svc.maintain()

	got := repo.updates[12][AccountExtraCLIVersion]
	require.NotEqual(t, "9.9.9", got, "evicted version must be rebound")
	require.Contains(t, claude.LibraryVersions(), got)
}

func TestMaintainUpgradesOnlyOneStep(t *testing.T) {
	versions := claude.LibraryVersions()
	require.NotEmpty(t, versions)
	// 库只有一个版本时无升级可做，这里断言"已在最新 → 只补 next_at"。
	latest := versions[0]
	account := Account{ID: 13, Platform: PlatformAnthropic, Type: AccountTypeOAuth, Status: StatusActive}
	account.Extra = map[string]any{AccountExtraCLIVersion: latest}

	repo := newClaudeVersionAccountRepoStub(account)
	svc := newTestVersionService(t, repo)
	svc.maintain()

	update := repo.updates[13]
	require.NotContains(t, update, AccountExtraCLIVersion, "already-latest account must not be rewritten")
	require.NotEmpty(t, update[AccountExtraCLIVersionNextAt])
}

// TestMaintainSchedulesWithoutUpgradingWhenNextAtMissing 覆盖手工改绑后的语义：
// 绑定值有效但没有排期时，先排下一次而不是当成已到期立刻升一档，
// 否则刚钉住的版本下一轮就被挪走，等于白绑。
func TestMaintainSchedulesWithoutUpgradingWhenNextAtMissing(t *testing.T) {
	versions := claude.LibraryVersions()
	require.GreaterOrEqual(t, len(versions), 2)
	pinned := versions[1] // 非最新，有升级空间

	account := Account{ID: 21, Platform: PlatformAnthropic, Type: AccountTypeOAuth, Status: StatusActive}
	account.Extra = map[string]any{AccountExtraCLIVersion: pinned}

	repo := newClaudeVersionAccountRepoStub(account)
	svc := newTestVersionService(t, repo)
	svc.maintain()

	update := repo.updates[21]
	require.NotContains(t, update, AccountExtraCLIVersion, "missing schedule must not upgrade in the same run")
	require.NotEmpty(t, update[AccountExtraCLIVersionNextAt])
}

// --- NoteVersion ---
func TestNoteVersionAppendsAndPersists(t *testing.T) {
	settingRepo := newClaudeCodeVersionSyncSettingRepoStub(nil)
	svc := NewClaudeVersionService(settingRepo, newClaudeVersionAccountRepoStub())

	svc.NoteVersion(context.Background(), "2.1.500")

	raw, err := settingRepo.GetValue(context.Background(), SettingKeyClaudeCodeVersionHistory)
	require.NoError(t, err)
	var stored []string
	require.NoError(t, json.Unmarshal([]byte(raw), &stored))
	require.Equal(t, []string{"2.1.500"}, stored)
	require.Equal(t, "2.1.500", svc.Versions(context.Background())[0])
}

func TestNoteVersionIgnoresInvalidAndDuplicates(t *testing.T) {
	settingRepo := newClaudeCodeVersionSyncSettingRepoStub(nil)
	svc := NewClaudeVersionService(settingRepo, newClaudeVersionAccountRepoStub())

	svc.NoteVersion(context.Background(), "garbage")
	_, err := settingRepo.GetValue(context.Background(), SettingKeyClaudeCodeVersionHistory)
	require.ErrorIs(t, err, ErrSettingNotFound)

	// 特征库已收录的版本不必进运行期补充列表。
	svc.NoteVersion(context.Background(), claude.LibraryVersions()[0])
	_, err = settingRepo.GetValue(context.Background(), SettingKeyClaudeCodeVersionHistory)
	require.ErrorIs(t, err, ErrSettingNotFound)
}
