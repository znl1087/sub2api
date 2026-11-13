package admin

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/stretchr/testify/require"
)

func TestIsBindableClaudeVersion(t *testing.T) {
	versions := claude.LibraryVersions()
	require.NotEmpty(t, versions)

	// 库内版本即使低于当前下界（CLICurrentVersion）也必须可绑，
	// 否则历史版本在界面上永远选不回来。
	for _, v := range versions {
		require.True(t, isBindableClaudeVersion(v), "library version %s must be bindable", v)
	}

	require.False(t, isBindableClaudeVersion("2.0.1"), "below baseline must be rejected")
	require.False(t, isBindableClaudeVersion("abc"))
	require.False(t, isBindableClaudeVersion(""))
	// 高于下界的合法 semver 允许，便于绑到尚未入库的新版本。
	require.True(t, isBindableClaudeVersion("2.1.999"))
}
