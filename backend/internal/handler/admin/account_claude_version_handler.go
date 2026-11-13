package admin

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// 账号绑定的客户端版本走 extra.cli_version（见 service.AccountExtraCLIVersion）。
// 未绑定 / 绑定空串时由 ClaudeVersionService 的后台维护按账号权重自动分配，
// 这里只负责让管理员能显式钉住或解绑，所以一律走 UpdateAccountExtra
// 做 key 级合并，避免覆盖 extra 里的其它运行态键。

type claudeVersionBindingResponse struct {
	AccountID int64  `json:"account_id"`
	Version   string `json:"cli_version"`
	Auto      bool   `json:"auto"`
}

type updateClaudeVersionBindingRequest struct {
	// Version 为空表示解绑，回到自动分配。
	Version string `json:"version"`
}

// ListClaudeVersions 返回可绑定的版本列表（最新在前），供前端下拉使用。
// GET /api/v1/admin/accounts/cli-versions
func (h *AccountHandler) ListClaudeVersions(c *gin.Context) {
	versions := claude.LibraryVersions()
	sort.SliceStable(versions, func(i, j int) bool {
		return service.CompareVersions(versions[i], versions[j]) > 0
	})
	response.Success(c, gin.H{"versions": versions})
}

// GetClaudeVersionBinding 返回账号当前绑定的版本。
// GET /api/v1/admin/accounts/:id/cli-version
func (h *AccountHandler) GetClaudeVersionBinding(c *gin.Context) {
	account, err := h.getClaudeVersionAccount(c)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, buildClaudeVersionBindingResponse(account))
}

// UpdateClaudeVersionBinding 绑定或解绑账号的客户端版本。
// PUT /api/v1/admin/accounts/:id/cli-version
func (h *AccountHandler) UpdateClaudeVersionBinding(c *gin.Context) {
	account, err := h.getClaudeVersionAccount(c)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	var req updateClaudeVersionBindingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	version := strings.TrimSpace(req.Version)
	if version != "" && !isBindableClaudeVersion(version) {
		response.ErrorFrom(c, infraerrors.BadRequest(
			"CLAUDE_VERSION_UNSUPPORTED",
			"version must be a version present in the fingerprint library or a supported newer CLI version",
		))
		return
	}

	// next_at 一并清空：手动绑定后由维护任务按绑定后的位置重新排期，
	// 否则会沿用旧版本算出来的时间点，出现刚绑就立刻被升走的怪现象。
	updates := map[string]any{
		service.AccountExtraCLIVersion:       version,
		service.AccountExtraCLIVersionNextAt: "",
	}
	if err := h.adminService.UpdateAccountExtra(c.Request.Context(), account.ID, updates); err != nil {
		response.ErrorFrom(c, err)
		return
	}

	updated, err := h.adminService.GetAccount(c.Request.Context(), account.ID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, buildClaudeVersionBindingResponse(updated))
}

func (h *AccountHandler) getClaudeVersionAccount(c *gin.Context) (*service.Account, error) {
	accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return nil, infraerrors.BadRequest("INVALID_ACCOUNT_ID", "Invalid account ID")
	}
	account, err := h.adminService.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, infraerrors.NotFound("ACCOUNT_NOT_FOUND", "account not found")
	}
	if account.Platform != service.PlatformAnthropic {
		return nil, infraerrors.BadRequest(
			"CLAUDE_VERSION_UNSUPPORTED_PLATFORM",
			"client version binding is only supported for Anthropic accounts",
		)
	}
	if account.Type != service.AccountTypeOAuth && account.Type != service.AccountTypeSetupToken {
		return nil, infraerrors.BadRequest(
			"CLAUDE_VERSION_UNSUPPORTED_ACCOUNT",
			"client version binding is only supported for OAuth and setup-token accounts",
		)
	}
	return account, nil
}

// isBindableClaudeVersion 与运行时的可用集保持一致：特征库内版本（含低于下界的历史版本）
// 或满足下界的合法 semver。库内版本不走 IsSupportedCLIVersion，否则 2.1.312 这类会被拒。
func isBindableClaudeVersion(version string) bool {
	for _, v := range claude.LibraryVersions() {
		if v == version {
			return true
		}
	}
	return claude.IsSupportedCLIVersion(version)
}

func buildClaudeVersionBindingResponse(account *service.Account) claudeVersionBindingResponse {
	version := strings.TrimSpace(account.GetExtraString(service.AccountExtraCLIVersion))
	return claudeVersionBindingResponse{
		AccountID: account.ID,
		Version:   version,
		Auto:      version == "",
	}
}
