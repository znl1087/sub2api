package service

import (
	"context"
	"slices"
)

type authenticatedUserBindingGroupKey struct{}

type authenticatedUserBindingGroup struct {
	groupID int64
	ownerID int64
}

// WithAuthenticatedUserBindingGroup preserves the authorized private group when
// dispatch, routing, or billing replaces the current group in the request context.
func WithAuthenticatedUserBindingGroup(ctx context.Context, group *Group) context.Context {
	if group == nil || group.OwnerUserID == nil || *group.OwnerUserID <= 0 || group.ID <= 0 {
		return ctx
	}
	return context.WithValue(ctx, authenticatedUserBindingGroupKey{}, authenticatedUserBindingGroup{
		groupID: group.ID,
		ownerID: *group.OwnerUserID,
	})
}

func AuthenticatedUserBindingGroupID(ctx context.Context) int64 {
	group, _ := ctx.Value(authenticatedUserBindingGroupKey{}).(authenticatedUserBindingGroup)
	return group.groupID
}

// AccountVisibleForUserBinding checks isolation for both public and private pools.
// It does not replace the ordinary model, platform, or group membership checks.
func AccountVisibleForUserBinding(ctx context.Context, account *Account, groupID *int64) bool {
	if account == nil {
		return false
	}
	privateGroupID := AuthenticatedUserBindingGroupID(ctx)
	if privateGroupID == 0 {
		return !account.UserBindingEnabled
	}
	return account.UserBindingEnabled && groupID != nil && *groupID == privateGroupID &&
		slices.Contains(account.GroupIDs, privateGroupID)
}

// Recheck after hydration, which refreshes an account selected from an
// already-scoped pool and can observe a binding change since selection.
func hydratedAccountVisibleForUserBinding(ctx context.Context, repo AccountRepository, account *Account) error {
	group, _ := ctx.Value(authenticatedUserBindingGroupKey{}).(authenticatedUserBindingGroup)
	return verifyAccountUserBinding(ctx, repo, account, &group.groupID)
}

type accountUserBindingVerifier interface {
	VerifyAccountUserBinding(ctx context.Context, accountID, privateGroupID, ownerID int64) (bool, error)
}

// Verify the final candidate against the database even if a stale cached
// account still looks public. Only the selected account needs this extra read.
func verifyAccountUserBinding(ctx context.Context, repo AccountRepository, account *Account, groupID *int64) error {
	if !AccountVisibleForUserBinding(ctx, account, groupID) {
		return ErrNoAvailableAccounts
	}
	if verifier, ok := repo.(accountUserBindingVerifier); ok {
		group, _ := ctx.Value(authenticatedUserBindingGroupKey{}).(authenticatedUserBindingGroup)
		visible, err := verifier.VerifyAccountUserBinding(ctx, account.ID, group.groupID, group.ownerID)
		if err != nil {
			return err
		}
		if !visible {
			return ErrNoAvailableAccounts
		}
	}
	return nil
}

// filterUserBindingAccounts compacts a caller-owned candidate slice in place.
func filterUserBindingAccounts(ctx context.Context, accounts []Account, groupID *int64) []Account {
	visible := accounts[:0]
	for i := range accounts {
		if AccountVisibleForUserBinding(ctx, &accounts[i], groupID) {
			visible = append(visible, accounts[i])
		}
	}
	clear(accounts[len(visible):])
	return visible
}
