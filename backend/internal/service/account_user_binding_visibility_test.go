package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/stretchr/testify/require"
)

type userBindingSnapshotCache struct {
	SchedulerCache
	accounts []*Account
}

func (c userBindingSnapshotCache) GetSnapshot(_ context.Context, _ SchedulerBucket) ([]*Account, bool, error) {
	return c.accounts, true, nil
}

func (c userBindingSnapshotCache) GetAccount(_ context.Context, _ int64) (*Account, error) {
	return c.accounts[0], nil
}

type userBindingVerifierRepo struct {
	AccountRepository
	allowed bool
	checked int64
}

func (r *userBindingVerifierRepo) VerifyAccountUserBinding(_ context.Context, accountID, _, _ int64) (bool, error) {
	r.checked = accountID
	return r.allowed, nil
}

func TestSchedulerSnapshotRestrictsPrivateAccountsToAuthenticatedGroup(t *testing.T) {
	ownerID := int64(77)
	privateGroup := &Group{ID: 21, OwnerUserID: &ownerID}
	otherGroupID := int64(22)
	cache := userBindingSnapshotCache{accounts: []*Account{
		{ID: 11, Status: StatusActive, Schedulable: true},
		{ID: 12, Status: StatusActive, Schedulable: true, UserBindingEnabled: true, GroupIDs: []int64{privateGroup.ID}},
		{ID: 13, Status: StatusActive, Schedulable: true, UserBindingEnabled: true, GroupIDs: []int64{otherGroupID}},
	}}
	snapshot := &SchedulerSnapshotService{cache: cache}
	// A service-side group rewrite does not establish an authenticated binding.
	publicCtx := context.WithValue(context.Background(), ctxkey.Group, privateGroup)
	public, _, err := snapshot.ListSchedulableAccounts(publicCtx, nil, PlatformOpenAI, false)
	require.NoError(t, err)
	require.Len(t, public, 1)
	require.Equal(t, int64(11), public[0].ID)

	privateCtx := WithAuthenticatedUserBindingGroup(context.Background(), privateGroup)
	owned, _, err := snapshot.ListSchedulableAccounts(privateCtx, &privateGroup.ID, PlatformOpenAI, false)
	require.NoError(t, err)
	require.Len(t, owned, 1)
	require.Equal(t, int64(12), owned[0].ID)

	wrongBucket, _, err := snapshot.ListSchedulableAccounts(privateCtx, &otherGroupID, PlatformOpenAI, false)
	require.NoError(t, err)
	require.Empty(t, wrongBucket)
}

func TestGatewayFinalSelectionChecksStalePublicSnapshotAgainstBinding(t *testing.T) {
	repo := &userBindingVerifierRepo{}
	stale := &Account{ID: 42, Status: StatusActive, Schedulable: true}
	snapshot := &SchedulerSnapshotService{cache: userBindingSnapshotCache{accounts: []*Account{stale}}}
	svc := &GatewayService{accountRepo: repo, schedulerSnapshot: snapshot}

	released := false
	selection, err := svc.newSelectionResult(context.Background(), stale, true, func() { released = true }, nil)
	require.ErrorIs(t, err, ErrNoAvailableAccounts)
	require.Nil(t, selection)
	require.Equal(t, stale.ID, repo.checked)
	require.True(t, released)
}
