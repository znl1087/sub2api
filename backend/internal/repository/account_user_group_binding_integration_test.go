//go:build integration

package repository

import (
	"context"
	"testing"

	dbaccount "github.com/Wei-Shaw/sub2api/ent/account"
	dbgroup "github.com/Wei-Shaw/sub2api/ent/group"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAdminAccountManagedUserBinding(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	users := NewUserRepository(client, integrationDB)
	accounts := newAccountRepositoryWithSQL(client, integrationDB, nil)
	groups := NewAdminGroupRepository(client, integrationDB)
	admin := service.NewAdminService(&config.Config{}, users, groups, accounts,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, client,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	first := mustCreateUser(t, client, &service.User{})
	second := mustCreateUser(t, client, &service.User{})
	stranger := mustCreateUser(t, client, &service.User{})
	platform := service.PlatformAnthropic
	public, err := client.Group.Create().SetName(t.Name() + "-public").SetPlatform(platform).Save(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		// This test owns these groups, the users, and the accounts attached to them.
		_, _ = integrationDB.ExecContext(ctx, `DELETE FROM accounts WHERE name LIKE 'managed-binding-test-%'`)
		_, _ = integrationDB.ExecContext(ctx, `DELETE FROM groups WHERE id=$1 OR owner_user_id IN ($2,$3)`, public.ID, first.ID, second.ID)
		_, _ = integrationDB.ExecContext(ctx, `DELETE FROM users WHERE id IN ($1,$2,$3)`, first.ID, second.ID, stranger.ID)
	})

	create := func(name string, ownerIDs []int64, groupIDs []int64) (*service.Account, error) {
		return admin.CreateAccount(ctx, &service.CreateAccountInput{
			Name: "managed-binding-test-" + name, Platform: platform, Type: service.AccountTypeAPIKey,
			Credentials: map[string]any{"api_key": "example-only"}, Concurrency: 1,
			BoundUserIDs: ownerIDs, GroupIDs: groupIDs, SkipDefaultGroupBind: true,
		})
	}
	registered, err := create("both", []int64{second.ID, first.ID, first.ID}, nil)
	require.NoError(t, err)
	require.True(t, registered.UserBindingEnabled)
	require.ElementsMatch(t, []int64{first.ID, second.ID}, registered.BoundUserIDs())
	require.Len(t, registered.Groups, 2)
	ownerGroups := make(map[int64]int64, len(registered.Groups))
	for _, group := range registered.Groups {
		require.True(t, group.IsExclusive)
		require.Equal(t, service.SubscriptionTypeStandard, group.SubscriptionType)
		ownerGroups[*group.OwnerUserID] = group.ID
		owner, err := users.GetByID(ctx, *group.OwnerUserID)
		require.NoError(t, err)
		require.Contains(t, owner.AllowedGroups, group.ID)
		listed, err := accounts.ListSchedulableByGroupIDAndPlatform(ctx, group.ID, platform)
		require.NoError(t, err)
		require.Len(t, listed, 1)
		require.Equal(t, registered.ID, listed[0].ID)
	}
	unboundUser, err := users.GetByID(ctx, stranger.ID)
	require.NoError(t, err)
	require.NotContains(t, unboundUser.AllowedGroups, ownerGroups[first.ID])
	global, err := accounts.ListSchedulableByPlatform(ctx, platform)
	require.NoError(t, err)
	for _, account := range global {
		require.NotEqual(t, registered.ID, account.ID)
	}
	_, err = client.AccountGroup.Create().SetAccountID(registered.ID).SetGroupID(public.ID).Save(ctx)
	require.Error(t, err)

	ordinary, err := create("ordinary", nil, []int64{public.ID})
	require.NoError(t, err)
	_, err = client.AccountGroup.Create().SetAccountID(ordinary.ID).SetGroupID(ownerGroups[first.ID]).Save(ctx)
	require.Error(t, err)
	owners := []int64{first.ID}
	converted, err := admin.UpdateAccount(ctx, ordinary.ID, &service.UpdateAccountInput{BoundUserIDs: &owners})
	require.NoError(t, err)
	require.True(t, converted.UserBindingEnabled)
	require.Equal(t, []int64{ownerGroups[first.ID]}, converted.GroupIDs, "reuse the existing owned group")
	ordinaryGroups := []int64{public.ID}
	_, err = admin.UpdateAccount(ctx, ordinary.ID, &service.UpdateAccountInput{GroupIDs: &ordinaryGroups})
	require.Error(t, err, "legacy shared-group edits cannot release a user-bound account")

	revoked := []int64{second.ID}
	rerouted, err := admin.UpdateAccount(ctx, ordinary.ID, &service.UpdateAccountInput{BoundUserIDs: &revoked})
	require.NoError(t, err)
	require.Equal(t, []int64{ownerGroups[second.ID]}, rerouted.GroupIDs)
	for _, check := range []struct {
		groupID int64
		ownerID int64
		allowed bool
	}{
		{0, 0, false},
		{ownerGroups[first.ID], first.ID, false},
		{ownerGroups[second.ID], stranger.ID, false},
		{ownerGroups[second.ID], second.ID, true},
	} {
		allowed, err := accounts.VerifyAccountUserBinding(ctx, ordinary.ID, check.groupID, check.ownerID)
		require.NoError(t, err)
		require.Equal(t, check.allowed, allowed)
	}
	remaining, err := accounts.ListSchedulableByGroupIDAndPlatform(ctx, ownerGroups[first.ID], platform)
	require.NoError(t, err)
	require.Len(t, remaining, 1)
	require.Equal(t, registered.ID, remaining[0].ID)

	empty := []int64{}
	released, err := admin.UpdateAccount(ctx, ordinary.ID, &service.UpdateAccountInput{BoundUserIDs: &empty, GroupIDs: &ordinaryGroups})
	require.NoError(t, err)
	require.False(t, released.UserBindingEnabled)
	require.Equal(t, []int64{public.ID}, released.GroupIDs)

	_, err = create("invalid-user", []int64{stranger.ID, -1}, nil)
	require.Error(t, err)
	exists, err := client.Group.Query().Where(dbgroup.OwnerUserIDEQ(stranger.ID)).Exist(ctx)
	require.NoError(t, err)
	require.False(t, exists)
	exists, err = client.Account.Query().Where(dbaccount.NameEQ("managed-binding-test-invalid-user")).Exist(ctx)
	require.NoError(t, err)
	require.False(t, exists)
}
