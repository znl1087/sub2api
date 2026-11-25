package service

import (
	"context"
	"fmt"
	"slices"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	dbaccount "github.com/Wei-Shaw/sub2api/ent/account"
	dbgroup "github.com/Wei-Shaw/sub2api/ent/group"
	dbuser "github.com/Wei-Shaw/sub2api/ent/user"
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/adminaccess"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

var errManagedAccountGroups = infraerrors.BadRequest("MANAGED_ACCOUNT_GROUPS", "Change the account's bound users to manage its dedicated groups")

func (s *adminServiceImpl) inAccountUserBindingTransaction(ctx context.Context, mutate func(context.Context) (*Account, error)) (*Account, error) {
	if adminaccess.RestrictedFromContext(ctx) != nil {
		return nil, infraerrors.Forbidden("ACCOUNT_USER_BINDING_SCOPE", "User binding requires full administrator access")
	}
	if s.cfg != nil && s.cfg.RunMode == config.RunModeSimple {
		return nil, infraerrors.BadRequest("ACCOUNT_USER_BINDING_SIMPLE_MODE", "User binding requires standard mode")
	}
	if dbent.TxFromContext(ctx) != nil {
		return mutate(ctx)
	}
	if s.entClient == nil {
		return nil, fmt.Errorf("account user binding requires a database transaction")
	}
	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	account, err := mutate(dbent.NewTxContext(ctx, tx))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return account, nil
}

func (s *adminServiceImpl) managedAccountGroups(ctx context.Context, platform string, userIDs []int64) ([]int64, error) {
	if len(userIDs) > 100 {
		return nil, infraerrors.BadRequest("ACCOUNT_BINDING_USER_LIMIT", "Select at most 100 users for one account")
	}
	ids := slices.Clone(userIDs)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	client := dbent.TxFromContext(ctx).Client()
	// Lock owners in a stable order so concurrent account imports reuse the same groups.
	users, err := client.User.Query().Where(dbuser.IDIn(ids...), dbuser.StatusEQ(StatusActive)).
		Order(dbent.Asc(dbuser.FieldID)).ForUpdate().All(ctx)
	if err != nil {
		return nil, err
	}
	if len(users) != len(ids) {
		return nil, infraerrors.BadRequest("ACCOUNT_BINDING_INVALID_USER", "Every bound user must be an active user")
	}
	groupIDs := make([]int64, 0, len(ids))
	for _, userID := range ids {
		group, err := client.Group.Query().Where(dbgroup.OwnerUserIDEQ(userID), dbgroup.PlatformEQ(platform)).Only(ctx)
		if dbent.IsNotFound(err) {
			group, err = client.Group.Create().
				SetName(fmt.Sprintf("private-%s-user-%d", platform, userID)).
				SetPlatform(platform).
				SetOwnerUserID(userID).
				SetIsExclusive(true).
				Save(ctx)
		}
		if err != nil {
			return nil, err
		}
		if err := s.userRepo.AddGroupToAllowedGroups(ctx, userID, group.ID); err != nil {
			return nil, err
		}
		groupIDs = append(groupIDs, group.ID)
	}
	return groupIDs, nil
}

// lockAccountUserBinding serializes membership changes with Spark shadow creation.
func lockAccountUserBinding(ctx context.Context, id int64) error {
	_, err := dbent.TxFromContext(ctx).Client().Account.Query().Where(dbaccount.IDEQ(id)).ForUpdate().Only(ctx)
	if dbent.IsNotFound(err) {
		return ErrAccountNotFound
	}
	return err
}

func (s *adminServiceImpl) publishAccountUserBinding(ctx context.Context, accountID int64, userIDs []int64) {
	AfterAccountCommit(ctx, func(committed context.Context) {
		if repo, ok := s.accountRepo.(interface{ RefreshAccountUserBinding(context.Context, int64) }); ok {
			repo.RefreshAccountUserBinding(committed, accountID)
		}
		if s.authCacheInvalidator != nil {
			for _, id := range userIDs {
				s.authCacheInvalidator.InvalidateAuthCacheByUserID(committed, id)
			}
		}
	})
}

func (s *adminServiceImpl) validateManualAccountGroups(ctx context.Context, groupIDs []int64) error {
	if err := s.ValidateAccountGroupBindings(ctx, groupIDs); err != nil {
		return err
	}
	if len(groupIDs) == 0 || s.entClient == nil {
		return nil
	}
	client := s.entClient
	if tx := dbent.TxFromContext(ctx); tx != nil {
		client = tx.Client()
	}
	managed, err := client.Group.Query().Where(dbgroup.IDIn(groupIDs...), dbgroup.OwnerUserIDNotNil()).Exist(ctx)
	if err != nil {
		return err
	}
	if managed {
		return errManagedAccountGroups
	}
	return nil
}
