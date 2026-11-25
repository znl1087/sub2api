ALTER TABLE accounts ADD COLUMN user_binding_enabled boolean NOT NULL DEFAULT false;

ALTER TABLE groups ADD COLUMN owner_user_id bigint REFERENCES users (id) ON DELETE RESTRICT;
ALTER TABLE groups ADD CONSTRAINT groups_managed_owner_policy CHECK (
    owner_user_id IS NULL OR (
        is_exclusive AND subscription_type = 'standard'
        AND fallback_group_id IS NULL AND fallback_group_id_on_invalid_request IS NULL
    )
);
CREATE UNIQUE INDEX groups_live_owner_platform_key ON groups (owner_user_id, platform)
    WHERE owner_user_id IS NOT NULL AND deleted_at IS NULL;

-- Group cloning and bulk operations can write the join without the account editor.
CREATE FUNCTION enforce_managed_account_group() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    private_account boolean;
    account_platform varchar;
    group_owner bigint;
    group_platform varchar;
BEGIN
    SELECT user_binding_enabled, platform INTO private_account, account_platform
        FROM accounts WHERE id = NEW.account_id FOR SHARE;
    SELECT owner_user_id, platform INTO group_owner, group_platform
        FROM groups WHERE id = NEW.group_id FOR SHARE;
    IF private_account <> (group_owner IS NOT NULL)
        OR (private_account AND account_platform <> group_platform) THEN
        RAISE EXCEPTION 'Private accounts can only be attached to managed groups of the same platform'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER account_groups_managed_scope BEFORE INSERT OR UPDATE OF account_id, group_id ON account_groups
    FOR EACH ROW EXECUTE FUNCTION enforce_managed_account_group();

-- A Spark shadow must never provide a second route to a private credential.
CREATE FUNCTION enforce_managed_account_shadow() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    private_parent boolean;
BEGIN
    IF NEW.parent_account_id IS NOT NULL THEN
        SELECT user_binding_enabled INTO private_parent FROM accounts WHERE id = NEW.parent_account_id FOR SHARE;
        IF NEW.user_binding_enabled OR private_parent THEN
            RAISE EXCEPTION 'Private accounts cannot participate in Spark shadow routing' USING ERRCODE = '23514';
        END IF;
    END IF;
    IF NEW.user_binding_enabled AND EXISTS (
        SELECT 1 FROM accounts WHERE parent_account_id = NEW.id AND deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'Remove Spark shadows before binding their parent to users' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER accounts_managed_shadow BEFORE INSERT OR UPDATE OF user_binding_enabled, parent_account_id ON accounts
    FOR EACH ROW EXECUTE FUNCTION enforce_managed_account_shadow();
