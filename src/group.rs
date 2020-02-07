pub use crate::internal::group_api::{
    GroupAccessEditErr, GroupAccessEditResult, GroupCreateResult, GroupGetResult, GroupId,
    GroupListResult, GroupMetaResult, GroupName, GroupUpdatePrivateKeyResult,
};
use crate::{
    internal::{
        group_api, group_api::GroupCreateOptsStd, run_maybe_timed_sdk_op, user_api::UserId,
        IronOxideErr,
    },
    Result, SdkOperation,
};
use vec1::Vec1;

#[derive(Clone)]
/// Options for group creation.
pub struct GroupCreateOpts {
    // unique id of a group within a segment. If none, the server will assign an id.
    id: Option<GroupId>,
    // human readable name of the group. Does not need to be unique.
    name: Option<GroupName>,
    // true (default) - creating user will be added as an admin of the group.
    // false - creating user will not be added as an admin of the group.
    add_as_admin: bool,
    // true (default) - creating user will be added to the group's membership (in addition to being the group's admin);
    // false - creating user will not be added to the group's membership
    add_as_member: bool,
    // Specifies who the owner of this group is. Group owners have the same permissions as other admins but they cannot be removed as an administrator.
    // None (default) - The creating user will be the owner of the group. Cannot be used if `add_as_admin` is set to false as the owner must be an admin.
    // Some(UserId) - The provided user will be the owner of the group. This ID will automatically be added to the admins list.
    owner: Option<UserId>,
    // list of users to add as admins of the group
    // note: even if `add_as_admin` is false, the calling user will be added as an admin if they are in this list.
    admins: Vec<UserId>,
    // list of users to add as members of the group.
    // note: even if `add_as_member` is false, the calling user will be added as a member if they are in this list.
    members: Vec<UserId>,
    // true - group's private key will be marked for rotation
    // false (default) - group's private key will not be marked for rotation
    needs_rotation: bool,
}

impl GroupCreateOpts {
    /// Constructor. Also see `default()`
    ///
    /// # Arguments
    /// - `id` - Unique id of a group within a segment. If none, the server will assign an id.
    /// - `name` - Human readable name of the group. Does not need to be unique. Will **not** be encrypted.
    /// - `add_as_admin`
    ///     - true (default) - The creating user will be added as an admin of the group.
    ///     - false - The creating user will not be an admin of the group.
    /// - `add_as_member`
    ///     - true (default) - The creating user will be added as a member of the group.
    ///     - false - The creating user will not be a member of the group.
    /// - `owner` - Specifies the owner of the group
    ///     - None (default) - The creating user will be the owner of the group. Cannot be used if `add_as_admin` is set to false as the owner must be an admin.
    ///     - Some(UserId) - The provided user will be the owner of the group. This ID will automatically be added to the admins list.
    /// - `admins` - List of users to be added as admins of the group. This list takes priority over `add_as_admin`,
    ///             so the calling user will be added as a member if their id is in this list even if `add_as_admin` is false.
    /// - `members` - List of users to be added as members of the group. This list takes priority over `add_as_member`,
    ///             so the calling user will be added as a member if their id is in this list even if `add_as_member` is false.
    /// - `needs_rotation`
    ///     - true - group's private key will be marked for rotation
    ///     - false (default) - group's private key will not be marked for rotation
    pub fn new(
        id: Option<GroupId>,
        name: Option<GroupName>,
        add_as_admin: bool,
        add_as_member: bool,
        owner: Option<UserId>,
        admins: Vec<UserId>,
        members: Vec<UserId>,
        needs_rotation: bool,
    ) -> GroupCreateOpts {
        GroupCreateOpts {
            id,
            name,
            add_as_admin,
            add_as_member,
            owner,
            admins,
            members,
            needs_rotation,
        }
    }

    fn standardize(self, calling_id: &UserId) -> Result<GroupCreateOptsStd> {
        // if `add_as_member`, make sure the calling user is in the `members` list
        let standardized_members = if self.add_as_member && !self.members.contains(calling_id) {
            let mut members = self.members.clone();
            members.push(calling_id.clone());
            members
        } else {
            self.members
        };
        let (standardized_admins, owner_id) = {
            // if `add_as_admin`, make sure the calling user is in the `admins` list
            let mut admins = if self.add_as_admin && !self.admins.contains(calling_id) {
                let mut admins = self.admins.clone();
                admins.push(calling_id.clone());
                admins
            } else {
                self.admins
            };
            let owner: &UserId = match &self.owner {
                Some(owner_id) => {
                    // if the owner is specified, make sure they're in the `admins` list
                    if !admins.contains(owner_id) {
                        admins.push(owner_id.clone());
                    }
                    owner_id
                }
                // if the owner is the calling user (default), they should have been added to the
                // admins list by `add_as_admin`. If they aren't, it will error later on.
                None => calling_id,
            };
            (admins, owner)
        };

        let non_empty_admins = Vec1::try_from_vec(standardized_admins).map_err(|_| {
            IronOxideErr::ValidationError(format!("admins"), format!("admins list cannot be empty"))
        })?;

        if !non_empty_admins.contains(owner_id) {
            Err(IronOxideErr::ValidationError(
                format!("admins"),
                format!("admins list must contain the owner"),
            ))
        } else {
            Ok(GroupCreateOptsStd {
                id: self.id,
                name: self.name,
                owner: self.owner,
                admins: non_empty_admins,
                members: standardized_members,
                needs_rotation: self.needs_rotation,
            })
        }
    }
}

impl Default for GroupCreateOpts {
    /// Default GroupCreateOpts for common use cases. The user who calls `group_create()` will be the owner of the group
    /// as well as an admin and member of the group.
    fn default() -> Self {
        GroupCreateOpts::new(None, None, true, true, None, vec![], vec![], false)
    }
}

#[async_trait]
pub trait GroupOps {
    /// List all of the groups that the current user is either an admin or member of.
    ///
    /// # Returns
    /// `GroupListResult` List of (abbreviated) metadata about each group the user is a part of.
    async fn group_list(&self) -> Result<GroupListResult>;

    /// Create a group. The creating user will become a group admin and by default a group member.
    ///
    /// # Arguments
    /// `group_create_opts` - See `GroupCreateOpts`. Use the `Default` implementation for defaults.
    async fn group_create(&self, group_create_opts: &GroupCreateOpts) -> Result<GroupCreateResult>;

    /// Get the full metadata for a specific group given its ID.
    ///
    /// # Arguments
    /// - `id` - Unique ID of the group to retrieve
    ///
    /// # Returns
    /// `GroupMetaResult` with details about the requested group.
    async fn group_get_metadata(&self, id: &GroupId) -> Result<GroupGetResult>;

    /// Delete the identified group. Group does not have to be empty of admins/members in order to
    /// delete the group. **Warning: Deletion of a group will cause all documents encrypted to that
    /// group to no longer be decryptable. Caution should be used when deleting groups.**
    ///
    /// # Arguments
    /// `id` - Unique id of group
    ///
    /// # Returns
    /// Deleted group id or error
    async fn group_delete(&self, id: &GroupId) -> Result<GroupId>;

    /// Update a group name to a new value or clear its value.
    ///
    /// # Arguments
    /// - `id` - ID of the group to update
    /// - `name` - New name for the group. Provide a Some to update to a new name and a None to clear the name field.
    ///
    /// # Returns
    /// `Result<GroupMetaResult>` Metadata about the group that was updated.
    async fn group_update_name(
        &self,
        id: &GroupId,
        name: Option<&GroupName>,
    ) -> Result<GroupMetaResult>;

    /// Add the users as members of a group.
    ///
    /// # Arguments
    /// - `id` - ID of the group to add members to
    /// - `users` - The list of users thet will be added to the group as members.
    /// # Returns
    /// GroupAccessEditResult, which contains all the users that were added. It also contains the users that were not added and
    ///   the reason they were not.
    async fn group_add_members(
        &self,
        id: &GroupId,
        users: &[UserId],
    ) -> Result<GroupAccessEditResult>;

    /// Remove a list of users as members from the group.
    ///
    /// # Arguments
    /// - `id` - ID of the group to remove members from
    /// - `revoke_list` - List of user IDs to remove as members
    ///
    /// # Returns
    /// `Result<GroupAccessEditResult>` List of users that were removed. Also contains the users that failed to be removed
    ///    and the reason they were not.
    async fn group_remove_members(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult>;

    /// Add the users as admins of a group.
    ///
    /// # Arguments
    /// - `id` - ID of the group to add admins to
    /// - `users` - The list of users that will be added to the group as admins.
    /// # Returns
    /// GroupAccessEditResult, which contains all the users that were added. It also contains the users that were not added and
    ///   the reason they were not.
    async fn group_add_admins(
        &self,
        id: &GroupId,
        users: &[UserId],
    ) -> Result<GroupAccessEditResult>;

    /// Remove a list of users as admins from the group.
    ///
    /// # Arguments
    /// - `id` - ID of the group
    /// - `revoke_list` - List of user IDs to remove as admins
    ///
    /// # Returns
    /// `Result<GroupAccessEditResult>` List of users that were removed. Also contains the users that failed to be removed
    ///    and the reason they were not.
    async fn group_remove_admins(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult>;

    /// Rotate the provided group's private key, but leave the public key the same.
    /// There's no black magic here! This is accomplished via multi-party computation with the
    /// IronCore webservice.
    /// Note: You must be an admin of the group in order to rotate its private key.
    ///
    /// # Arguments
    /// `id` - ID of the group you wish to rotate the private key of
    ///
    /// # Returns
    /// An indication of whether the group's private key needs an additional rotation
    async fn group_rotate_private_key(&self, id: &GroupId) -> Result<GroupUpdatePrivateKeyResult>;
}

#[async_trait]
impl GroupOps for crate::IronOxide {
    async fn group_list(&self) -> Result<GroupListResult> {
        run_maybe_timed_sdk_op(
            group_api::list(self.device.auth(), None),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupList,
        )
        .await?
    }

    async fn group_create(&self, opts: &GroupCreateOpts) -> Result<GroupCreateResult> {
        let standard_opts = opts.clone().standardize(self.device.auth().account_id())?;
        let all_users = &standard_opts.all_users();
        let GroupCreateOptsStd {
            id,
            name,
            owner,
            admins,
            members,
            needs_rotation,
        } = standard_opts;

        run_maybe_timed_sdk_op(
            group_api::group_create(
                &self.recrypt,
                self.device.auth(),
                id,
                name,
                owner,
                admins,
                members,
                all_users,
                needs_rotation,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupCreate,
        )
        .await?
    }

    async fn group_get_metadata(&self, id: &GroupId) -> Result<GroupGetResult> {
        run_maybe_timed_sdk_op(
            group_api::get_metadata(self.device.auth(), id),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupGetMetadata,
        )
        .await?
    }

    async fn group_delete(&self, id: &GroupId) -> Result<GroupId> {
        run_maybe_timed_sdk_op(
            group_api::group_delete(self.device.auth(), id),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupDelete,
        )
        .await?
    }

    async fn group_update_name(
        &self,
        id: &GroupId,
        name: Option<&GroupName>,
    ) -> Result<GroupMetaResult> {
        run_maybe_timed_sdk_op(
            group_api::update_group_name(self.device.auth(), id, name),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupUpdateName,
        )
        .await?
    }

    async fn group_add_members(
        &self,
        id: &GroupId,
        grant_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        run_maybe_timed_sdk_op(
            group_api::group_add_members(
                &self.recrypt,
                self.device.auth(),
                self.device.device_private_key(),
                id,
                &grant_list.to_vec(),
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupAddMembers,
        )
        .await?
    }

    async fn group_remove_members(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        run_maybe_timed_sdk_op(
            group_api::group_remove_entity(
                self.device.auth(),
                id,
                &revoke_list.to_vec(),
                group_api::GroupEntity::Member,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupRemoveMembers,
        )
        .await?
    }

    async fn group_add_admins(
        &self,
        id: &GroupId,
        users: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        run_maybe_timed_sdk_op(
            group_api::group_add_admins(
                &self.recrypt,
                self.device.auth(),
                self.device.device_private_key(),
                id,
                &users.to_vec(),
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupAddAdmins,
        )
        .await?
    }

    async fn group_remove_admins(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        run_maybe_timed_sdk_op(
            group_api::group_remove_entity(
                self.device.auth(),
                id,
                &revoke_list.to_vec(),
                group_api::GroupEntity::Admin,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupRemoveAdmins,
        )
        .await?
    }

    async fn group_rotate_private_key(&self, id: &GroupId) -> Result<GroupUpdatePrivateKeyResult> {
        run_maybe_timed_sdk_op(
            group_api::group_rotate_private_key(
                &self.recrypt,
                self.device().auth(),
                id,
                self.device().device_private_key(),
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupRotatePrivateKey,
        )
        .await?
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        group::GroupCreateOpts,
        internal::{user_api::UserId, IronOxideErr},
    };

    #[test]
    fn build_group_create_opts_default() {
        let opts = GroupCreateOpts::default();
        assert_eq!(None, opts.id);
        assert_eq!(None, opts.name);
        assert_eq!(true, opts.add_as_member);
    }

    #[test]
    fn group_create_opts_default_standardize() -> Result<(), IronOxideErr> {
        let calling_user_id = UserId::unsafe_from_string("test_user".to_string());
        let opts = GroupCreateOpts::default();
        let std_opts = opts.standardize(&calling_user_id)?;
        assert_eq!(std_opts.all_users(), [calling_user_id.clone()]);
        assert_eq!(std_opts.owner, None);
        assert_eq!(std_opts.admins, [calling_user_id.clone()]);
        assert_eq!(std_opts.members, [calling_user_id]);
        assert_eq!(std_opts.needs_rotation, false);
        Ok(())
    }

    #[test]
    fn group_create_opts_standardize_non_owner() -> Result<(), IronOxideErr> {
        let calling_user_id = UserId::unsafe_from_string("test_user".to_string());
        let owner = UserId::unsafe_from_string("owner".to_string());
        let opts = GroupCreateOpts::new(
            None,
            None,
            false,
            false,
            Some(owner.clone()),
            vec![],
            vec![],
            true,
        );
        let std_opts = opts.standardize(&calling_user_id)?;
        assert_eq!(std_opts.all_users(), [owner.clone()]);
        assert_eq!(std_opts.owner, Some(owner.clone()));
        assert_eq!(std_opts.admins, [owner.clone()]);
        assert_eq!(std_opts.members, []);
        assert_eq!(std_opts.needs_rotation, true);
        Ok(())
    }

    #[test]
    fn group_create_opts_standardize_invalid() -> Result<(), IronOxideErr> {
        let calling_user_id = UserId::unsafe_from_string("test_user".to_string());
        let opts = GroupCreateOpts::new(None, None, false, true, None, vec![], vec![], false);
        let std_opts = opts.standardize(&calling_user_id);
        assert!(std_opts.is_err());
        Ok(())
    }
}
