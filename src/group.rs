//! Group API
//!
//! See [GroupOps](trait.GroupOps.html) for group functions and key terms.

pub use crate::internal::group_api::{
    GroupAccessEditErr, GroupAccessEditResult, GroupCreateResult, GroupGetResult, GroupId,
    GroupListResult, GroupMetaResult, GroupName, GroupUpdatePrivateKeyResult,
};
use crate::{
    IronOxideErr, Result,
    common::SdkOperation,
    internal::{add_optional_timeout, group_api, group_api::GroupCreateOptsStd},
    user::UserId,
};
use futures::Future;
use vec1::Vec1;

/// Options for group creation.
///
/// Default values are provided with [GroupCreateOpts::default()](struct.GroupCreateOpts.html#method.default)
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GroupCreateOpts {
    /// ID of the group. If `None`, the server will assign the ID.
    id: Option<GroupId>,
    /// Name of the group.
    name: Option<GroupName>,
    /// - `true` (default) - creating user will be added as an admin of the group.
    /// - `false` - creating user will not be added as an admin of the group.
    add_as_admin: bool,
    /// - `true` (default) - creating user will be added to the group's membership.
    /// - `false` - creating user will not be added to the group's membership
    add_as_member: bool,
    /// Specifies who the owner of this group is. Group owners have the same permissions as other admins but they cannot be removed as an administrator.
    /// - `None` (default) - The creating user will be the owner of the group. Cannot be used if `add_as_admin` is set to false as the owner must be an admin.
    /// - `Some` - The provided user will be the owner of the group. This ID will automatically be added to the admins list.
    owner: Option<UserId>,
    /// List of users to add as admins of the group. Even if `add_as_admin` is false, the calling user will be added as an admin if they are in this list.
    admins: Vec<UserId>,
    /// List of users to add as members of the group. Even if `add_as_member` is false, the calling user will be added as a member if they are in this list.
    members: Vec<UserId>,
    /// - `true` - group's private key will be marked for rotation
    /// - `false` (default) - group's private key will not be marked for rotation
    needs_rotation: bool,
}

impl GroupCreateOpts {
    /// # Arguments
    /// - `id`
    ///     - `None` (default) - The server will assign the group's ID.
    ///     - `Some` - The provided ID will be used as the group's ID.
    /// - `name`
    ///     - `None` (default) - The group will be created with no name.
    ///     - `Some` - The provided name will be used as the group's name.
    /// - `add_as_admin`
    ///     - `true` (default) - The creating user will be added as a group admin.
    ///     - `false` - The creating user will not be a group admin.
    /// - `add_as_member`
    ///     - `true` (default) - The creating user will be added as a group member.
    ///     - `false` - The creating user will not be a group member.
    /// - `owner`
    ///     - `None` (default) - The creating user will be the owner of the group.
    ///     - `Some` - The provided user will be the owner of the group. This ID will automatically be added to the admin list.
    /// - `admins`
    ///     - The list of users to be added as group admins. This list takes priority over `add_as_admin`,
    ///       so the calling user will be added as an admin if they are in this list even if `add_as_admin` is false.
    /// - `members`
    ///     - The list of users to be added as members of the group. This list takes priority over `add_as_member`,
    ///       so the calling user will be added as a member if they are in this list even if `add_as_member` is false.
    /// - `needs_rotation`
    ///     - `true` - The group's private key will be marked for rotation.
    ///     - `false` (default) - The group's private key will not be marked for rotation.
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
            IronOxideErr::ValidationError(
                "admins".to_string(),
                "admins list cannot be empty".to_string(),
            )
        })?;

        if !non_empty_admins.contains(owner_id) {
            Err(IronOxideErr::ValidationError(
                "admins".to_string(),
                "admins list must contain the owner".to_string(),
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
    /// Default `GroupCreateOpts` for common use cases.
    ///
    /// The group will be assigned an ID and have an empty name. The user who calls [group_create](trait.GroupOps.html#tymethod.group_create)
    /// will be the owner of the group as well as the only admin and member of the group. The group's private key will not be marked for rotation.
    fn default() -> Self {
        GroupCreateOpts::new(None, None, true, true, None, vec![], vec![], false)
    }
}

/// IronOxide Group Operations
///
/// # Key Terms
/// - ID     - The ID representing a group. It must be unique within the group's segment and will **not** be encrypted.
/// - Name   - The human-readable name of a group. It does not need to be unique and will **not** be encrypted.
/// - Member - A user who is able to encrypt and decrypt data using the group.
/// - Admin  - A user who is able to manage the group's member and admin lists. An admin cannot encrypt or decrypt data using the group
///            unless they first add themselves as group members or are added by another admin.
/// - Owner  - The user who owns the group. The owner has the same permissions as a group admin, but is protected from being removed as
///            a group admin.
/// - Rotation - Changing a group's private key while leaving its public key unchanged. This can be accomplished by calling
///     [group_rotate_private_key](trait.GroupOps.html#tymethod.group_rotate_private_key).
pub trait GroupOps {
    /// Creates a group.
    ///
    /// With default `GroupCreateOpts`, the group will be assigned an ID and have no name. The creating user will become the
    /// owner of the group and the only group member and administrator.
    ///
    /// # Arguments
    /// `group_create_opts` - Group creation parameters. Default values are provided with
    ///      [GroupCreateOpts::default()](struct.GroupCreateOpts.html#method.default)
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use std::convert::TryFrom;
    /// let group_id = Some(GroupId::try_from("empl412")?);
    /// let opts = GroupCreateOpts::new(group_id, None, true, true, None, vec![], vec![], false);
    /// let group = sdk.group_create(&opts).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn group_create(
        &self,
        group_create_opts: &GroupCreateOpts,
    ) -> impl Future<Output = Result<GroupCreateResult>> + Send;

    /// Gets the full metadata for a group.
    ///
    /// The encrypted private key for the group will not be returned.
    ///
    /// # Arguments
    /// - `id` - ID of the group to retrieve
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use std::convert::TryFrom;
    /// let group_id = GroupId::try_from("empl412")?;
    /// let group_metadata = sdk.group_get_metadata(&group_id).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn group_get_metadata(
        &self,
        id: &GroupId,
    ) -> impl Future<Output = Result<GroupGetResult>> + Send;

    /// Lists all of the groups that the current user is an admin or a member of.
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// let group_list = sdk.group_list().await?;
    /// let groups: Vec<GroupMetaResult> = group_list.result().to_vec();
    /// # Ok(())
    /// # }
    /// ```
    fn group_list(&self) -> impl Future<Output = Result<GroupListResult>> + Send;

    /// Modifies or removes a group's name.
    ///
    /// Returns the updated metadata of the group.
    ///
    /// # Arguments
    /// - `id` - ID of the group to update
    /// - `name` - New name for the group. Provide a `Some` to update to a new name or a `None` to clear the group's name
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use std::convert::TryFrom;
    /// let group_id = GroupId::try_from("empl412")?;
    /// let new_name = GroupName::try_from("HQ Employees")?;
    /// let new_metadata = sdk.group_update_name(&group_id, Some(&new_name)).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn group_update_name(
        &self,
        id: &GroupId,
        name: Option<&GroupName>,
    ) -> impl Future<Output = Result<GroupMetaResult>> + Send;

    /// Rotates a group's private key while leaving its public key unchanged.
    ///
    /// There's no black magic here! This is accomplished via multi-party computation with the
    /// IronCore webservice.
    ///
    /// Note: You must be an administrator of a group in order to rotate its private key.
    ///
    /// # Arguments
    /// `id` - ID of the group whose private key should be rotated
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use std::convert::TryFrom;
    /// let group_id = GroupId::try_from("empl412")?;
    /// let rotate_result = sdk.group_rotate_private_key(&group_id).await?;
    /// let new_rotation = rotate_result.needs_rotation();
    /// # Ok(())
    /// # }
    /// ```
    fn group_rotate_private_key(
        &self,
        id: &GroupId,
    ) -> impl Future<Output = Result<GroupUpdatePrivateKeyResult>> + Send;

    /// Adds members to a group.
    ///
    /// Returns successful and failed additions.
    ///
    /// # Arguments
    /// - `id` - ID of the group to add members to
    /// - `users` - List of users to add as group members
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use std::convert::TryFrom;
    /// let group_id = GroupId::try_from("empl412")?;
    /// let user = UserId::try_from("colt")?;
    /// let add_result = sdk.group_add_members(&group_id, &vec![user]).await?;
    /// let new_members: Vec<UserId> = add_result.succeeded().to_vec();
    /// let failures: Vec<GroupAccessEditErr> = add_result.failed().to_vec();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// This operation supports partial success. If the request succeeds, then the resulting `GroupAccessEditResult`
    /// will indicate which additions succeeded and which failed, and it will provide an explanation for each failure.
    fn group_add_members(
        &self,
        id: &GroupId,
        users: &[UserId],
    ) -> impl Future<Output = Result<GroupAccessEditResult>> + Send;

    /// Removes members from a group.
    ///
    /// Returns successful and failed removals.
    ///
    /// # Arguments
    /// - `id` - ID of the group to remove members from
    /// - `revoke_list` - List of users to remove as group members
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use std::convert::TryFrom;
    /// let group_id = GroupId::try_from("empl412")?;
    /// let user = UserId::try_from("colt")?;
    /// let remove_result = sdk.group_remove_members(&group_id, &vec![user]).await?;
    /// let removed_members: Vec<UserId> = remove_result.succeeded().to_vec();
    /// let failures: Vec<GroupAccessEditErr> = remove_result.failed().to_vec();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// This operation supports partial success. If the request succeeds, then the resulting `GroupAccessEditResult`
    /// will indicate which removals succeeded and which failed, and it will provide an explanation for each failure.
    fn group_remove_members(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> impl Future<Output = Result<GroupAccessEditResult>> + Send;

    /// Adds administrators to a group.
    ///
    /// Returns successful and failed additions.
    ///
    /// # Arguments
    /// - `id` - ID of the group to add administrators to
    /// - `users` - List of users to add as group administrators
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use std::convert::TryFrom;
    /// let group_id = GroupId::try_from("empl412")?;
    /// let user = UserId::try_from("colt")?;
    /// let add_result = sdk.group_add_admins(&group_id, &vec![user]).await?;
    /// let new_admins: Vec<UserId> = add_result.succeeded().to_vec();
    /// let failures: Vec<GroupAccessEditErr> = add_result.failed().to_vec();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// This operation supports partial success. If the request succeeds, then the resulting `GroupAccessEditResult`
    /// will indicate which additions succeeded and which failed, and it will provide an explanation for each failure.
    fn group_add_admins(
        &self,
        id: &GroupId,
        users: &[UserId],
    ) -> impl Future<Output = Result<GroupAccessEditResult>> + Send;

    /// Removes administrators from a group.
    ///
    /// Returns successful and failed removals.
    ///
    /// # Arguments
    /// - `id` - ID of the group to remove administrators from
    /// - `revoke_list` - List of users to remove as group administrators
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use std::convert::TryFrom;
    /// let group_id = GroupId::try_from("empl412")?;
    /// let user = UserId::try_from("colt")?;
    /// let remove_result = sdk.group_remove_admins(&group_id, &vec![user]).await?;
    /// let removed_admins: Vec<UserId> = remove_result.succeeded().to_vec();
    /// let failures: Vec<GroupAccessEditErr> = remove_result.failed().to_vec();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// This operation supports partial success. If the request succeeds, then the resulting `GroupAccessEditResult`
    /// will indicate which removals succeeded and which failed, and it will provide an explanation for each failure.
    fn group_remove_admins(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> impl Future<Output = Result<GroupAccessEditResult>> + Send;

    /// Deletes a group.
    ///
    /// A group can be deleted even if it has existing members and administrators.
    ///
    /// **Warning: Deleting a group will prevent its members from decrypting all of the
    /// documents previously encrypted to the group. Caution should be used when deleting groups.**
    ///
    /// # Arguments
    /// `id` - ID of the group to delete
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use std::convert::TryFrom;
    /// let group_id = GroupId::try_from("empl412")?;
    /// let deleted_group_id = sdk.group_delete(&group_id).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn group_delete(&self, id: &GroupId) -> impl Future<Output = Result<GroupId>> + Send;
}

impl GroupOps for crate::IronOxide {
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

        add_optional_timeout(
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
        add_optional_timeout(
            group_api::get_metadata(self.device.auth(), id),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupGetMetadata,
        )
        .await?
    }

    async fn group_list(&self) -> Result<GroupListResult> {
        add_optional_timeout(
            group_api::list(self.device.auth(), None),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupList,
        )
        .await?
    }

    async fn group_update_name(
        &self,
        id: &GroupId,
        name: Option<&GroupName>,
    ) -> Result<GroupMetaResult> {
        add_optional_timeout(
            group_api::update_group_name(self.device.auth(), id, name),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupUpdateName,
        )
        .await?
    }

    async fn group_rotate_private_key(&self, id: &GroupId) -> Result<GroupUpdatePrivateKeyResult> {
        add_optional_timeout(
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

    async fn group_add_members(
        &self,
        id: &GroupId,
        grant_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        add_optional_timeout(
            group_api::group_add_members(
                &self.recrypt,
                self.device.auth(),
                self.device.device_private_key(),
                id,
                grant_list,
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
        add_optional_timeout(
            group_api::group_remove_entity(
                self.device.auth(),
                id,
                revoke_list,
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
        add_optional_timeout(
            group_api::group_add_admins(
                &self.recrypt,
                self.device.auth(),
                self.device.device_private_key(),
                id,
                users,
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
        add_optional_timeout(
            group_api::group_remove_entity(
                self.device.auth(),
                id,
                revoke_list,
                group_api::GroupEntity::Admin,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupRemoveAdmins,
        )
        .await?
    }

    async fn group_delete(&self, id: &GroupId) -> Result<GroupId> {
        add_optional_timeout(
            group_api::group_delete(self.device.auth(), id),
            self.config.sdk_operation_timeout,
            SdkOperation::GroupDelete,
        )
        .await?
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        group::GroupCreateOpts,
        internal::{IronOxideErr, user_api::UserId},
    };

    #[test]
    fn build_group_create_opts_default() {
        let opts = GroupCreateOpts::default();
        assert_eq!(None, opts.id);
        assert_eq!(None, opts.name);
        assert!(opts.add_as_member);
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
        assert!(!std_opts.needs_rotation);
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
        assert_eq!(std_opts.admins, [owner]);
        assert_eq!(std_opts.members, []);
        assert!(std_opts.needs_rotation);
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
