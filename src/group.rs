pub use crate::internal::group_api::{
    GroupAccessEditErr, GroupAccessEditResult, GroupCreateResult, GroupGetResult, GroupId,
    GroupListResult, GroupMetaResult, GroupName,
};
use crate::{
    internal::{group_api, user_api::UserId},
    Result,
};
use std::{collections::HashSet, iter::FromIterator};
use tokio::runtime::current_thread::Runtime;

struct GroupCreateOptsStd {
    id: Option<GroupId>,
    name: Option<GroupName>,
    owner: Option<UserId>,
    admins: Vec<UserId>,
    members: Vec<UserId>,
    users: Vec<UserId>,
    needs_rotation: bool,
}

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
    // None (default) - The creating user will be the owner of the group.
    // Some(UserId) - The provided user will be the owner of the group.
    // Note that the owner must be included in the `admins` list.
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
    /// - `owner` - Note that the owner must be included in the `admins` list.
    ///     - None (default) - The creating user will be the owner of the group.
    ///     - Some(UserId) - The provided user will be the owner of the group.
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

    fn standardize(self, calling_id: &UserId) -> GroupCreateOptsStd {
        // if `owner` contains own id, set to None, as this is the server's default
        let owner = if self.owner == Some(calling_id.clone()) {
            None
        } else {
            self.owner
        };

        // if `add_as_member`, make sure the calling user is in the `members` list
        let standardized_members = if self.add_as_member && !self.members.contains(calling_id) {
            let mut members = self.members.clone();
            members.push(calling_id.clone());
            members
        } else {
            self.members
        };
        let standardized_admins = {
            // if `add_as_admin`, make sure the calling user is in the `admins` list
            let mut admins = if self.add_as_admin && !self.admins.contains(calling_id) {
                let mut admins = self.admins.clone();
                admins.push(calling_id.clone());
                admins
            } else {
                self.admins
            };
            match owner.clone() {
                Some(owner_id) => {
                    // if the owner is specified, make sure they're in the `admins` list
                    if !admins.contains(&owner_id) {
                        admins.push(owner_id)
                    }
                }
                // if the owner is the default (calling user), they should have been added to the
                // admins list by `add_as_admin`. If they aren't it will error later on.
                None => (),
            }
            admins
        };

        // concatenate the vectors of admin and member ids. duplicates will be removed later.
        let all_users = [&standardized_admins[..], &standardized_members[..]].concat();
        let set: HashSet<UserId> = HashSet::from_iter(all_users);
        let users: Vec<UserId> = set.into_iter().collect();

        GroupCreateOptsStd {
            id: self.id,
            name: self.name,
            owner: owner,
            admins: standardized_admins,
            members: standardized_members,
            users: users,
            needs_rotation: self.needs_rotation,
        }
    }
}

impl Default for GroupCreateOpts {
    // Default GroupCreateOpts for common use cases. The user who calls `group_create()` will be the owner of the group
    // as well as an admin and member of the group.
    fn default() -> Self {
        GroupCreateOpts::new(None, None, true, true, None, vec![], vec![], false)
    }
}

pub trait GroupOps {
    /// List all of the groups that the current user is either an admin or member of.
    ///
    /// # Returns
    /// `GroupListResult` List of (abbreviated) metadata about each group the user is a part of.
    fn group_list(&self) -> Result<GroupListResult>;

    /// Create a group. The creating user will become a group admin and by default a group member.
    ///
    /// # Arguments
    /// `group_create_opts` - See `GroupCreateOpts`. Use the `Default` implementation for defaults.
    fn group_create(&self, group_create_opts: &GroupCreateOpts) -> Result<GroupCreateResult>;

    /// Get the full metadata for a specific group given its ID.
    ///
    /// # Arguments
    /// - `id` - Unique ID of the group to retrieve
    ///
    /// # Returns
    /// `GroupMetaResult` with details about the requested group.
    fn group_get_metadata(&self, id: &GroupId) -> Result<GroupGetResult>;

    /// Delete the identified group. Group does not have to be empty of admins/members in order to
    /// delete the group. **Warning: Deletion of a group will cause all documents encrypted to that
    /// group to no longer be decryptable. Caution should be used when deleting groups.**
    ///
    /// # Arguments
    /// `id` - Unique id of group
    ///
    /// # Returns
    /// Deleted group id or error
    fn group_delete(&self, id: &GroupId) -> Result<GroupId>;

    /// Update a group name to a new value or clear its value.
    ///
    /// # Arguments
    /// - `id` - ID of the group to update
    /// - `name` - New name for the group. Provide a Some to update to a new name and a None to clear the name field.
    ///
    /// # Returns
    /// `Result<GroupMetaResult>` Metadata about the group that was updated.
    fn group_update_name(&self, id: &GroupId, name: Option<&GroupName>) -> Result<GroupMetaResult>;

    /// Add the users as members of a group.
    ///
    /// # Arguments
    /// - `id` - ID of the group to add members to
    /// - `users` - The list of users thet will be added to the group as members.
    /// # Returns
    /// GroupAccessEditResult, which contains all the users that were added. It also contains the users that were not added and
    ///   the reason they were not.
    fn group_add_members(&self, id: &GroupId, users: &[UserId]) -> Result<GroupAccessEditResult>;

    /// Remove a list of users as members from the group.
    ///
    /// # Arguments
    /// - `id` - ID of the group to remove members from
    /// - `revoke_list` - List of user IDs to remove as members
    ///
    /// # Returns
    /// `Result<GroupAccessEditResult>` List of users that were removed. Also contains the users that failed to be removed
    ///    and the reason they were not.
    fn group_remove_members(
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
    fn group_add_admins(&self, id: &GroupId, users: &[UserId]) -> Result<GroupAccessEditResult>;

    /// Remove a list of users as admins from the group.
    ///
    /// # Arguments
    /// - `id` - ID of the group
    /// - `revoke_list` - List of user IDs to remove as admins
    ///
    /// # Returns
    /// `Result<GroupAccessEditResult>` List of users that were removed. Also contains the users that failed to be removed
    ///    and the reason they were not.
    fn group_remove_admins(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult>;
}

impl GroupOps for crate::IronOxide {
    fn group_list(&self) -> Result<GroupListResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(group_api::list(self.device.auth(), None))
    }

    fn group_create(&self, opts: &GroupCreateOpts) -> Result<GroupCreateResult> {
        let mut rt = Runtime::new().unwrap();

        let GroupCreateOptsStd {
            id,
            name,
            owner,
            admins,
            members,
            users,
            needs_rotation,
        } = opts.clone().standardize(self.device.auth().account_id());

        rt.block_on(group_api::group_create(
            &self.recrypt,
            self.device.auth(),
            id,
            name,
            owner,
            admins,
            members,
            &users,
            needs_rotation,
        ))
    }

    fn group_get_metadata(&self, id: &GroupId) -> Result<GroupGetResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(group_api::get_metadata(self.device.auth(), id))
    }

    fn group_delete(&self, id: &GroupId) -> Result<GroupId> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(group_api::group_delete(self.device.auth(), id))
    }

    fn group_update_name(&self, id: &GroupId, name: Option<&GroupName>) -> Result<GroupMetaResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(group_api::update_group_name(self.device.auth(), id, name))
    }

    fn group_add_members(
        &self,
        id: &GroupId,
        grant_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(group_api::group_add_members(
            &self.recrypt,
            self.device.auth(),
            self.device.device_private_key(),
            id,
            &grant_list.to_vec(),
        ))
    }

    fn group_remove_members(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(group_api::group_remove_entity(
            self.device.auth(),
            id,
            &revoke_list.to_vec(),
            group_api::GroupEntity::Member,
        ))
    }

    fn group_add_admins(&self, id: &GroupId, users: &[UserId]) -> Result<GroupAccessEditResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(group_api::group_add_admins(
            &self.recrypt,
            self.device.auth(),
            self.device.device_private_key(),
            id,
            &users.to_vec(),
        ))
    }

    fn group_remove_admins(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(group_api::group_remove_entity(
            self.device.auth(),
            id,
            &revoke_list.to_vec(),
            group_api::GroupEntity::Admin,
        ))
    }
}

#[cfg(test)]
mod test {
    use crate::group::GroupCreateOpts;

    #[test]
    fn build_group_create_opts_default() {
        let opts = GroupCreateOpts::default();
        assert_eq!(None, opts.id);
        assert_eq!(None, opts.name);
        assert_eq!(true, opts.add_as_member);
    }
}
