use crate::{
    crypto::transform,
    internal::{
        self,
        group_api::requests::{
            group_get::group_get_request, group_list::GroupListResponse, GroupAdmin,
            GroupUserEditResponse, User,
        },
        rest::json::{AugmentationFactor, EncryptedOnceValue, TransformedEncryptedValue},
        user_api::{self, UserId},
        validate_id, validate_name, DeviceSigningKeyPair, IronOxideErr, PrivateKey, PublicKey,
        RequestAuth, SchnorrSignature, TransformKey, WithKey,
    },
};
use core::convert::identity;
use futures::try_join;
use itertools::{Either, Itertools};
use recrypt::{api::EncryptedValue, prelude::*};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    iter::FromIterator,
};
use time::OffsetDateTime;
use vec1::Vec1;

mod requests;

pub enum GroupEntity {
    Member,
    Admin,
}

/// This is used for GroupCreateOpts that have been standardized with the GroupCreateOpts::standardize function.
/// `add_as_member` and `add_as_admin` have been removed, with the calling user added to the `members` and `admins` lists.
#[derive(Clone)]
pub struct GroupCreateOptsStd {
    pub(crate) id: Option<GroupId>,
    pub(crate) name: Option<GroupName>,
    pub(crate) owner: Option<UserId>,
    pub(crate) admins: Vec1<UserId>,
    pub(crate) members: Vec<UserId>,
    pub(crate) needs_rotation: bool,
}
impl GroupCreateOptsStd {
    /// returns all the users who need their public keys looked up (with duplicates removed).
    pub fn all_users(&self) -> Vec<UserId> {
        let admins_and_members = [&self.admins[..], &self.members[..]].concat();
        let set: HashSet<UserId> = HashSet::from_iter(admins_and_members);
        set.into_iter().collect()
    }
}

/// ID of a group.
///
/// The ID can be validated from a `String` or `&str` using `GroupId::try_from`.
///
/// # Requirements
/// - Must be unique within the group's segment.
/// - Must match the regex `^[a-zA-Z0-9_.$#|@/:;=+'-]+$`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct GroupId(pub(crate) String);
impl GroupId {
    /// Constructs a `GroupId` with no validation. Useful for IDs coming back from the web service.
    pub fn unsafe_from_string(id: String) -> GroupId {
        GroupId(id)
    }
    /// ID of the group
    pub fn id(&self) -> &str {
        &self.0
    }
}
impl recrypt::api::Hashable for GroupId {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}
impl TryFrom<String> for GroupId {
    type Error = IronOxideErr;
    fn try_from(group_id: String) -> Result<Self, Self::Error> {
        group_id.as_str().try_into()
    }
}
impl TryFrom<&str> for GroupId {
    type Error = IronOxideErr;
    fn try_from(group_id: &str) -> Result<Self, Self::Error> {
        validate_id(group_id, "group_id").map(GroupId)
    }
}

/// Name of a group.
///
/// The name can be validated from a `String` or `&str` using `GroupName::try_from`.
///
/// # Requirements
/// - Must be between 1 and 100 characters long.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct GroupName(pub(crate) String);
impl GroupName {
    /// Name of the group
    pub fn name(&self) -> &String {
        &self.0
    }
}
impl TryFrom<String> for GroupName {
    type Error = IronOxideErr;
    fn try_from(group_name: String) -> Result<Self, Self::Error> {
        group_name.as_str().try_into()
    }
}
impl TryFrom<&str> for GroupName {
    type Error = IronOxideErr;
    fn try_from(group_name: &str) -> Result<Self, Self::Error> {
        validate_name(group_name, "group_name").map(GroupName)
    }
}

/// Metadata for each group the user is an admin or a member of.
///
/// Result from [group_list](trait.GroupOps.html#tymethod.group_list).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GroupListResult {
    result: Vec<GroupMetaResult>,
}
impl GroupListResult {
    /// Metadata for each group that the requesting user is an admin or a member of
    pub fn result(&self) -> &Vec<GroupMetaResult> {
        &self.result
    }
}

/// Abbreviated group metadata.
///
/// Result from [GroupListResult.result()](struct.GroupListResult.html#method.result) and
/// [group_update_name](trait.GroupOps.html#tymethod.group_update_name).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GroupMetaResult {
    id: GroupId,
    name: Option<GroupName>,
    group_master_public_key: PublicKey,
    is_admin: bool,
    is_member: bool,
    created: OffsetDateTime,
    updated: OffsetDateTime,
    needs_rotation: Option<bool>,
}
impl GroupMetaResult {
    /// ID of the group
    pub fn id(&self) -> &GroupId {
        &self.id
    }
    /// Name of the group
    pub fn name(&self) -> Option<&GroupName> {
        self.name.as_ref()
    }
    /// `true` if the calling user is a group administrator
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
    /// `true` if the calling user is a group member
    pub fn is_member(&self) -> bool {
        self.is_member
    }
    /// Date and time when the group was created
    pub fn created(&self) -> &OffsetDateTime {
        &self.created
    }
    /// Date and time when the group was last updated
    pub fn last_updated(&self) -> &OffsetDateTime {
        &self.updated
    }
    /// Public key for encrypting to the group
    pub fn group_master_public_key(&self) -> &PublicKey {
        &self.group_master_public_key
    }
    /// Whether the group's private key needs rotation. Can only be accessed by a group administrator.
    /// - `Some(bool)` - Indicates whether the group's private key needs rotation.
    /// - `None` - The calling user does not have permission to view this.
    pub fn needs_rotation(&self) -> Option<bool> {
        self.needs_rotation
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
/// Full metadata for a newly created group.
///
/// Result from [group_create](trait.GroupOps.html#tymethod.group_create).
pub struct GroupCreateResult {
    id: GroupId,
    name: Option<GroupName>,
    group_master_public_key: PublicKey,
    is_admin: bool,
    is_member: bool,
    owner: UserId,
    admins: Vec<UserId>,
    members: Vec<UserId>,
    created: OffsetDateTime,
    updated: OffsetDateTime,
    needs_rotation: Option<bool>,
}
impl GroupCreateResult {
    /// ID of the group
    pub fn id(&self) -> &GroupId {
        &self.id
    }
    /// Name of the group
    pub fn name(&self) -> Option<&GroupName> {
        self.name.as_ref()
    }
    /// Public key for encrypting to the group
    pub fn group_master_public_key(&self) -> &PublicKey {
        &self.group_master_public_key
    }
    /// `true` if the calling user is a group administrator
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
    /// `true` if the calling user is a group member
    pub fn is_member(&self) -> bool {
        self.is_member
    }
    /// Owner of the group
    pub fn owner(&self) -> &UserId {
        &self.owner
    }
    /// List of all group administrators
    pub fn admins(&self) -> &Vec<UserId> {
        self.admins.as_ref()
    }
    /// List of all group members
    pub fn members(&self) -> &Vec<UserId> {
        self.members.as_ref()
    }
    /// Date and time when the group was created
    pub fn created(&self) -> &OffsetDateTime {
        &self.created
    }
    /// Date and time when the group was last updated
    pub fn last_updated(&self) -> &OffsetDateTime {
        &self.updated
    }
    /// Whether the group's private key needs rotation. Can only be accessed by a group administrator.
    /// - `Some(bool)` - Indicates whether the group's private key needs rotation.
    /// - `None` - The calling user does not have permission to view this.
    pub fn needs_rotation(&self) -> Option<bool> {
        self.needs_rotation
    }
}

/// Full metadata for a group.
///
/// Result from [group_get_metadata](trait.GroupOps.html#tymethod.group_get_metadata).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GroupGetResult {
    id: GroupId,
    name: Option<GroupName>,
    group_master_public_key: PublicKey,
    is_admin: bool,
    is_member: bool,
    owner: Option<UserId>,
    admin_list: Option<Vec<UserId>>,
    member_list: Option<Vec<UserId>>,
    created: OffsetDateTime,
    updated: OffsetDateTime,
    needs_rotation: Option<bool>,
    /// not exposed outside of the module
    encrypted_private_key: Option<TransformedEncryptedValue>,
}
impl GroupGetResult {
    /// ID of the group
    pub fn id(&self) -> &GroupId {
        &self.id
    }
    /// Name of the group
    pub fn name(&self) -> Option<&GroupName> {
        self.name.as_ref()
    }
    /// Public key for encrypting to the group
    pub fn group_master_public_key(&self) -> &PublicKey {
        &self.group_master_public_key
    }
    /// `true` if the calling user is a group administrator
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
    /// `true` if the calling user is a group member
    pub fn is_member(&self) -> bool {
        self.is_member
    }
    /// Date and time when the group was created
    pub fn created(&self) -> &OffsetDateTime {
        &self.created
    }
    /// Date and time when the group was last updated
    pub fn last_updated(&self) -> &OffsetDateTime {
        &self.updated
    }
    /// The owner of the group
    ///     - Some(UserId) - The ID of the group owner.
    ///     - None - The calling user is not a member of the group and cannot view the owner.
    pub fn owner(&self) -> Option<&UserId> {
        self.owner.as_ref()
    }
    /// List of all group administrators
    pub fn admin_list(&self) -> Option<&Vec<UserId>> {
        self.admin_list.as_ref()
    }
    /// List of all group members
    pub fn member_list(&self) -> Option<&Vec<UserId>> {
        self.member_list.as_ref()
    }
    /// Whether the group's private key needs rotation. Can only be accessed by a group administrator.
    /// - `Some(bool)` - Indicates whether the group's private key needs rotation.
    /// - `None` - The calling user does not have permission to view this.
    pub fn needs_rotation(&self) -> Option<bool> {
        self.needs_rotation
    }
}

/// A failure when attempting to change a group's member or admin lists.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GroupAccessEditErr {
    user: UserId,
    error: String,
}
impl GroupAccessEditErr {
    fn new(user: UserId, error: String) -> GroupAccessEditErr {
        GroupAccessEditErr { user, error }
    }
    /// The user who was unable to be added/removed from the group.
    pub fn user(&self) -> &UserId {
        &self.user
    }
    /// The error encountered when attempting to add/remove the user from the group.
    pub fn error(&self) -> &String {
        &self.error
    }
}

/// Successful and failed changes to a group's member or admin lists.
///
/// Partial success is supported.
///
/// Result from [group_add_members](trait.GroupOps.html#tymethod.group_add_members), [group_remove_members](trait.GroupOps.html#tymethod.group_remove_members),
/// [group_add_admins](trait.GroupOps.html#tymethod.group_add_admins), and [group_remove_admins](trait.GroupOps.html#tymethod.group_remove_admins).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GroupAccessEditResult {
    succeeded: Vec<UserId>,
    failed: Vec<GroupAccessEditErr>,
}

impl GroupAccessEditResult {
    /// Users whose access was successfully modified
    pub fn succeeded(&self) -> &Vec<UserId> {
        &self.succeeded
    }
    /// Errors resulting from failure to modify a user's access
    pub fn failed(&self) -> &Vec<GroupAccessEditErr> {
        &self.failed
    }
}

// List all of the groups that the requesting user is either a member or admin of
pub async fn list(
    auth: &RequestAuth,
    ids: Option<&[GroupId]>,
) -> Result<GroupListResult, IronOxideErr> {
    let GroupListResponse { result } = match ids {
        Some(group_ids) => requests::group_list::group_limited_list_request(auth, group_ids).await,
        None => requests::group_list::group_list_request(auth).await,
    }?;
    let group_list = result
        .into_iter()
        .map(|g| g.try_into())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GroupListResult { result: group_list })
}

/// Get the keys for groups. The result should be either a failure for a specific UserId (Left) or the id with their public key (Right).
/// The resulting lists will have the same combined size as the incoming list.
/// Calling this with an empty `groups` list will not result in a call to the server.
pub(crate) async fn get_group_keys(
    auth: &RequestAuth,
    groups: &[GroupId],
) -> Result<(Vec<GroupId>, Vec<WithKey<GroupId>>), IronOxideErr> {
    // if there aren't any groups in the list, just return with empty results
    if groups.is_empty() {
        return Ok((vec![], vec![]));
    }

    let cloned_groups: Vec<GroupId> = groups.to_vec();
    let GroupListResult { result } = list(auth, Some(groups)).await?;
    let ids_with_keys =
        result
            .iter()
            .fold(HashMap::with_capacity(groups.len()), |mut acc, group| {
                let public_key = group.group_master_public_key();
                acc.insert(group.id().clone(), public_key.clone());
                acc
            });
    Ok(cloned_groups.into_iter().partition_map(move |group_id| {
        let maybe_public_key = ids_with_keys.get(&group_id).cloned();
        match maybe_public_key {
            Some(public_key) => Either::Right(WithKey {
                id: group_id,
                public_key,
            }),
            None => Either::Left(group_id),
        }
    }))
}

fn check_user_mismatch<T: Eq + std::hash::Hash + std::fmt::Debug, X>(
    desired_users: &[T],
    found_users: HashMap<T, X>,
) -> Result<HashMap<T, X>, IronOxideErr> {
    if found_users.len() != desired_users.len() {
        let desired_users_set: HashSet<&T> = HashSet::from_iter(desired_users);
        let found_users_vec: Vec<T> = found_users.into_iter().map(|(x, _)| x).collect();
        let found_users_set: HashSet<&T> = HashSet::from_iter(&found_users_vec);
        let diff: Vec<&&T> = desired_users_set.difference(&found_users_set).collect();
        Err(IronOxideErr::UserDoesNotExist(format!(
            "Failed to find the following users: {:?}",
            diff
        )))
    } else {
        Ok(found_users)
    }
}

/// Partitions `user_ids_and_keys` into a vector of admins and a vector of members.
/// Also generates TransformKeys for members to prepare for making requests::GroupMembers
fn collect_admin_and_member_info<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    signing_key: &crate::internal::DeviceSigningKeyPair,
    group_priv_key: recrypt::api::PrivateKey,
    admins: Vec1<UserId>,
    members: Vec<UserId>,
    user_ids_and_keys: HashMap<UserId, PublicKey>,
) -> Result<
    (
        Vec<(UserId, PublicKey, TransformKey)>,
        Vec<(UserId, PublicKey)>,
    ),
    IronOxideErr,
> {
    let members_set: HashSet<_> = HashSet::from_iter(&members);
    let admins_set: HashSet<_> = HashSet::from_iter(&admins);
    let mut member_info: Vec<Result<(UserId, PublicKey, TransformKey), IronOxideErr>> = vec![];
    let mut admin_info: Vec<(UserId, PublicKey)> = vec![];
    user_ids_and_keys
        .into_iter()
        .for_each(|(id, user_pub_key)| {
            if members_set.contains(&id) {
                let maybe_transform_key = recrypt.generate_transform_key(
                    &group_priv_key.clone(),
                    &user_pub_key.clone().into(),
                    &signing_key.into(),
                );
                match maybe_transform_key {
                    Ok(member_trans_key) => member_info.push(Ok((
                        id.clone(),
                        user_pub_key.clone(),
                        member_trans_key.into(),
                    ))),
                    Err(err) => member_info.push(Err(err.into())),
                };
            }
            if admins_set.contains(&id) {
                admin_info.push((id, user_pub_key));
            }
        });
    let member_info = member_info.into_iter().collect::<Result<Vec<_>, _>>()?;
    Ok((member_info, admin_info))
}

/// Create a group with the calling user as the group admin.
///
/// # Arguments
/// - `recrypt` - recrypt instance to use for cryptographic operations
/// - `auth` - Auth context details for making API requests. The user associated with this device will be an admin
///     of the newly created group,
/// - `user_master_pub_key` - public key of the user creating this group.
/// - `group_id` - unique id for the group within the segment.
/// - `name` - name for the group. Does not need to be unique.
/// - `members` - list of user ids to add as members of the group.
/// - `needs_rotation` - true if the group private key should be rotated by an admin, else false
pub async fn group_create<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    auth: &RequestAuth,
    group_id: Option<GroupId>,
    name: Option<GroupName>,
    owner: Option<UserId>,
    admins: Vec1<UserId>,
    members: Vec<UserId>,
    users_to_lookup: &[UserId],
    needs_rotation: bool,
) -> Result<GroupCreateResult, IronOxideErr> {
    let user_ids_and_keys = user_api::user_key_list(auth, users_to_lookup).await?;
    // this will occur when one of the UserIds cannot be found
    let user_ids_and_keys = check_user_mismatch(users_to_lookup, user_ids_and_keys)?;
    let (plaintext, group_priv_key, group_pub_key) = transform::gen_group_keys(recrypt)?;
    let (member_info, admin_info) = collect_admin_and_member_info(
        recrypt,
        auth.signing_private_key(),
        group_priv_key,
        admins,
        members,
        user_ids_and_keys,
    )?;

    let group_members: Vec<requests::GroupMember> = member_info
        .into_iter()
        .map(
            |(member_id, member_pub_key, member_trans_key)| requests::GroupMember {
                user_id: member_id,
                transform_key: member_trans_key.into(),
                user_master_public_key: member_pub_key.into(),
            },
        )
        .collect();
    let maybe_group_members = if group_members.is_empty() {
        None
    } else {
        Some(group_members)
    };

    let group_admins: Vec<GroupAdmin> = admin_info
        .into_iter()
        .map(|(admin_id, admin_pub_key)| {
            let encrypted_group_key = recrypt.encrypt(
                &plaintext,
                &admin_pub_key.clone().into(),
                &auth.signing_private_key().into(),
            );
            encrypted_group_key
                .map_err(|e| e.into())
                .and_then(EncryptedOnceValue::try_from)
                .map(|enc_msg| GroupAdmin {
                    encrypted_msg: enc_msg,
                    user: requests::User {
                        user_id: admin_id,
                        user_master_public_key: admin_pub_key.into(),
                    },
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let resp = requests::group_create::group_create(
        auth,
        group_id,
        name,
        group_pub_key,
        owner,
        group_admins,
        maybe_group_members,
        needs_rotation,
    )
    .await?;

    resp.try_into()
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
/// Metadata returned after rotating a group's private key.
///
/// Result from [group_rotate_private_key](trait.GroupOps.html#tymethod.group_rotate_private_key).
pub struct GroupUpdatePrivateKeyResult {
    id: GroupId,
    needs_rotation: bool,
}
impl GroupUpdatePrivateKeyResult {
    /// The ID of the group
    pub fn id(&self) -> &GroupId {
        &self.id
    }
    /// `true` if this group's private key requires additional rotation
    pub fn needs_rotation(&self) -> bool {
        self.needs_rotation
    }
}

/// Maps the successful results of `transform::encrypt_to_with_key()` into a vector of GroupAdmins
fn collect_group_admin_keys(
    admin_info: Vec<(WithKey<UserId>, EncryptedValue)>,
) -> Result<Vec<GroupAdmin>, IronOxideErr> {
    admin_info
        .into_iter()
        .map(|(key_and_id, encrypted_admin_key)| {
            encrypted_admin_key
                .try_into()
                .map(|encrypted_msg| GroupAdmin {
                    user: User {
                        user_id: key_and_id.id,
                        user_master_public_key: key_and_id.public_key.into(),
                    },
                    encrypted_msg,
                })
        })
        .collect()
}

/// Decrypts the group's private key, generates a new private key and plaintext,
/// computes the difference between the old and new private keys, and encrypts the new plaintext to each group admin.
fn generate_aug_and_admins<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    device_signing_key_pair: &DeviceSigningKeyPair,
    encrypted_group_key: EncryptedValue,
    device_private_key: &PrivateKey,
    admin_map: HashMap<UserId, PublicKey>,
) -> Result<(AugmentationFactor, Vec<(WithKey<UserId>, EncryptedValue)>), IronOxideErr> {
    let (_, old_group_private_key) = transform::decrypt_as_private_key(
        recrypt,
        encrypted_group_key,
        device_private_key.recrypt_key(),
    )?;
    let (new_plaintext, aug_factor) =
        internal::gen_plaintext_and_aug_with_retry(recrypt, &old_group_private_key.into())?;
    let (errors, updated_group_admins) = transform::encrypt_to_with_key(
        recrypt,
        &new_plaintext,
        &device_signing_key_pair.into(),
        admin_map
            .into_iter()
            .map(|(id, public_key)| WithKey { id, public_key })
            .collect(),
    );
    errors
        .into_iter()
        .try_for_each(|(_, e)| Err::<(), IronOxideErr>(e.into()))?;
    Ok((aug_factor.into(), updated_group_admins))
}

/// Rotate the group's private key. The public key for the group remains unchanged.
///
/// # Arguments
/// - `recrypt` - recrypt instance to use for cryptographic operations
/// - `auth` - Auth context details for making API requests. The user associated with this device must be an admin of the group.
/// - `group_id` - unique id for the group needing rotation within the segment.
/// - `device_private_key` - user's device private key to use for decrypting the group's private key.
pub async fn group_rotate_private_key<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    auth: &RequestAuth,
    group_id: &GroupId,
    device_private_key: &PrivateKey,
) -> Result<GroupUpdatePrivateKeyResult, IronOxideErr> {
    let group_info = group_get_request(auth, group_id).await?;
    let encrypted_group_key = group_info
        .encrypted_private_key
        .ok_or_else(|| IronOxideErr::NotGroupAdmin(group_id.to_owned()))?;
    let admins = group_info
        .admin_ids
        .ok_or_else(|| IronOxideErr::NotGroupAdmin(group_id.to_owned()))?;
    let found_admins = user_api::user_key_list(auth, &admins).await?;
    let admin_info = check_user_mismatch(&admins, found_admins)?;
    let (aug_factor, updated_group_admins) = generate_aug_and_admins(
        recrypt,
        auth.signing_private_key(),
        encrypted_group_key.try_into()?,
        device_private_key,
        admin_info,
    )?;
    let request_admins = collect_group_admin_keys(updated_group_admins)?;

    requests::group_update_private_key::update_private_key(
        auth,
        group_id,
        group_info.current_key_id,
        request_admins,
        aug_factor,
    )
    .await
    .map(|resp| resp.into())
}

/// Get the metadata for a group given its ID
pub async fn get_metadata(
    auth: &RequestAuth,
    id: &GroupId,
) -> Result<GroupGetResult, IronOxideErr> {
    let resp = requests::group_get::group_get_request(auth, id).await?;
    resp.try_into()
}

///Delete the provided group given its ID
pub async fn group_delete(auth: &RequestAuth, group_id: &GroupId) -> Result<GroupId, IronOxideErr> {
    requests::group_delete::group_delete_request(auth, group_id)
        .await
        .map(|resp| resp.id)
}

/// Add the users as members of a group.
///
/// # Arguments
/// - `recrypt` - recrypt instance to use for cryptographic operations
/// - `auth` - Auth context details for making API requests. The user associated with this device must be an admin of the group.
/// - `group_id` - unique id for the group within the segment.
/// - `users` - The list of users that will be added to the group as members.
///
/// # Returns
/// GroupAccessEditResult, which contains all the users that were added. It also contains the users that were not added and
///   the reason they were not.
pub async fn group_add_members<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    auth: &RequestAuth,
    device_private_key: &PrivateKey,
    group_id: &GroupId,
    users: &[UserId],
) -> Result<GroupAccessEditResult, IronOxideErr> {
    let (group_get, (mut acc_fails, successes)) =
        try_join!(get_metadata(auth, group_id), get_user_keys(auth, users))?;
    //At this point the acc_fails list is just the key fetch failures. We append to it as we go.
    let encrypted_group_key = group_get
        .encrypted_private_key
        .ok_or_else(|| IronOxideErr::NotGroupAdmin(group_id.clone()))?;
    let (plaintext, _) = transform::decrypt_as_private_key(
        recrypt,
        encrypted_group_key.try_into()?,
        device_private_key.recrypt_key(),
    )?;
    let group_private_key = recrypt.derive_private_key(&plaintext);
    let recrypt_schnorr_sig = recrypt.schnorr_sign(
        &group_private_key,
        &group_get.group_master_public_key.into(),
        group_id,
    );
    let (mut transform_fails, transform_success) = generate_transform_for_keys(
        recrypt,
        &group_private_key,
        &auth.signing_private_key().into(),
        successes,
    );
    acc_fails.append(&mut transform_fails);
    let (schnorr_sig, acc_fails, transforms_to_send) = (
        SchnorrSignature(recrypt_schnorr_sig),
        acc_fails,
        transform_success,
    );
    //Now actually add the members that we have transform keys for.
    //acc_fails is currently the transform generation fails and the key fetch failures.
    requests::group_add_member::group_add_member_request(
        auth,
        group_id,
        transforms_to_send
            .into_iter()
            .map(|(user_id, pub_key, transform)| (user_id, pub_key.into(), transform.into()))
            .collect(),
        schnorr_sig,
    )
    .await
    .map(|response| group_access_api_response_to_result(acc_fails, response))
}

/// Add the users as admins of a group.
///
/// # Arguments
/// - `recrypt` - recrypt instance to use for cryptographic operations
/// - `auth` - Auth context details for making API requests. The user associated with this device must be an admin of the group.
/// - `group_id` - unique id for the group within the segment.
/// - `users` - The list of users that will be added to the group as admins.
///
/// # Returns
/// GroupAccessEditResult, which contains all the users that were added. It also contains the users that were not added and
///   the reason they were not.
pub async fn group_add_admins<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    auth: &RequestAuth,
    device_private_key: &PrivateKey,
    group_id: &GroupId,
    users: &[UserId],
) -> Result<GroupAccessEditResult, IronOxideErr> {
    let (group_get, (mut acc_fails, successes)) =
        try_join!(get_metadata(auth, group_id), get_user_keys(auth, users))?;
    //At this point the acc_fails list is just the key fetch failures. We append to it as we go.
    let encrypted_group_key = group_get
        .encrypted_private_key
        .ok_or_else(|| IronOxideErr::NotGroupAdmin(group_id.clone()))?;
    let (plaintext, _) = transform::decrypt_as_private_key(
        recrypt,
        encrypted_group_key.try_into()?,
        device_private_key.recrypt_key(),
    )?;
    let private_group_key = recrypt.derive_private_key(&plaintext);
    let recrypt_schnorr_sig = recrypt.schnorr_sign(
        &private_group_key,
        &group_get.group_master_public_key.into(),
        group_id,
    );
    let (recrypt_errors, transform_success) = transform::encrypt_to_with_key(
        recrypt,
        &plaintext,
        &auth.signing_private_key().into(),
        successes,
    );
    let mut transform_fails = recrypt_errors
        .into_iter()
        .map(|(WithKey { id: user_id, .. }, _)| GroupAccessEditErr {
            user: user_id,
            error: "Transform key could not be generated.".to_string(),
        })
        .collect();
    acc_fails.append(&mut transform_fails);
    let (schnorr_sig, acc_fails, admin_keys_to_send) = (
        SchnorrSignature(recrypt_schnorr_sig),
        acc_fails,
        transform_success,
    );
    //acc_fails is currently the transform generation fails and the key fetch failures.
    requests::group_add_admin::group_add_admin_request(
        auth,
        group_id,
        collect_group_admin_keys(admin_keys_to_send)?,
        schnorr_sig,
    )
    .await
    .map(|response| group_access_api_response_to_result(acc_fails, response))
}

///This is a thin wrapper that's just mapping the errors into the type we need for add member and add admin
async fn get_user_keys(
    auth: &RequestAuth,
    users: &[UserId],
) -> Result<(Vec<GroupAccessEditErr>, Vec<WithKey<UserId>>), IronOxideErr> {
    let (failed_ids, succeeded_ids) = user_api::get_user_keys(auth, users).await?;
    let failed_ids_result = failed_ids
        .into_iter()
        .map(|user| GroupAccessEditErr::new(user, "User does not exist".to_string()))
        .collect::<Vec<_>>();
    Ok((failed_ids_result, succeeded_ids))
}

///Map the edit response into the edit result. If there are other failures, we'll append the errors in `edit_resp` to them.
fn group_access_api_response_to_result(
    mut other_fails: Vec<GroupAccessEditErr>,
    edit_resp: requests::GroupUserEditResponse,
) -> GroupAccessEditResult {
    let mut fails_from_req = edit_resp
        .failed_ids
        .into_iter()
        .map(|f| GroupAccessEditErr::new(f.user_id, f.error_message))
        .collect();
    other_fails.append(&mut fails_from_req);
    GroupAccessEditResult {
        succeeded: edit_resp
            .succeeded_ids
            .into_iter()
            .map(|r| r.user_id)
            .collect(),
        failed: other_fails,
    }
}

// Update a group's name. Value can be updated to either a new name with a Some or the name value can be cleared out
// by providing a None.
pub async fn update_group_name(
    auth: &RequestAuth,
    id: &GroupId,
    name: Option<&GroupName>,
) -> Result<GroupMetaResult, IronOxideErr> {
    let resp = requests::group_update::group_update_request(auth, id, name).await?;
    resp.try_into()
}

/// Remove the provided list of users as either members or admins (based on the entity_type) from the provided group ID. The
/// request and response format of these two operations are identical which is why we have a single method for it.
pub async fn group_remove_entity(
    auth: &RequestAuth,
    id: &GroupId,
    users: &[UserId],
    entity_type: GroupEntity,
) -> Result<GroupAccessEditResult, IronOxideErr> {
    let GroupUserEditResponse {
        succeeded_ids,
        failed_ids,
    } = requests::group_remove_entity::remove_entity_request(auth, id, users, entity_type).await?;
    Ok(GroupAccessEditResult {
        succeeded: succeeded_ids.into_iter().map(|user| user.user_id).collect(),
        failed: failed_ids
            .into_iter()
            .map(|fail| GroupAccessEditErr::new(fail.user_id, fail.error_message))
            .collect(),
    })
}

///A stripped down version of this could be put in `transform.rs`, but since it was inconvenient to do the type mapping afterwards
///I just moved it to here so I could keep all of the mapping code together.
fn generate_transform_for_keys<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    from_private: &recrypt::api::PrivateKey,
    signing_keys: &recrypt::api::SigningKeypair,
    users: Vec<WithKey<UserId>>,
) -> (
    Vec<GroupAccessEditErr>,
    Vec<(UserId, PublicKey, TransformKey)>,
) {
    //Generate transform keys for all the users we can. If they error, we'll put them in the acc_fails list.
    let transform_results_iter = users.into_iter().map(
        move |WithKey {
                  id: user_id,
                  public_key,
              }| {
            let group_to_user_transform = recrypt.generate_transform_key(
                from_private,
                &public_key.clone().into(),
                signing_keys,
            );
            match group_to_user_transform {
                Ok(recrypt_transform_key) => {
                    Either::Right((user_id, public_key, TransformKey(recrypt_transform_key)))
                }
                Err(_) => Either::Left(GroupAccessEditErr::new(
                    user_id,
                    "Transform key could not be generated.".to_string(),
                )),
            }
        },
    );
    //Now split the transform failures from the successes, this is done as a separate step
    //because we can't mutate recrypt in a partition_map call.
    transform_results_iter.partition_map(identity)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use galvanic_assert::*;
    use vec1::vec1;

    pub fn create_group_meta_result(
        id: GroupId,
        name: Option<GroupName>,
        group_master_public_key: PublicKey,
        is_admin: bool,
        is_member: bool,
        created: OffsetDateTime,
        updated: OffsetDateTime,
        needs_rotation: Option<bool>,
    ) -> GroupMetaResult {
        GroupMetaResult {
            id,
            name,
            group_master_public_key,
            is_admin,
            is_member,
            created,
            updated,
            needs_rotation,
        }
    }

    #[test]
    fn group_id_validate_good() {
        let group_id1 = "a_fo_real_good_group_id$";
        let group_id2 = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        assert_eq!(
            GroupId(group_id1.to_string()),
            GroupId::try_from(group_id1).unwrap()
        );
        assert_eq!(
            GroupId(group_id2.to_string()),
            GroupId::try_from(group_id2).unwrap()
        )
    }

    #[test]
    fn group_id_rejects_invalid() {
        let group_id1 = GroupId::try_from("not a good ID!");
        let group_id2 = GroupId::try_from("!!");
        let group_id3 = GroupId::try_from("01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567891");

        assert_that!(
            &group_id1.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(
            &group_id2.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(
            &group_id3.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
    }

    #[test]
    fn group_id_rejects_empty() {
        let group_id = GroupId::try_from("");
        assert_that!(&group_id, is_variant!(Err));
        assert_that!(
            &group_id.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );

        let group_id = GroupId::try_from("\n \t  ");
        assert_that!(&group_id, is_variant!(Err));
        assert_that!(
            &group_id.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
    }
    #[test]
    fn group_id_hashable_known_value() {
        use recrypt::api::Hashable;
        let string = "a_fo_real_good_group_id$";
        let bytes = b"a_fo_real_good_group_id$";
        let group_id: GroupId = string.try_into().unwrap();
        assert_eq!(group_id.to_bytes(), bytes.to_vec())
    }

    #[test]
    fn group_name_rejects_empty() {
        let group_name = GroupName::try_from("");
        assert_that!(&group_name, is_variant!(Err));
        assert_that!(
            &group_name.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );

        let group_name = GroupName::try_from("\n \t  ");
        assert_that!(&group_name, is_variant!(Err));
        assert_that!(
            &group_name.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
    }

    #[test]
    fn group_name_rejects_too_long() {
        let group_name = GroupName::try_from("01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567891");

        assert_that!(
            &group_name.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        )
    }

    #[test]
    fn check_user_mismatch_test() -> Result<(), String> {
        let user1 = UserId::unsafe_from_string("user1".to_string());
        let user2 = UserId::unsafe_from_string("user2".to_string());
        let desired_users = vec![user1.clone(), user2];
        let mut found_users = HashMap::new();
        found_users.insert(user1, "test");
        let err = check_user_mismatch(&desired_users, found_users)
            .expect_err("check_user_mismatch should return error.");
        let err_msg = match err {
            IronOxideErr::UserDoesNotExist(msg) => Ok(msg),
            _ => Err("Wrong type of error. Should never happen."),
        }?;
        assert_eq!(
            err_msg,
            "Failed to find the following users: [UserId(\"user2\")]"
        );
        Ok(())
    }

    #[test]
    fn collect_admin_and_member_info_test() -> Result<(), IronOxideErr> {
        let recrypt = recrypt::api::Recrypt::new();
        let signing_key =
            crate::internal::DeviceSigningKeyPair::from(recrypt.generate_ed25519_key_pair());
        let (group_priv_key, _) = recrypt.generate_key_pair()?;
        let user1 = UserId::unsafe_from_string("user1".to_string());
        let user2 = UserId::unsafe_from_string("user2".to_string());
        let user3 = UserId::unsafe_from_string("user3".to_string());
        let admins_vec = vec1![user1.clone()];
        let members_vec = vec![user1, user2, user3];

        let user_ids_and_keys = members_vec
            .clone()
            .into_iter()
            .map(|id| {
                recrypt
                    .generate_key_pair()
                    .map_err(|e| e.into())
                    .map(|(_, key)| (id, key.into()))
            })
            .collect::<Result<HashMap<UserId, PublicKey>, IronOxideErr>>()?;

        let (member_info, admin_info) = collect_admin_and_member_info(
            &recrypt,
            &signing_key,
            group_priv_key,
            admins_vec.clone(),
            members_vec.clone(),
            user_ids_and_keys,
        )?;
        assert_eq!(member_info.len(), members_vec.len());
        assert_eq!(admin_info.len(), admins_vec.len());
        Ok(())
    }

    #[test]
    fn collect_admin_and_member_info_empty_members() -> Result<(), IronOxideErr> {
        let recrypt = recrypt::api::Recrypt::new();
        let signing_key =
            crate::internal::DeviceSigningKeyPair::from(recrypt.generate_ed25519_key_pair());
        let (group_priv_key, pub_key) = recrypt.generate_key_pair()?;
        let user1 = UserId::unsafe_from_string("user1".to_string());
        let mut user_ids_and_keys = HashMap::new();
        user_ids_and_keys.insert(user1.clone(), pub_key.into());

        let (member_info, admin_info) = collect_admin_and_member_info(
            &recrypt,
            &signing_key,
            group_priv_key,
            vec1![user1],
            vec![],
            user_ids_and_keys,
        )?;
        assert!(member_info.is_empty());
        assert_eq!(admin_info.len(), 1);
        Ok(())
    }

    #[test]
    fn augment_admin_list() -> Result<(), IronOxideErr> {
        let recrypt = recrypt::api::Recrypt::new();
        // hashmap of generated ids and public keys to be the pre-rotation admins
        let mut admin_map: HashMap<UserId, (PrivateKey, PublicKey)> = HashMap::new();
        for _ in 0..10 {
            let (priv_key, pub_key) = recrypt.generate_key_pair()?;
            admin_map.insert(
                uuid::Uuid::new_v4().to_string().try_into()?,
                (priv_key.into(), pub_key.into()),
            );
        }
        let (priv_key, pub_key) = recrypt.generate_key_pair()?;
        let plaintext = recrypt.gen_plaintext();
        let signing_key = recrypt.generate_ed25519_key_pair();
        let encrypted_value = recrypt.encrypt(&plaintext, &pub_key, &signing_key)?;
        // creates an augmentation factor and encrypts the plaintext to the admins
        let (aug, new_admins) = generate_aug_and_admins(
            &recrypt,
            &signing_key.into(),
            encrypted_value,
            &priv_key.into(),
            admin_map
                .clone()
                .into_iter()
                .map(|(id, (_, pu))| (id, pu))
                .collect(),
        )?;
        // decrypted plaintexts for each admins using their private keys
        // this should be the same for all admins
        let admin_plaintexts: Vec<_> = new_admins
            .into_iter()
            .map(|(with_key, enc)| {
                recrypt
                    .decrypt(enc, admin_map.get(&with_key.id).unwrap().0.recrypt_key())
                    .unwrap()
            })
            .collect();
        let first_admin = admin_plaintexts.first().unwrap();
        assert!(admin_plaintexts
            .iter()
            .all(|text| text.bytes()[..] == first_admin.bytes()[..]));

        // using the first admin to test, verify that the augmentation factor plus the
        // decrypted plaintext's private key equals the group's private key
        let dec_private = recrypt.derive_private_key(first_admin);
        let group_private = recrypt.derive_private_key(&plaintext);
        let aug_private: PrivateKey = aug.0.as_slice().try_into()?;
        let dec_plus_aug = dec_private.augment_plus(aug_private.recrypt_key());

        assert_eq!(dec_plus_aug.bytes(), group_private.bytes());

        Ok(())
    }
}
