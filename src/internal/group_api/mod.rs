use crate::{
    crypto::transform,
    internal::{
        group_api::requests::{group_list::GroupListResponse, GroupUserEditResponse},
        rest::json::{EncryptedOnceValue, TransformedEncryptedValue},
        user_api::{self, UserId},
        validate_id, validate_name, IronOxideErr, PrivateKey, PublicKey, RequestAuth,
        SchnorrSignature, TransformKey, WithKey,
    },
};
use chrono::{DateTime, Utc};
use core::convert::identity;
use futures::{future::err, prelude::*};
use itertools::{Either, Itertools};
use recrypt::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    iter::FromIterator,
};
mod requests;

pub enum GroupEntity {
    Member,
    Admin,
}

// This is used for GroupCreateOpts that have been standardized with the GroupCreateOpts::standardize function.
// `add_as_member` and `add_as_admin` have been removed, with the calling user added to the `members` and `admins` lists.
#[derive(Clone)]
pub struct GroupCreateOptsStd {
    pub(crate) id: Option<GroupId>,
    pub(crate) name: Option<GroupName>,
    pub(crate) owner: Option<UserId>,
    pub(crate) admins: Vec<UserId>,
    pub(crate) members: Vec<UserId>,
    pub(crate) needs_rotation: bool,
}
impl GroupCreateOptsStd {
    // returns all the users who need their public keys looked up with duplicates removed.
    pub fn all_users(&self) -> Vec<UserId> {
        let admins_and_members = [&self.admins[..], &self.members[..]].concat();
        let set: HashSet<UserId> = HashSet::from_iter(admins_and_members);
        set.into_iter().collect()
    }
}

/// Group ID. Unique within a segment. Must match the regex `^[a-zA-Z0-9_.$#|@/:;=+'-]+$`
#[derive(Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Clone)]
pub struct GroupId(pub(crate) String);
impl GroupId {
    pub fn id(&self) -> &str {
        &self.0
    }

    /// Create a GroupId from a string with no validation. Useful for ids coming back from the web service.
    pub fn unsafe_from_string(id: String) -> GroupId {
        GroupId(id)
    }
}
impl recrypt::api::Hashable for GroupId {
    fn to_bytes(self: &Self) -> Vec<u8> {
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

/// Group's user-assigned name. (non-unique)
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct GroupName(pub(crate) String);
impl GroupName {
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

/// List of (abbreviated) groups for which the requesting user is either an admin or member.
#[derive(Debug)]
pub struct GroupListResult {
    result: Vec<GroupMetaResult>,
}
impl GroupListResult {
    pub fn new(metas: Vec<GroupMetaResult>) -> GroupListResult {
        GroupListResult { result: metas }
    }

    pub fn result(&self) -> &Vec<GroupMetaResult> {
        &self.result
    }
}
/// Abbreviated group information.
#[derive(Clone, Debug)]
pub struct GroupMetaResult {
    id: GroupId,
    name: Option<GroupName>,
    group_master_public_key: PublicKey,
    is_admin: bool,
    is_member: bool,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
    needs_rotation: Option<bool>,
}
impl GroupMetaResult {
    /// A single document grant/revoke failure for a user or group.
    pub fn id(&self) -> &GroupId {
        &self.id
    }
    /// Name of the group
    pub fn name(&self) -> Option<&GroupName> {
        self.name.as_ref()
    }
    /// true if the calling user is a group administrator
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
    /// true if the calling user is a group member
    pub fn is_member(&self) -> bool {
        self.is_member
    }
    /// Date and time of when the group was created
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }
    /// Date and time of when the group was last updated
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.updated
    }
    /// Public key for encrypting to the group
    pub fn group_master_public_key(&self) -> &PublicKey {
        &self.group_master_public_key
    }
    /// `Some(boolean)` indicating if the group needs rotation if the calling user is a group admin.
    /// `None` if the calling user is not a group admin.
    pub fn needs_rotation(&self) -> Option<bool> {
        self.needs_rotation
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupCreateResult {
    id: GroupId,
    name: Option<GroupName>,
    group_master_public_key: PublicKey,
    is_admin: bool,
    is_member: bool,
    owner: UserId,
    admins: Vec<UserId>,
    members: Vec<UserId>,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
    needs_rotation: Option<bool>,
}
impl GroupCreateResult {
    /// A single document grant/revoke failure for a user or group.
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
    /// true if the calling user is a group administrator
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
    /// true if the calling user is a group member
    pub fn is_member(&self) -> bool {
        self.is_member
    }
    /// owner of the group
    pub fn owner(&self) -> &UserId {
        &self.owner
    }
    /// List of all group admins. Group admins can change group membership.
    pub fn admins(&self) -> &Vec<UserId> {
        self.admins.as_ref()
    }
    /// List of group members. Members of a group can decrypt values encrypted to the group.
    pub fn members(&self) -> &Vec<UserId> {
        self.members.as_ref()
    }
    /// Date and time of when the group was created
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }
    /// Date and time of when the group was last updated
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.updated
    }
    /// `Some(boolean)` indicating if the group needs rotation if the calling user is a group admin.
    /// `None` if the calling user is not a group admin.
    pub fn needs_rotation(&self) -> Option<bool> {
        self.needs_rotation
    }
}
/// Group information.
#[derive(Debug)]
pub struct GroupGetResult {
    id: GroupId,
    name: Option<GroupName>,
    group_master_public_key: PublicKey,
    is_admin: bool,
    is_member: bool,
    owner: Option<UserId>,
    admin_list: Option<Vec<UserId>>,
    member_list: Option<Vec<UserId>>,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
    needs_rotation: Option<bool>,
    pub(crate) encrypted_private_key: Option<TransformedEncryptedValue>,
}
impl GroupGetResult {
    /// unique id of the group (within the segment)
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
    /// true if the calling user is a group administrator
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
    /// true if the calling user is a group member
    pub fn is_member(&self) -> bool {
        self.is_member
    }
    /// Date and time of when the group was created
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }
    /// Date and time of when the group was last updated
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.updated
    }
    /// The owner of the group. The group owner cannot be removed as an admin.
    ///     Some(UserId) - The id of the group owner.
    ///     None - The calling user is not a member of the group and cannot view the owner.
    pub fn owner(&self) -> Option<&UserId> {
        self.owner.as_ref()
    }
    /// List of all group admins. Group admins can change group membership.
    pub fn admin_list(&self) -> Option<&Vec<UserId>> {
        self.admin_list.as_ref()
    }
    /// List of group members. Members of a group can decrypt values encrypted to the group.
    pub fn member_list(&self) -> Option<&Vec<UserId>> {
        self.member_list.as_ref()
    }
    /// `Some(boolean)` indicating if the group needs rotation if the calling user is a group admin.
    /// `None` if the calling user is not a group admin.
    pub fn needs_rotation(&self) -> Option<bool> {
        self.needs_rotation
    }
}

/// Failure to make the requested change to a group's membership or administrators.
#[derive(Debug, Clone)]
pub struct GroupAccessEditErr {
    user: UserId,
    error: String,
}

impl GroupAccessEditErr {
    pub(crate) fn new(user: UserId, error: String) -> GroupAccessEditErr {
        GroupAccessEditErr { user, error }
    }
    pub fn user(&self) -> &UserId {
        &self.user
    }
    pub fn error(&self) -> &String {
        &self.error
    }
}

/// Result from requesting changes to a group's membership or administrators. Partial success is supported.
#[derive(Debug)]
pub struct GroupAccessEditResult {
    succeeded: Vec<UserId>,
    failed: Vec<GroupAccessEditErr>,
}

impl GroupAccessEditResult {
    /// Users whose access could not be modified.
    pub fn failed(&self) -> &Vec<GroupAccessEditErr> {
        &self.failed
    }
    /// Users whose access was modified.
    pub fn succeeded(&self) -> &Vec<UserId> {
        &self.succeeded
    }
}

// List all of the groups that the requesting user is either a member or admin of
pub fn list<'a>(
    auth: &'a RequestAuth,
    ids: Option<&'a Vec<GroupId>>,
) -> impl Future<Item = GroupListResult, Error = IronOxideErr> + 'a {
    let resp = match ids {
        Some(group_ids) => requests::group_list::group_limited_list_request(auth, &group_ids),
        None => requests::group_list::group_list_request(auth),
    };

    resp.and_then(|GroupListResponse { result }| {
        let group_list = result
            .into_iter()
            .map(|g| g.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(GroupListResult::new(group_list))
    })
}

/// Get the keys for groups. The result should be either a failure for a specific UserId (Left) or the id with their public key (Right).
/// The resulting lists will have the same combined size as the incoming list.
/// Calling this with an empty `groups` list will not result in a call to the server.
pub(crate) fn get_group_keys<'a>(
    auth: &'a RequestAuth,
    groups: &'a Vec<GroupId>,
) -> Box<dyn Future<Item = (Vec<GroupId>, Vec<WithKey<GroupId>>), Error = IronOxideErr> + 'a> {
    // if there aren't any groups in the list, just return with empty results
    if groups.len() == 0 {
        return Box::new(futures::future::ok((vec![], vec![])));
    }

    let cloned_groups: Vec<GroupId> = groups.clone();
    let fetch_groups = list(auth, Some(&groups));
    Box::new(
        fetch_groups
            .map(move |GroupListResult { result }| {
                result
                    .iter()
                    .fold(HashMap::with_capacity(groups.len()), |mut acc, group| {
                        let public_key = group.group_master_public_key();
                        acc.insert(group.id().clone(), public_key.clone());
                        acc
                    })
            })
            .map(move |ids_with_keys| {
                cloned_groups.into_iter().partition_map(move |group_id| {
                    let maybe_public_key = ids_with_keys.get(&group_id).cloned();
                    match maybe_public_key {
                        Some(public_key) => Either::Right(WithKey {
                            id: group_id,
                            public_key,
                        }),
                        None => Either::Left(group_id),
                    }
                })
            }),
    )
}

fn compare_users(
    desired_users: &Vec<UserId>,
    found_users: HashMap<UserId, PublicKey>,
) -> futures::future::FutureResult<
    (
        PublicKey,
        Option<Vec<requests::GroupMember>>,
        Vec<requests::GroupAdmin>,
    ),
    IronOxideErr,
> {
    let desired_users_set: HashSet<UserId> = HashSet::from_iter(desired_users.clone());
    let found_users_set: HashSet<UserId> = found_users.into_iter().map(|(x, _)| x).collect();
    let diff: Vec<&UserId> = desired_users_set.difference(&found_users_set).collect();
    err(IronOxideErr::UserDoesNotExist(format!(
        "Failed to find the following users: {:?}",
        diff
    )))
}

fn collect_admin_and_member_info<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    auth: &RequestAuth,
    group_priv_key: recrypt::api::PrivateKey,
    admins: Vec<UserId>,
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
            // only calculate transform key if they're to be a member
            if members_set.contains(&id) {
                let maybe_transform_key = recrypt.generate_transform_key(
                    &group_priv_key.clone().into(),
                    &user_pub_key.clone().into(),
                    &auth.signing_private_key().into(),
                );
                match maybe_transform_key {
                    Ok(member_trans_key) => member_info.push(Ok((
                        id.clone(),
                        user_pub_key.clone(),
                        member_trans_key.into(),
                    ))),
                    Err(_) => (),
                };
            }
            if admins_set.contains(&id) {
                admin_info.push((id, user_pub_key));
            }
        });
    let test: Result<Vec<(UserId, PublicKey, TransformKey)>, IronOxideErr> =
        member_info.into_iter().collect();
    let test = test?;
    Ok((test, admin_info))
}

/// Create a group with the calling user as the group admin.
///
/// # Arguments
/// `recrypt` - recrypt instance to use for cryptographic operations
/// `auth` - Auth context details for making API requests. The user associated with this device will be an admin
///     of the newly created group,
/// `user_master_pub_key` - public key of the user creating this group.
/// `group_id` - unique id for the group within the segment.
/// `name` - name for the group. Does not need to be unique.
/// `members` - list of user ids to add as members of the group.
/// `needs_rotation` - true if the group private key should be rotated by an admin, else false
pub fn group_create<'a, CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    auth: &'a RequestAuth,
    group_id: Option<GroupId>,
    name: Option<GroupName>,
    owner: Option<UserId>,
    admins: Vec<UserId>,
    members: Vec<UserId>,
    users_to_lookup: &'a Vec<UserId>,
    needs_rotation: bool,
) -> impl Future<Item = GroupCreateResult, Error = IronOxideErr> + 'a {
    user_api::user_key_list(auth, users_to_lookup)
        .and_then(move |user_ids_and_keys| {
            // this will occur when one of the UserIds cannot be found
            if user_ids_and_keys.len() != users_to_lookup.len() {
                compare_users(users_to_lookup, user_ids_and_keys)
            } else {
                transform::gen_group_keys(recrypt)
                    .and_then(move |(plaintext, group_priv_key, group_pub_key)| {
                        let (member_info, admin_info) = collect_admin_and_member_info(
                            recrypt,
                            auth,
                            group_priv_key,
                            admins,
                            members,
                            user_ids_and_keys,
                        )?;

                        let group_members: Vec<requests::GroupMember> = member_info
                            .into_iter()
                            .map(|(member_id, member_pub_key, member_trans_key)| {
                                requests::GroupMember {
                                    user_id: member_id,
                                    transform_key: member_trans_key.into(),
                                    user_master_public_key: member_pub_key.into(),
                                }
                            })
                            .collect();
                        let maybe_group_members = if group_members.is_empty() {
                            None
                        } else {
                            Some(group_members)
                        };

                        let group_admins_result: Result<Vec<requests::GroupAdmin>, _> = admin_info
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
                                    .map(|enc_msg| requests::GroupAdmin {
                                        encrypted_msg: enc_msg,
                                        user: requests::User {
                                            user_id: admin_id,
                                            user_master_public_key: admin_pub_key.into(),
                                        },
                                    })
                            })
                            .collect();
                        let group_admins = group_admins_result?;

                        Ok((group_pub_key, maybe_group_members, group_admins))
                    })
                    .into_future()
            }
        })
        .and_then(move |(group_pub_key, member_vec, admin_vec)| {
            requests::group_create::group_create(
                &auth,
                group_id,
                name,
                group_pub_key,
                owner,
                admin_vec,
                member_vec,
                needs_rotation,
            )
        })
        .and_then(move |resp| resp.try_into())
}

/// Get the metadata for a group given its ID
pub fn get_metadata<'a>(
    auth: &'a RequestAuth,
    id: &GroupId,
) -> impl Future<Item = GroupGetResult, Error = IronOxideErr> + 'a {
    requests::group_get::group_get_request(auth, id).and_then(|resp| resp.try_into())
}

//Delete the provided group given it's ID
pub fn group_delete<'a>(
    auth: &'a RequestAuth,
    group_id: &GroupId,
) -> impl Future<Item = GroupId, Error = IronOxideErr> + 'a {
    requests::group_delete::group_delete_request(auth, &group_id)
        .and_then(|resp| resp.id.try_into())
}

/// Add the users as members of a group.
///
/// # Arguments
/// `recrypt` - recrypt instance to use for cryptographic operations
/// `auth` - Auth context details for making API requests. The user associated with this device must be an admin of the group.
/// `group_id` - unique id for the group within the segment.
/// `users` - The list of users thet will be added to the group as members.
/// # Returns GroupAccessEditResult, which contains all the users that were added. It also contains the users that were not added and
///   the reason they were not.
pub fn group_add_members<'a, CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    auth: &'a RequestAuth,
    device_private_key: &'a PrivateKey,
    group_id: &'a GroupId,
    users: &'a Vec<UserId>,
) -> impl Future<Item = GroupAccessEditResult, Error = IronOxideErr> + 'a {
    get_metadata(auth, group_id)
        .join(get_user_keys(auth, users))
        //At this point the acc_fails list is just the key fetch failures. We append to it as we go.
        .and_then(move |(group_get, (mut acc_fails, successes))| {
            let encrypted_group_key = group_get
                .encrypted_private_key
                .ok_or(IronOxideErr::NotGroupAdmin(group_id.clone()))?;
            let (plaintext, _) = transform::decrypt_plaintext(
                &recrypt,
                encrypted_group_key.try_into()?,
                &device_private_key.recrypt_key(),
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
            Ok((
                SchnorrSignature(recrypt_schnorr_sig),
                acc_fails,
                transform_success,
            ))
        })
        //Now actually add the members that we have transform keys for.
        //acc_fails is currently the transform generation fails and the key fetch failures.
        .and_then(move |(schnorr_sig, acc_fails, transforms_to_send)| {
            requests::group_add_member::group_add_member_request(
                &auth,
                &group_id,
                transforms_to_send
                    .into_iter()
                    .map(|(user_id, pub_key, transform)| {
                        (user_id, pub_key.into(), transform.into())
                    })
                    .collect(),
                schnorr_sig,
            )
            .map(|response| group_access_api_response_to_result(acc_fails, response))
        })
}

/// Add the users as admins of a group.
///
/// # Arguments
/// `recrypt` - recrypt instance to use for cryptographic operations
/// `auth` - Auth context details for making API requests. The user associated with this device must be an admin of the group.
/// `group_id` - unique id for the group within the segment.
/// `users` - The list of users that will be added to the group as admins.
/// # Returns GroupAccessEditResult, which contains all the users that were added. It also contains the users that were not added and
///   the reason they were not.
pub fn group_add_admins<'a, CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    auth: &'a RequestAuth,
    device_private_key: &'a PrivateKey,
    group_id: &'a GroupId,
    users: &'a Vec<UserId>,
) -> impl Future<Item = GroupAccessEditResult, Error = IronOxideErr> + 'a {
    get_metadata(auth, group_id)
        .join(get_user_keys(auth, users))
        //At this point the acc_fails list is just the key fetch failures. We append to it as we go.
        .and_then(move |(group_get, (mut acc_fails, successes))| {
            let encrypted_group_key = group_get
                .encrypted_private_key
                .ok_or(IronOxideErr::NotGroupAdmin(group_id.clone()))?;
            let (plaintext, _) = transform::decrypt_plaintext(
                &recrypt,
                encrypted_group_key.try_into()?,
                &device_private_key.recrypt_key(),
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
            Ok((
                SchnorrSignature(recrypt_schnorr_sig),
                acc_fails,
                transform_success,
            ))
        })
        //Now actually add the members that we have transform keys for.
        //acc_fails is currently the transform generation fails and the key fetch failures.
        .and_then(move |(schnorr_sig, acc_fails, admin_keys_to_send)| {
            requests::group_add_admin::group_add_admin_request(
                &auth,
                &group_id,
                admin_keys_to_send
                    .into_iter()
                    .map(
                        |(
                            WithKey {
                                id: user_id,
                                public_key,
                            },
                            encrypted_admin_key,
                        )| {
                            (user_id, public_key.into(), encrypted_admin_key)
                        },
                    )
                    .collect(),
                schnorr_sig,
            )
            .map(|response| group_access_api_response_to_result(acc_fails, response))
        })
}

///This is a thin wrapper that's just mapping the errors into the type we need for add member and add admin
fn get_user_keys<'a>(
    auth: &'a RequestAuth,
    users: &'a Vec<UserId>,
) -> impl Future<Item = (Vec<GroupAccessEditErr>, Vec<WithKey<UserId>>), Error = IronOxideErr> + 'a
{
    user_api::get_user_keys(auth, &users).map(|(failed_ids, succeeded_ids)| {
        (
            failed_ids
                .into_iter()
                .map(|user| GroupAccessEditErr::new(user, "User does not exist".to_string()))
                .collect::<Vec<_>>(),
            succeeded_ids,
        )
    })
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
pub fn update_group_name<'a>(
    auth: &'a RequestAuth,
    id: &'a GroupId,
    name: Option<&'a GroupName>,
) -> impl Future<Item = GroupMetaResult, Error = IronOxideErr> + 'a {
    requests::group_update::group_update_request(auth, id, name).and_then(|resp| resp.try_into())
}

/// Remove the provided list of users as either members or admins (based on the entity_type) from the provided group ID. The
/// request and response format of these two operations are identical which is why we have a single method for it.
pub fn group_remove_entity<'a>(
    auth: &'a RequestAuth,
    id: &'a GroupId,
    users: &'a Vec<UserId>,
    entity_type: GroupEntity,
) -> impl Future<Item = GroupAccessEditResult, Error = IronOxideErr> + 'a {
    requests::group_remove_entity::remove_entity_request(auth, id, users, entity_type).map(
        |GroupUserEditResponse {
             succeeded_ids,
             failed_ids,
         }| GroupAccessEditResult {
            succeeded: succeeded_ids.into_iter().map(|user| user.user_id).collect(),
            failed: failed_ids
                .into_iter()
                .map(|fail| GroupAccessEditErr::new(fail.user_id, fail.error_message))
                .collect(),
        },
    )
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
                from_private.into(),
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
mod test {
    use super::*;

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
    fn group_create() {}
}
