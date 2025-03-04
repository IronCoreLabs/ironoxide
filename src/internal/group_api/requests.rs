use crate::internal::{
    self, IronOxideErr, RequestAuth, RequestErrorCode, SchnorrSignature,
    auth_v2::AuthV2Builder,
    group_api::{
        GroupCreateResult, GroupEntity, GroupGetResult, GroupId, GroupMetaResult, GroupName, UserId,
    },
    rest::{
        self,
        json::{
            Base64Standard, EncryptedOnceValue, PublicKey, TransformKey, TransformedEncryptedValue,
        },
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
};
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Permission {
    Member,
    Admin,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupBasicApiResponse {
    pub(crate) id: GroupId,
    pub(crate) current_key_id: u64,
    pub(crate) name: Option<GroupName>,
    pub(crate) permissions: HashSet<Permission>,
    pub(crate) status: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) updated: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) created: OffsetDateTime,
    pub(crate) group_master_public_key: PublicKey,
    pub(crate) needs_rotation: Option<bool>,
}
impl TryFrom<GroupBasicApiResponse> for GroupMetaResult {
    type Error = IronOxideErr;

    fn try_from(resp: GroupBasicApiResponse) -> Result<Self, Self::Error> {
        let group_master_public_key = resp.group_master_public_key.try_into()?;
        Ok(GroupMetaResult {
            id: resp.id,
            name: resp.name,
            group_master_public_key,
            is_admin: resp.permissions.contains(&Permission::Admin),
            is_member: resp.permissions.contains(&Permission::Member),
            created: resp.created,
            updated: resp.updated,
            needs_rotation: resp.needs_rotation,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupGetApiResponse {
    pub(crate) id: GroupId,
    pub(crate) current_key_id: u64,
    pub(crate) name: Option<GroupName>,
    pub(crate) permissions: HashSet<Permission>,
    pub(crate) status: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) updated: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) created: OffsetDateTime,
    pub(crate) owner: Option<UserId>,
    pub(crate) admin_ids: Option<Vec<UserId>>,
    pub(crate) member_ids: Option<Vec<UserId>>,
    pub(crate) group_master_public_key: PublicKey,
    pub(crate) encrypted_private_key: Option<TransformedEncryptedValue>,
    pub(crate) needs_rotation: Option<bool>,
}
impl TryFrom<GroupGetApiResponse> for GroupGetResult {
    type Error = IronOxideErr;

    fn try_from(resp: GroupGetApiResponse) -> Result<Self, Self::Error> {
        let group_master_public_key = resp.group_master_public_key.try_into()?;
        Ok(GroupGetResult {
            id: resp.id,
            name: resp.name,
            encrypted_private_key: resp.encrypted_private_key,
            group_master_public_key,
            is_admin: resp.permissions.contains(&Permission::Admin),
            is_member: resp.permissions.contains(&Permission::Member),
            owner: resp.owner,
            admin_list: resp.admin_ids,
            member_list: resp.member_ids,
            created: resp.created,
            updated: resp.updated,
            needs_rotation: resp.needs_rotation,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupCreateApiResponse {
    pub(in crate::internal) id: GroupId,
    pub(in crate::internal) name: Option<GroupName>,
    pub(in crate::internal) permissions: HashSet<Permission>,
    #[serde(with = "time::serde::rfc3339")]
    pub(in crate::internal) updated: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(in crate::internal) created: OffsetDateTime,
    pub(in crate::internal) owner: UserId,
    pub(in crate::internal) admin_ids: Vec<UserId>,
    pub(in crate::internal) member_ids: Vec<UserId>,
    pub(in crate::internal) group_master_public_key: PublicKey,
    pub(in crate::internal) needs_rotation: Option<bool>,
}
impl TryFrom<GroupCreateApiResponse> for GroupCreateResult {
    type Error = IronOxideErr;

    fn try_from(resp: GroupCreateApiResponse) -> Result<Self, Self::Error> {
        let group_master_public_key = resp.group_master_public_key.try_into()?;
        Ok(GroupCreateResult {
            id: resp.id,
            name: resp.name,
            group_master_public_key,
            is_admin: resp.permissions.contains(&Permission::Admin),
            is_member: resp.permissions.contains(&Permission::Member),
            owner: resp.owner,
            admins: resp.admin_ids,
            members: resp.member_ids,
            created: resp.created,
            updated: resp.updated,
            needs_rotation: resp.needs_rotation,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct GroupAdmin {
    pub(in crate::internal) user: User,
    #[serde(flatten)]
    pub(in crate::internal) encrypted_msg: EncryptedOnceValue,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub(in crate::internal) user_id: UserId,
    pub(in crate::internal) transform_key: TransformKey,
    pub(in crate::internal) user_master_public_key: PublicKey,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub(in crate::internal) user_id: UserId,
    pub(in crate::internal) user_master_public_key: PublicKey,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuccessRes {
    pub(crate) user_id: UserId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailRes {
    pub(crate) user_id: UserId,
    pub(crate) error_message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupUserEditResponse {
    pub(crate) succeeded_ids: Vec<SuccessRes>,
    pub(crate) failed_ids: Vec<FailRes>,
}

pub mod group_list {
    use super::*;

    #[derive(Clone, Debug, Deserialize)]
    pub struct GroupListResponse {
        pub result: Vec<GroupBasicApiResponse>,
    }

    ///List all the groups that the user is in or is an admin of.
    pub async fn group_list_request(auth: &RequestAuth) -> Result<GroupListResponse, IronOxideErr> {
        auth.request
            .get(
                "groups",
                RequestErrorCode::GroupList,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }

    //List a specific set of groups given a list of group IDs
    pub async fn group_limited_list_request(
        auth: &RequestAuth,
        groups: &[GroupId],
    ) -> Result<GroupListResponse, IronOxideErr> {
        let group_ids: Vec<&str> = groups.iter().map(GroupId::id).collect();
        auth.request
            .get_with_query_params(
                "groups",
                &[("id".into(), rest::url_encode(&group_ids.join(",")))],
                RequestErrorCode::GroupList,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }
}

pub mod group_create {
    use super::*;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GroupCreateReq {
        pub(in crate::internal) id: Option<GroupId>,
        pub(in crate::internal) name: Option<GroupName>,
        pub(in crate::internal) owner: Option<UserId>,
        pub(in crate::internal) admins: Vec<GroupAdmin>,
        pub(in crate::internal) members: Option<Vec<GroupMember>>,
        pub(in crate::internal) group_public_key: PublicKey,
        pub(in crate::internal) needs_rotation: bool,
    }

    pub async fn group_create(
        auth: &RequestAuth,
        id: Option<GroupId>, // if None, server will generate
        name: Option<GroupName>,
        group_pub_key: internal::PublicKey,
        owner: Option<UserId>,
        admins: Vec<GroupAdmin>,
        members: Option<Vec<GroupMember>>,
        needs_rotation: bool,
    ) -> Result<GroupCreateApiResponse, IronOxideErr> {
        let req = GroupCreateReq {
            id,
            name,
            owner,
            admins,
            group_public_key: group_pub_key.into(),
            members,
            needs_rotation,
        };

        auth.request
            .post(
                "groups",
                &req,
                RequestErrorCode::GroupCreate,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }
}

pub mod group_get {
    use super::*;

    pub async fn group_get_request(
        auth: &RequestAuth,
        id: &GroupId,
    ) -> Result<GroupGetApiResponse, IronOxideErr> {
        auth.request
            .get(
                &format!("groups/{}", rest::url_encode(&id.0)),
                RequestErrorCode::GroupGet,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }
}

/// PUT /groups/{groupId}/keys/{groupKeyId}
pub mod group_update_private_key {
    use super::*;
    use internal::{group_api::GroupUpdatePrivateKeyResult, rest::json::AugmentationFactor};

    #[derive(Debug, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GroupUpdatePrivateKeyRequest {
        admins: Vec<GroupAdmin>,
        augmentation_factor: AugmentationFactor,
    }

    #[derive(Debug, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GroupUpdatePrivateKeyResponse {
        group_key_id: u64,
        group_id: GroupId,
        needs_rotation: bool,
    }

    impl From<GroupUpdatePrivateKeyResponse> for GroupUpdatePrivateKeyResult {
        fn from(resp: GroupUpdatePrivateKeyResponse) -> Self {
            // don't expose the current_key_id to the outside world until we need to
            GroupUpdatePrivateKeyResult {
                id: resp.group_id,
                needs_rotation: resp.needs_rotation,
            }
        }
    }

    pub async fn update_private_key(
        auth: &RequestAuth,
        group_id: &GroupId,
        group_key_id: u64,
        admins: Vec<GroupAdmin>,
        augmentation_factor: AugmentationFactor,
    ) -> Result<GroupUpdatePrivateKeyResponse, IronOxideErr> {
        auth.request
            .put(
                &format!(
                    "groups/{}/keys/{}",
                    rest::url_encode(group_id.id()),
                    group_key_id
                ),
                &GroupUpdatePrivateKeyRequest {
                    augmentation_factor,
                    admins,
                },
                RequestErrorCode::GroupKeyUpdate,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }
}

pub mod group_delete {
    use super::*;

    #[derive(Deserialize)]
    pub struct GroupDeleteApiResponse {
        pub(crate) id: GroupId,
    }

    pub async fn group_delete_request(
        auth: &RequestAuth,
        id: &GroupId,
    ) -> Result<GroupDeleteApiResponse, IronOxideErr> {
        auth.request
            .delete_with_no_body(
                &format!("groups/{}", rest::url_encode(&id.0)),
                RequestErrorCode::GroupDelete,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }
}

pub mod group_update {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Serialize)]
    struct GroupUpdateRequest<'a> {
        name: Option<&'a GroupName>,
    }

    pub async fn group_update_request(
        auth: &RequestAuth,
        id: &GroupId,
        name: Option<&GroupName>,
    ) -> Result<GroupBasicApiResponse, IronOxideErr> {
        auth.request
            .put(
                &format!("groups/{}", rest::url_encode(&id.0)),
                &GroupUpdateRequest { name },
                RequestErrorCode::GroupUpdate,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }
}

pub mod group_add_member {
    use super::*;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GroupAddMembersReq {
        pub users: Vec<GroupMember>,
        #[serde(with = "Base64Standard")]
        pub signature: Vec<u8>,
    }

    pub async fn group_add_member_request(
        auth: &RequestAuth,
        id: &GroupId,
        users: Vec<(UserId, PublicKey, TransformKey)>,
        signature: SchnorrSignature,
    ) -> Result<GroupUserEditResponse, IronOxideErr> {
        let encoded_id = rest::url_encode(&id.0).to_string();
        let users = users
            .into_iter()
            .map(|(user_id, pk, tkey)| GroupMember {
                user_id,
                transform_key: tkey,
                user_master_public_key: pk,
            })
            .collect();
        auth.request
            .post(
                &format!("groups/{encoded_id}/users"),
                &GroupAddMembersReq {
                    users,
                    signature: signature.into(),
                },
                RequestErrorCode::GroupAddMember,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }
}

pub mod group_add_admin {
    use super::*;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GroupAddAdminsReq {
        pub admins: Vec<GroupAdmin>,
        #[serde(with = "Base64Standard")]
        pub signature: Vec<u8>,
    }

    pub async fn group_add_admin_request(
        auth: &RequestAuth,
        id: &GroupId,
        admins: Vec<GroupAdmin>,
        signature: SchnorrSignature,
    ) -> Result<GroupUserEditResponse, IronOxideErr> {
        let encoded_id = rest::url_encode(&id.0).to_string();
        auth.request
            .post(
                &format!("groups/{encoded_id}/admins"),
                &GroupAddAdminsReq {
                    admins,
                    signature: signature.into(),
                },
                RequestErrorCode::GroupAddMember,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }
}

pub mod group_remove_entity {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Serialize)]
    #[serde(rename_all = "camelCase")]
    struct GroupEntityId<'a> {
        user_id: &'a UserId,
    }

    #[derive(Clone, Debug, PartialEq, Serialize)]
    struct GroupEntityRemoveRequest<'a> {
        users: Vec<GroupEntityId<'a>>,
    }

    pub async fn remove_entity_request(
        auth: &RequestAuth,
        group_id: &GroupId,
        user_ids: &[UserId],
        entity_type: GroupEntity,
    ) -> Result<GroupUserEditResponse, IronOxideErr> {
        let removed_users = user_ids
            .iter()
            .map(|user_id| GroupEntityId { user_id })
            .collect();
        let (url_entity_path, error_code) = match entity_type {
            GroupEntity::Admin => ("admins", RequestErrorCode::GroupAdminRemove),
            GroupEntity::Member => ("users", RequestErrorCode::GroupMemberRemove),
        };
        auth.request
            .delete(
                &format!(
                    "groups/{}/{}",
                    rest::url_encode(&group_id.0),
                    url_entity_path
                ),
                &GroupEntityRemoveRequest {
                    users: removed_users,
                },
                error_code,
                AuthV2Builder::new(auth, OffsetDateTime::now_utc()),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use recrypt::api::KeyGenOps;

    ///This test is to ensure our lowercase admin and member permissions are handled correctly.
    #[test]
    fn group_item_serde_format_is_expected() {
        let created = OffsetDateTime::from_unix_timestamp_nanos(1_551_461_529_000_000_000).unwrap();
        let updated = OffsetDateTime::from_unix_timestamp_nanos(1_551_461_529_001_000_000).unwrap();
        let mut permissions = HashSet::new();
        permissions.insert(Permission::Member);
        permissions.insert(Permission::Admin);

        let recrypt = recrypt::api::Recrypt::new();
        let (_, pk) = recrypt.generate_key_pair().unwrap();
        let item = GroupBasicApiResponse {
            id: GroupId("my_id".to_string()),
            current_key_id: 10,
            name: None,
            status: 1,
            group_master_public_key: pk.into(),
            permissions,
            created,
            updated,
            needs_rotation: Some(true),
        };
        let result = serde_json::to_string(&item).unwrap();
        assert!(
            result.contains("\"admin\""),
            "{} should contain admin",
            result
        );
        assert!(
            result.contains("\"member\""),
            "{} should contain member",
            result
        );
        let de_result = serde_json::from_str(&result).unwrap();
        assert_eq!(item, de_result)
    }
}
