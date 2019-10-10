use crate::internal::{
    group_api::{GroupEntity, GroupGetResult, GroupId, GroupMetaResult, GroupName, UserId},
    rest::{
        self,
        json::{EncryptedOnceValue, PublicKey, TransformKey, TransformedEncryptedValue},
    },
    IronOxideErr, RequestAuth, RequestErrorCode,
};
use chrono::{DateTime, Utc};
use futures::Future;
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
};

use crate::internal::auth_v2::AuthV2Builder;

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Permission {
    Member,
    Admin,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GroupBasicApiResponse {
    pub(crate) id: GroupId,
    pub(crate) name: Option<GroupName>,
    pub(crate) permissions: HashSet<Permission>,
    pub(crate) status: u32,
    pub(crate) updated: DateTime<Utc>,
    pub(crate) created: DateTime<Utc>,
    pub(crate) group_master_public_key: PublicKey,
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
        })
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GroupGetApiResponse {
    pub(crate) id: GroupId,
    pub(crate) name: Option<GroupName>,
    pub(crate) permissions: HashSet<Permission>,
    pub(crate) status: u32,
    pub(crate) updated: DateTime<Utc>,
    pub(crate) created: DateTime<Utc>,
    pub(crate) admin_ids: Option<Vec<String>>,
    pub(crate) member_ids: Option<Vec<String>>,
    pub(crate) group_master_public_key: PublicKey,
    pub(crate) encrypted_private_key: Option<TransformedEncryptedValue>,
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
            admin_list: resp
                .admin_ids
                .map(|admins| admins.into_iter().map(UserId).collect()),
            member_list: resp
                .member_ids
                .map(|members| members.into_iter().map(UserId).collect()),
            created: resp.created,
            updated: resp.updated,
        })
    }
}

#[derive(Serialize, Debug, PartialEq)]
pub struct GroupAdmin {
    user: User,
    #[serde(flatten)]
    encrypted_msg: EncryptedOnceValue,
}

#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    user_id: UserId,
    transform_key: TransformKey,
    user_master_public_key: PublicKey,
}

#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    user_id: UserId,
    user_master_public_key: PublicKey,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SuccessRes {
    pub(crate) user_id: UserId,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FailRes {
    pub(crate) user_id: UserId,
    pub(crate) error_message: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GroupUserEditResponse {
    pub(crate) succeeded_ids: Vec<SuccessRes>,
    pub(crate) failed_ids: Vec<FailRes>,
}

pub mod group_list {
    use super::*;

    #[derive(Deserialize, Debug, Clone)]
    pub struct GroupListResponse {
        pub result: Vec<GroupBasicApiResponse>,
    }

    ///List all the groups that the user is in or is an admin of.
    pub fn group_list_request(
        auth: &RequestAuth,
    ) -> Box<dyn Future<Item = GroupListResponse, Error = IronOxideErr>> {
        Box::new(auth.request.get(
            "groups",
            RequestErrorCode::GroupList,
            AuthV2Builder::new(&auth, Utc::now()),
        ))
    }

    //List a specific set of groups given a list of group IDs
    pub fn group_limited_list_request(
        auth: &RequestAuth,
        groups: &Vec<GroupId>,
    ) -> Box<dyn Future<Item = GroupListResponse, Error = IronOxideErr>> {
        let group_ids: Vec<&str> = groups.iter().map(|group| group.id()).collect();
        Box::new(auth.request.get(
            &format!("groups?id={}", rest::url_encode(&group_ids.join(","))),
            RequestErrorCode::GroupList,
            AuthV2Builder::new(&auth, Utc::now()),
        ))
    }
}

pub mod group_create {
    use super::*;
    use crate::internal::auth_v2::AuthV2Builder;
    use crate::internal::{self, rest::json::EncryptedOnceValue};
    use futures::prelude::*;
    use std::convert::TryFrom;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GroupCreateReq {
        pub id: Option<GroupId>,
        pub name: Option<GroupName>,
        pub admins: Vec<GroupAdmin>,
        pub group_public_key: PublicKey,
        pub members: Option<Vec<GroupMember>>,
    }

    pub fn group_create<'a>(
        auth: &'a RequestAuth,
        user_master_pub_key: &'a internal::PublicKey,
        id: Option<GroupId>, // if None, server will generate
        name: Option<GroupName>,
        re_encrypted_once_value: recrypt::api::EncryptedValue,
        group_pub_key: internal::PublicKey,
        user_id: &'a UserId,
        member_transform_key: Option<internal::TransformKey>,
    ) -> impl Future<Item = GroupBasicApiResponse, Error = IronOxideErr> + 'a {
        EncryptedOnceValue::try_from(re_encrypted_once_value)
            .into_future()
            .and_then(move |enc_msg| {
                let req = GroupCreateReq {
                    id,
                    name,
                    admins: vec![GroupAdmin {
                        encrypted_msg: enc_msg,
                        user: User {
                            user_id: user_id.clone(),
                            user_master_public_key: user_master_pub_key.clone().into(),
                        },
                    }],
                    group_public_key: group_pub_key.to_owned().into(),
                    members: member_transform_key.map(|tkey| {
                        vec![GroupMember {
                            user_id: user_id.clone(),
                            transform_key: tkey.into(),
                            user_master_public_key: user_master_pub_key.clone().into(),
                        }]
                    }),
                };

                auth.request.post2(
                    "groups",
                    &req,
                    RequestErrorCode::GroupCreate,
                    AuthV2Builder::new(&auth, Utc::now()),
                )
            })
    }
}

pub mod group_get {
    use super::*;

    pub fn group_get_request(
        auth: &RequestAuth,
        id: &GroupId,
    ) -> impl Future<Item = GroupGetApiResponse, Error = IronOxideErr> {
        auth.request.get(
            &format!("groups/{}", rest::url_encode(&id.0)),
            RequestErrorCode::GroupGet,
            AuthV2Builder::new(&auth, Utc::now()),
        )
    }
}

pub mod group_delete {
    use super::*;

    #[derive(Deserialize)]
    pub struct GroupDeleteApiResponse {
        pub(crate) id: String,
    }

    pub fn group_delete_request(
        auth: &RequestAuth,
        id: &GroupId,
    ) -> impl Future<Item = GroupDeleteApiResponse, Error = IronOxideErr> {
        auth.request.delete_with_no_body(
            &format!("groups/{}", rest::url_encode(&id.0)),
            RequestErrorCode::GroupDelete,
            AuthV2Builder::new(&auth, Utc::now()),
        )
    }
}

pub mod group_update {
    use super::*;
    use crate::internal::auth_v2::AuthV2Builder;

    #[derive(Serialize, Debug, Clone, PartialEq)]
    struct GroupUpdateRequest<'a> {
        name: Option<&'a GroupName>,
    }

    pub fn group_update_request<'a>(
        auth: &'a RequestAuth,
        id: &'a GroupId,
        name: Option<&'a GroupName>,
    ) -> impl Future<Item = GroupBasicApiResponse, Error = IronOxideErr> + 'a {
        auth.request.put(
            &format!("groups/{}", rest::url_encode(&id.0)),
            &GroupUpdateRequest { name },
            RequestErrorCode::GroupUpdate,
            AuthV2Builder::new(&auth, Utc::now()),
        )
    }
}

pub mod group_add_member {
    use super::*;
    use crate::internal::auth_v2::AuthV2Builder;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GroupAddMembersReq {
        pub users: Vec<GroupMember>,
    }

    pub fn group_add_member_request(
        auth: &RequestAuth,
        id: &GroupId,
        users: Vec<(UserId, PublicKey, TransformKey)>,
    ) -> impl Future<Item = GroupUserEditResponse, Error = IronOxideErr> {
        let encoded_id = rest::url_encode(&id.0).to_string();
        let users = users
            .into_iter()
            .map(|(user_id, pk, tkey)| GroupMember {
                user_id,
                transform_key: tkey.into(),
                user_master_public_key: pk.into(),
            })
            .collect();
        auth.request.post2(
            &format!("groups/{}/users", encoded_id),
            &GroupAddMembersReq { users },
            RequestErrorCode::GroupAddMember,
            AuthV2Builder::new(&auth, Utc::now()),
        )
    }
}

pub mod group_add_admin {
    use super::*;
    use crate::internal::auth_v2::AuthV2Builder;
    use futures::prelude::*;
    use std::convert::TryInto;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct GroupAddAdminsReq {
        pub admins: Vec<GroupAdmin>,
    }

    pub fn group_add_admin_request<'a>(
        auth: &'a RequestAuth,
        id: &'a GroupId,
        users: Vec<(UserId, PublicKey, recrypt::api::EncryptedValue)>,
    ) -> impl Future<Item = GroupUserEditResponse, Error = IronOxideErr> + 'a {
        //The users could _technically_ contiain a reencrypted value, if that happened the `try_into` would fail.
        //This can't happen in a normal usecase.
        let users_or_error = users
            .into_iter()
            .map(|(user_id, user_master_public_key, encrypted_value)| {
                encrypted_value.try_into().map(|encrypted_msg| GroupAdmin {
                    user: User {
                        user_id,
                        user_master_public_key,
                    },
                    encrypted_msg,
                })
            })
            .collect::<Result<Vec<GroupAdmin>, IronOxideErr>>();
        users_or_error.into_future().and_then(move |admins| {
            let encoded_id = rest::url_encode(&id.0).to_string();
            auth.request.post2(
                &format!("groups/{}/admins", encoded_id),
                &GroupAddAdminsReq { admins },
                RequestErrorCode::GroupAddMember,
                AuthV2Builder::new(&auth, Utc::now()),
            )
        })
    }
}

pub mod group_remove_entity {
    use super::*;

    #[derive(Serialize, Debug, Clone, PartialEq)]
    #[serde(rename_all = "camelCase")]
    struct GroupEntityId<'a> {
        user_id: &'a UserId,
    }

    #[derive(Serialize, Debug, Clone, PartialEq)]
    struct GroupEntityRemoveRequest<'a> {
        users: Vec<GroupEntityId<'a>>,
    }

    pub fn remove_entity_request<'a>(
        auth: &'a RequestAuth,
        group_id: &'a GroupId,
        user_ids: &'a Vec<UserId>,
        entity_type: GroupEntity,
    ) -> impl Future<Item = GroupUserEditResponse, Error = IronOxideErr> + 'a {
        let removed_users = user_ids
            .into_iter()
            .map(|user_id| GroupEntityId { user_id })
            .collect();
        let (url_entity_path, error_code) = match entity_type {
            GroupEntity::Admin => ("admins", RequestErrorCode::GroupAdminRemove),
            GroupEntity::Member => ("users", RequestErrorCode::GroupMemberRemove),
        };
        auth.request.delete(
            &format!(
                "groups/{}/{}",
                rest::url_encode(&group_id.0),
                url_entity_path
            ),
            &GroupEntityRemoveRequest {
                users: removed_users,
            },
            error_code,
            AuthV2Builder::new(&auth, Utc::now()),
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use recrypt::api::KeyGenOps;

    ///This test is to ensure our lowercase admin and member permissions are handled correctly.
    #[test]
    fn group_item_serde_format_is_expected() {
        let created = Utc.timestamp_millis(1551461529000);
        let updated = Utc.timestamp_millis(1551461529001);
        let mut permissions = HashSet::new();
        permissions.insert(Permission::Member);
        permissions.insert(Permission::Admin);

        let recrypt = recrypt::api::Recrypt::new();
        let (_, pk) = recrypt.generate_key_pair().unwrap();
        let item = GroupBasicApiResponse {
            id: GroupId("my_id".to_string()),
            name: None,
            status: 1,
            group_master_public_key: pk.into(),
            permissions,
            created,
            updated,
        };
        let result = serde_json::to_string(&item).unwrap();
        assert!(
            result.contains("\"admin\""),
            format!("{} should contain admin", result)
        );
        assert!(
            result.contains("\"member\""),
            format!("{} should contain member", result)
        );
        let de_result = serde_json::from_str(&result).unwrap();
        assert_eq!(item, de_result)
    }
}
