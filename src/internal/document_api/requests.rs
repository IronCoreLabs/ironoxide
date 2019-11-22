use super::{AssociationType, DocumentId, DocumentName};
use crate::internal::{
    self,
    auth_v2::AuthV2Builder,
    document_api::{EncryptedDek, UserOrGroup, VisibleGroup, VisibleUser, WithKey},
    group_api::GroupId,
    rest::{
        self,
        json::{EncryptedOnceValue, PublicKey, TransformedEncryptedValue},
    },
    user_api::UserId,
    IronOxideErr, RequestAuth, RequestErrorCode,
};
use chrono::{DateTime, Utc};
use futures::Future;
use futures3::compat::Future01CompatExt;
use std::convert::{TryFrom, TryInto};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Association {
    #[serde(rename = "type")]
    pub typ: AssociationType,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct DocumentVisibility {
    pub users: Vec<VisibleUser>,
    pub groups: Vec<VisibleGroup>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum UserOrGroupWithKey {
    #[serde(rename_all = "camelCase")]
    User {
        id: String,
        // optional because the resp on document create does not return a public key
        master_public_key: Option<PublicKey>,
    },
    #[serde(rename_all = "camelCase")]
    Group {
        id: String,
        master_public_key: Option<PublicKey>,
    },
}

impl From<UserOrGroupWithKey> for UserOrGroup {
    fn from(with_key: UserOrGroupWithKey) -> Self {
        match with_key {
            UserOrGroupWithKey::User { id, .. } => UserOrGroup::User {
                id: UserId::unsafe_from_string(id),
            },
            UserOrGroupWithKey::Group { id, .. } => UserOrGroup::Group {
                id: GroupId::unsafe_from_string(id),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccessGrant {
    pub(crate) user_or_group: UserOrGroupWithKey,
    #[serde(flatten)]
    pub(crate) encrypted_value: EncryptedOnceValue,
}

impl TryFrom<(WithKey<UserOrGroup>, recrypt::api::EncryptedValue)> for AccessGrant {
    type Error = IronOxideErr;
    fn try_from(
        entry: (WithKey<UserOrGroup>, recrypt::api::EncryptedValue),
    ) -> Result<Self, Self::Error> {
        EncryptedDek {
            grant_to: entry.0,
            encrypted_dek_data: entry.1,
        }
        .try_into()
    }
}

impl TryFrom<EncryptedDek> for AccessGrant {
    type Error = IronOxideErr;

    fn try_from(value: EncryptedDek) -> Result<Self, Self::Error> {
        Ok(AccessGrant {
            encrypted_value: value.encrypted_dek_data.try_into()?,
            user_or_group: match value.grant_to {
                WithKey {
                    id: UserOrGroup::User { id },
                    public_key,
                } => UserOrGroupWithKey::User {
                    id: id.0,
                    master_public_key: Some(public_key.into()),
                },
                WithKey {
                    id: UserOrGroup::Group { id },
                    public_key,
                } => UserOrGroupWithKey::Group {
                    id: id.0,
                    master_public_key: Some(public_key.into()),
                },
            },
        })
    }
}

impl From<&AccessGrant> for UserOrGroup {
    fn from(grant: &AccessGrant) -> Self {
        match grant {
            AccessGrant {
                user_or_group: UserOrGroupWithKey::User { id, .. },
                ..
            } => UserOrGroup::User {
                id: UserId::unsafe_from_string(id.clone()),
            },
            AccessGrant {
                user_or_group: UserOrGroupWithKey::Group { id, .. },
                ..
            } => UserOrGroup::Group {
                id: GroupId::unsafe_from_string(id.clone()),
            },
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DocumentMetaApiResponse {
    pub id: DocumentId,
    pub name: Option<DocumentName>,
    pub association: Association,
    pub visible_to: DocumentVisibility,
    pub encrypted_symmetric_key: TransformedEncryptedValue,
    pub updated: DateTime<Utc>,
    pub created: DateTime<Utc>,
}

pub mod document_list {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub struct DocumentListApiResponse {
        pub result: Vec<DocumentListApiResponseItem>,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub struct DocumentListApiResponseItem {
        pub id: DocumentId,
        pub name: Option<DocumentName>,
        pub association: Association,
        pub created: DateTime<Utc>,
        pub updated: DateTime<Utc>,
    }

    /// Make GET request to document list endpoint for the current user/device context
    pub async fn document_list_request(
        auth: &RequestAuth,
    ) -> Result<DocumentListApiResponse, IronOxideErr> {
        auth.request
            .get(
                "documents",
                RequestErrorCode::DocumentList,
                AuthV2Builder::new(&auth, Utc::now()),
            )
            .compat()
            .await
    }
}

pub mod document_get {
    use super::*;

    pub async fn document_get_request(
        auth: &RequestAuth,
        id: &DocumentId,
    ) -> Result<DocumentMetaApiResponse, IronOxideErr> {
        auth.request
            .get(
                &format!("documents/{}", rest::url_encode(&id.0)),
                RequestErrorCode::DocumentGet,
                AuthV2Builder::new(&auth, Utc::now()),
            )
            .compat()
            .await
    }
}

pub mod edek_transform {
    use super::*;

    pub fn edek_transform<'a>(
        auth: &'a RequestAuth,
        edek_bytes: &'a [u8],
    ) -> impl Future<Item = EdekTransformResponse, Error = IronOxideErr> + 'a {
        auth.request.post_raw(
            "edeks/transform",
            edek_bytes,
            RequestErrorCode::EdekTransform,
            AuthV2Builder::new(&auth, Utc::now()),
        )
    }

    #[derive(Serialize, Debug, Clone, Deserialize, PartialEq)]
    #[serde(rename_all = "camelCase")]
    pub struct EdekTransformResponse {
        pub(in crate::internal::document_api) user_or_group: UserOrGroup,
        pub(in crate::internal::document_api) encrypted_symmetric_key: TransformedEncryptedValue,
    }
}

pub mod document_create {
    use super::*;
    use crate::internal::{
        auth_v2::AuthV2Builder,
        document_api::{DocumentName, EncryptedDek},
    };
    use std::convert::TryInto;

    #[derive(Serialize, Debug, Clone, Deserialize, PartialEq)]
    #[serde(rename_all = "camelCase")]
    pub struct DocumentCreateValue {
        pub(crate) name: Option<DocumentName>,
        pub(crate) shared_with: Vec<AccessGrant>,
    }

    #[derive(Serialize, Debug, Clone, PartialEq)]
    pub struct DocumentCreateRequest {
        pub(crate) id: DocumentId,
        pub(crate) value: DocumentCreateValue,
    }

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct DocumentCreateResponse {
        pub(crate) id: DocumentId,
        pub(crate) name: Option<DocumentName>,
        pub(crate) updated: DateTime<Utc>,
        pub(crate) created: DateTime<Utc>,
        pub(crate) shared_with: Vec<AccessGrant>,
    }

    pub async fn document_create_request(
        auth: &RequestAuth,
        id: DocumentId,
        name: Option<DocumentName>,
        grants: Vec<EncryptedDek>,
    ) -> Result<DocumentCreateResponse, IronOxideErr> {
        let maybe_req_grants: Result<Vec<_>, _> =
            grants.into_iter().map(|g| g.try_into()).collect();

        match maybe_req_grants {
            Ok(req_grants) => {
                let req = DocumentCreateRequest {
                    id,
                    value: DocumentCreateValue {
                        name,
                        shared_with: req_grants,
                    },
                };
                auth.request
                    .post(
                        "documents",
                        &req,
                        RequestErrorCode::DocumentCreate,
                        AuthV2Builder::new(&auth, Utc::now()),
                    )
                    .compat()
                    .await
            }
            // the failure case here is that we couldn't convert the recrypt EncryptedValue because
            // it was not an EncryptedOnceValue -- really just a limitation of Rust's enums as we expect these to be EncryptedOnceValues
            Err(e) => futures3::future::err(e).await,
        }
    }
}

pub mod policy_get {
    use super::*;
    use crate::{
        internal::rest::{url_encode, PercentEncodedString},
        policy::{Category, DataSubject, PolicyGrant, Sensitivity},
    };

    pub(crate) const SUBSTITUTE_ID_QUERY_PARAM: &'static str = "substituteId";

    #[derive(Deserialize, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct PolicyResult {
        //TODO rename to PolicyResponse
        pub(crate) users_and_groups: Vec<UserOrGroupWithKey>,
        pub(crate) invalid_users_and_groups: Vec<UserOrGroup>,
    }

    pub async fn policy_get_request(
        auth: &RequestAuth,
        policy_grant: &PolicyGrant,
    ) -> Result<PolicyResult, IronOxideErr> {
        let query_params: Vec<(String, PercentEncodedString)> = [
            // all query params here are just letters, so no need to percent encode
            policy_grant
                .category()
                .map(|c| (Category::QUERY_PARAM.to_string(), url_encode(c.inner()))),
            policy_grant
                .sensitivity()
                .map(|s| (Sensitivity::QUERY_PARAM.to_string(), url_encode(s.inner()))),
            policy_grant
                .data_subject()
                .map(|d| (DataSubject::QUERY_PARAM.to_string(), url_encode(d.inner()))),
            policy_grant
                .substitute_user()
                .map(|UserId(u)| (SUBSTITUTE_ID_QUERY_PARAM.to_string(), url_encode(u))),
        ]
        .to_vec()
        .into_iter()
        .flatten()
        .collect();

        auth.request
            .get_with_query_params(
                "policies",
                &query_params,
                RequestErrorCode::PolicyGet,
                AuthV2Builder::new(&auth, Utc::now()),
            )
            .compat()
            .await
    }
}

pub mod document_update {
    use super::*;

    #[derive(Serialize, Debug, Clone, PartialEq)]
    struct DocumentUpdateRequest<'a> {
        name: Option<&'a DocumentName>,
    }

    pub async fn document_update_request(
        auth: &RequestAuth,
        id: &DocumentId,
        name: Option<&DocumentName>,
    ) -> Result<DocumentMetaApiResponse, IronOxideErr> {
        auth.request
            .put(
                &format!("documents/{}", rest::url_encode(&id.0)),
                &DocumentUpdateRequest { name },
                RequestErrorCode::DocumentUpdate,
                AuthV2Builder::new(&auth, Utc::now()),
            )
            .compat()
            .await
    }
}

pub mod document_access {
    use super::*;
    use crate::internal::{
        auth_v2::AuthV2Builder,
        document_api::{requests::document_access::resp::*, UserOrGroup, WithKey},
    };
    use std::convert::TryInto;

    pub mod resp {
        use crate::internal::{
            document_api::{DocAccessEditErr, DocumentAccessResult, UserOrGroup},
            group_api::GroupId,
            user_api::UserId,
        };

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct SuccessRes {
            pub(crate) user_or_group: UserOrGroupAccess,
        }

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct FailRes {
            pub(crate) user_or_group: UserOrGroupAccess,
            pub(crate) error_message: String,
        }

        #[derive(Deserialize, Serialize, Debug)]
        #[serde(tag = "type", rename_all = "camelCase")]
        pub enum UserOrGroupAccess {
            User { id: String },
            Group { id: String },
        }

        impl From<SuccessRes> for UserOrGroup {
            fn from(s: SuccessRes) -> Self {
                s.user_or_group.into()
            }
        }

        impl From<FailRes> for DocAccessEditErr {
            fn from(f: FailRes) -> Self {
                DocAccessEditErr {
                    user_or_group: f.user_or_group.into(),
                    err: f.error_message,
                }
            }
        }

        impl From<UserOrGroupAccess> for UserOrGroup {
            fn from(uog: UserOrGroupAccess) -> Self {
                match uog {
                    UserOrGroupAccess::User { id } => UserOrGroup::User {
                        id: UserId::unsafe_from_string(id),
                    },
                    UserOrGroupAccess::Group { id } => {
                        UserOrGroup::Group { id: GroupId(id) } //not validating here
                    }
                }
            }
        }

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        pub struct DocumentAccessResponse {
            succeeded_ids: Vec<SuccessRes>,
            failed_ids: Vec<FailRes>,
        }

        pub fn document_access_api_resp_to_result(
            access_resp: DocumentAccessResponse,
            other_errs: Vec<DocAccessEditErr>,
        ) -> DocumentAccessResult {
            use itertools::Itertools;
            let succeeded = access_resp
                .succeeded_ids
                .into_iter()
                .map(UserOrGroup::from)
                .collect();

            let failed = access_resp
                .failed_ids
                .into_iter()
                .map(DocAccessEditErr::from)
                .collect();

            DocumentAccessResult::new(succeeded, vec![failed, other_errs].into_iter().concat())
        }
    }

    #[derive(Serialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct DocumentGrantAccessRequest {
        /// Granting user's public key
        from_public_key: PublicKey,
        to: Vec<AccessGrant>,
    }

    #[derive(Serialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct DocumentRevokeAccessRequest {
        user_or_groups: Vec<UserOrGroupAccess>,
    }

    pub fn grant_access_request<'a>(
        auth: &'a RequestAuth,
        id: &'a DocumentId,
        from_pub_key: &'a internal::PublicKey,
        grants: Vec<(WithKey<UserOrGroup>, recrypt::api::EncryptedValue)>,
    ) -> Box<dyn Future<Item = DocumentAccessResponse, Error = IronOxideErr> + 'a> {
        let maybe_req_grants: Result<Vec<_>, _> =
            grants.into_iter().map(|g| g.try_into()).collect();

        match maybe_req_grants {
            Ok(req_grants) => {
                let req = DocumentGrantAccessRequest {
                    from_public_key: from_pub_key.clone().into(),
                    to: req_grants,
                };
                Box::new(auth.request.post(
                    &format!("documents/{}/access", rest::url_encode(id.id())),
                    &req,
                    RequestErrorCode::DocumentGrantAccess,
                    AuthV2Builder::new(&auth, Utc::now()),
                ))
            }
            // the failure case here is that we couldn't convert the recrypt EncryptedValue because
            // it was not an EncryptedOnceValue -- really just a limitation of Rust's enums as we expect these to be EncryptedOnceValues
            Err(e) => Box::new(futures::future::failed(e)),
        }
    }

    pub fn revoke_access_request<'a>(
        auth: &'a RequestAuth,
        doc_id: &DocumentId,
        revoke_list: Vec<UserOrGroupAccess>,
    ) -> impl Future<Item = DocumentAccessResponse, Error = IronOxideErr> + 'a {
        auth.request.delete(
            &format!("documents/{}/access", rest::url_encode(&doc_id.0)),
            &DocumentRevokeAccessRequest {
                user_or_groups: revoke_list,
            },
            RequestErrorCode::DocumentRevokeAccess,
            AuthV2Builder::new(&auth, Utc::now()),
        )
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    ///This test is to ensure our lowercase doc associations are handled correctly.
    #[test]
    fn document_item_serde_format_is_expected() {
        use document_list::DocumentListApiResponseItem;

        let created = Utc.timestamp_millis(1551461529000);
        let updated = Utc.timestamp_millis(1551461529001);
        let item = DocumentListApiResponseItem {
            id: DocumentId("my_id".to_string()),
            name: None,
            association: Association {
                typ: AssociationType::FromGroup,
            },
            created,
            updated,
        };
        let result = serde_json::to_string(&item).unwrap();
        assert!(
            result.contains("\"fromGroup\""),
            format!("{} should contain fromGroup", result)
        );
        let de_result = serde_json::from_str(&result).unwrap();
        assert_eq!(item, de_result)
    }
}
