//! User operation requests.
//! Types and functions defined here should remain private to `user_api`

use crate::{
    crypto::aes::EncryptedMasterKey,
    internal::{
        self,
        rest::{
            self,
            json::{Base64Standard, PublicKey},
            Authorization, IronCoreRequest,
        },
        user_api::{DeviceName, UserId},
        IronOxideErr, Jwt, RequestAuth, RequestErrorCode,
    },
};
use chrono::Utc;
use std::convert::TryFrom;

use crate::internal::auth_v2::AuthV2Builder;
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct EncryptedPrivateKey(#[serde(with = "Base64Standard")] pub Vec<u8>);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct AugmentationFactor(#[serde(with = "Base64Standard")] pub Vec<u8>);

impl From<internal::AugmentationFactor> for AugmentationFactor {
    fn from(af: internal::AugmentationFactor) -> Self {
        AugmentationFactor(af.as_bytes().to_vec())
    }
}

impl From<EncryptedMasterKey> for EncryptedPrivateKey {
    fn from(enc_master_key: EncryptedMasterKey) -> Self {
        EncryptedPrivateKey(enc_master_key.bytes().to_vec())
    }
}

impl From<EncryptedPrivateKey> for internal::user_api::EncryptedPrivateKey {
    fn from(resp_encrypt_priv_key: EncryptedPrivateKey) -> Self {
        internal::user_api::EncryptedPrivateKey(resp_encrypt_priv_key.0)
    }
}

impl TryFrom<EncryptedPrivateKey> for EncryptedMasterKey {
    type Error = IronOxideErr;

    fn try_from(value: EncryptedPrivateKey) -> Result<Self, Self::Error> {
        EncryptedMasterKey::new_from_slice(&value.0)
    }
}

pub mod user_verify {
    use crate::internal::user_api::UserResult;
    use std::convert::TryInto;

    use super::*;

    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct UserVerifyResponse {
        pub(crate) id: String,
        status: usize,
        pub(crate) segment_id: usize,
        pub(crate) user_private_key: EncryptedPrivateKey,
        pub(crate) user_master_public_key: PublicKey,
        pub(crate) needs_rotation: bool,
    }

    pub async fn user_verify(
        jwt: &Jwt,
        request: &IronCoreRequest<'static>,
    ) -> Result<Option<UserVerifyResponse>, IronOxideErr> {
        request
            .get_with_empty_result_jwt_auth(
                "users/verify?returnKeys=true",
                RequestErrorCode::UserVerify,
                &Authorization::JwtAuth(jwt),
            )
            .await
    }

    impl TryFrom<UserVerifyResponse> for UserResult {
        type Error = IronOxideErr;

        fn try_from(body: UserVerifyResponse) -> Result<Self, Self::Error> {
            Ok(UserResult {
                account_id: body.id.try_into()?,
                segment_id: body.segment_id,
                user_public_key: body.user_master_public_key.try_into()?,
                needs_rotation: body.needs_rotation,
            })
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::internal;
        use galvanic_assert::matchers::*;
        use recrypt::prelude::*;

        #[test]
        fn user_verify_resp_to_result() -> Result<(), IronOxideErr> {
            let r = recrypt::api::Recrypt::new();
            let (_, r_pub) = r.generate_key_pair()?;

            // private key doesn't go through any validation as we don't return it in the Result
            let priv_key: EncryptedPrivateKey = EncryptedPrivateKey(vec![1u8; 60]);
            let pub_key: PublicKey = r_pub.into();

            let t_account_id: UserId = UserId::unsafe_from_string("valid_user_id".to_string());
            let t_segment_id: usize = 200;
            let t_user_public_key: internal::PublicKey = r_pub.into();
            let t_needs_rotation = true;

            let resp = UserVerifyResponse {
                id: t_account_id.id().to_string(),
                status: 100,
                segment_id: t_segment_id,
                user_private_key: priv_key,
                user_master_public_key: pub_key,
                needs_rotation: t_needs_rotation,
            };
            let result: UserResult = resp.try_into().unwrap();

            assert_that!(
                &result,
                has_structure!(UserResult {
                    account_id: eq(t_account_id.clone()),
                    segment_id: eq(t_segment_id),
                    user_public_key: eq(t_user_public_key.clone()),
                    needs_rotation: eq(t_needs_rotation)
                })
            );
            Ok(())
        }
    }
}

pub mod user_get {
    use super::*;

    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct CurrentUserResponse {
        pub(in crate::internal) current_key_id: u64,
        pub(in crate::internal) id: String,
        pub(in crate::internal) status: usize,
        pub(in crate::internal) segment_id: usize,
        pub(in crate::internal) user_master_public_key: PublicKey,
        pub(in crate::internal) user_private_key: EncryptedPrivateKey,
        pub(in crate::internal) needs_rotation: bool,
        pub(in crate::internal) groups_needing_rotation: Vec<String>,
    }

    pub async fn get_curr_user(auth: &RequestAuth) -> Result<CurrentUserResponse, IronOxideErr> {
        auth.request
            .get(
                "users/current",
                RequestErrorCode::UserGetCurrent,
                AuthV2Builder::new(&auth, Utc::now()),
            )
            .await
    }
}

/// PUT /users/{userId}/keys/{userKeyId}
pub mod user_update_private_key {
    use super::*;
    use crate::internal::user_api::UserUpdatePrivateKeyResult;

    #[derive(Serialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct UserUpdatePrivateKey {
        user_private_key: EncryptedPrivateKey,
        augmentation_factor: AugmentationFactor,
    }

    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct UserUpdatePrivateKeyResponse {
        current_key_id: u64,
        user_private_key: EncryptedPrivateKey,
        needs_rotation: bool,
    }

    impl From<UserUpdatePrivateKeyResponse> for UserUpdatePrivateKeyResult {
        fn from(resp: UserUpdatePrivateKeyResponse) -> Self {
            // don't expose the current_key_id to the outside world until we need to
            UserUpdatePrivateKeyResult {
                user_master_private_key: resp.user_private_key.into(),
                needs_rotation: resp.needs_rotation,
            }
        }
    }

    pub async fn update_private_key(
        auth: &RequestAuth,
        user_id: UserId,
        user_key_id: u64,
        new_encrypted_private_key: EncryptedPrivateKey,
        augmenting_key: AugmentationFactor,
    ) -> Result<UserUpdatePrivateKeyResponse, IronOxideErr> {
        auth.request
            .put(
                &format!(
                    "users/{}/keys/{}",
                    rest::url_encode(user_id.id()),
                    user_key_id
                ),
                &UserUpdatePrivateKey {
                    user_private_key: new_encrypted_private_key,
                    augmentation_factor: augmenting_key,
                },
                RequestErrorCode::UserKeyUpdate,
                AuthV2Builder::new(&auth, Utc::now()),
            )
            .await
    }
}

pub mod user_create {
    use crate::internal::{user_api::UserCreateResult, TryInto};

    use super::*;

    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct UserCreateResponse {
        id: String,
        status: usize,
        segment_id: usize,
        pub user_private_key: EncryptedPrivateKey,
        pub user_master_public_key: PublicKey,
        needs_rotation: bool,
    }

    #[derive(Serialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct UserCreateReq {
        user_public_key: PublicKey,
        user_private_key: EncryptedPrivateKey,
        needs_rotation: bool,
    }

    pub async fn user_create(
        jwt: &Jwt,
        user_public_key: PublicKey,
        encrypted_user_private_key: EncryptedPrivateKey,
        needs_rotation: bool,
        request: IronCoreRequest<'_>,
    ) -> Result<UserCreateResponse, IronOxideErr> {
        let req_body = UserCreateReq {
            user_private_key: encrypted_user_private_key,
            user_public_key,
            needs_rotation,
        };
        request
            .post_jwt_auth(
                "users",
                &req_body,
                RequestErrorCode::UserCreate,
                &Authorization::JwtAuth(jwt),
            )
            .await
    }
    impl TryFrom<UserCreateResponse> for UserCreateResult {
        type Error = IronOxideErr;

        fn try_from(resp: UserCreateResponse) -> Result<Self, Self::Error> {
            Ok(UserCreateResult {
                user_public_key: resp.user_master_public_key.try_into()?,
                needs_rotation: resp.needs_rotation,
            })
        }
    }
}

pub mod user_key_list {
    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct UserPublicKey {
        pub id: String,
        pub user_master_public_key: crate::internal::rest::json::PublicKey,
    }
    #[derive(Deserialize)]
    pub struct UserKeyListResponse {
        pub(crate) result: Vec<UserPublicKey>,
    }

    pub async fn user_key_list_request(
        auth: &RequestAuth,
        users: &Vec<UserId>,
    ) -> Result<UserKeyListResponse, IronOxideErr> {
        let user_ids: Vec<&str> = users.iter().map(|user| user.id()).collect();
        if user_ids.len() != 0 {
            auth.request
                .get_with_query_params(
                    "users".into(),
                    &vec![("id".into(), rest::url_encode(&user_ids.join(",")))],
                    RequestErrorCode::UserKeyList,
                    AuthV2Builder::new(&auth, Utc::now()),
                )
                .await
        } else {
            Ok(UserKeyListResponse { result: vec![] })
        }
    }
}

pub mod device_add {
    use crate::internal::{
        rest::json::TransformKey,
        user_api::{requests::PublicKey, DeviceAdd, DeviceId},
        Jwt,
    };

    use super::*;

    #[derive(Serialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct DeviceAddReq {
        pub timestamp: u64,
        pub device: Device,
        #[serde(with = "Base64Standard")]
        pub signature: Vec<u8>,
        pub user_public_key: PublicKey,
    }

    #[derive(Serialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct Device {
        pub transform_key: TransformKey,
        pub name: Option<DeviceName>,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct DeviceAddResponse {
        #[serde(rename = "id")]
        pub device_id: DeviceId,
        pub device_public_key: PublicKey,
    }

    pub async fn user_device_add(
        jwt: &Jwt,
        device_add: &DeviceAdd,
        name: &Option<DeviceName>,
        request: &IronCoreRequest<'_>,
    ) -> Result<DeviceAddResponse, IronOxideErr> {
        let req_body: DeviceAddReq = DeviceAddReq {
            timestamp: device_add.signature_ts.timestamp_millis() as u64,
            user_public_key: device_add.user_public_key.clone().into(),
            signature: device_add.signature.clone().into(),
            device: Device {
                transform_key: device_add.transform_key.clone().into(),
                name: name.clone(),
            },
        };
        request
            .post_jwt_auth(
                "users/devices",
                &req_body,
                RequestErrorCode::UserDeviceAdd,
                &Authorization::JwtAuth(jwt),
            )
            .await
    }
}

pub mod device_list {
    use chrono::{DateTime, Utc};

    use crate::internal::user_api::{DeviceId, DeviceName, UserDevice};

    use super::*;

    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct DeviceListItem {
        #[serde(rename = "id")]
        device_id: DeviceId,
        name: Option<DeviceName>,
        created: DateTime<Utc>,
        updated: DateTime<Utc>,
        is_current_device: bool,
    }

    #[derive(Deserialize, PartialEq, Debug)]
    pub struct DeviceListResponse {
        pub(in crate::internal) result: Vec<DeviceListItem>,
    }

    pub async fn device_list(auth: &RequestAuth) -> Result<DeviceListResponse, IronOxideErr> {
        auth.request
            .get(
                &format!("users/{}/devices", rest::url_encode(&auth.account_id().0)),
                RequestErrorCode::UserDeviceList,
                AuthV2Builder::new(&auth, Utc::now()),
            )
            .await
    }

    impl From<DeviceListItem> for UserDevice {
        fn from(resp: DeviceListItem) -> Self {
            UserDevice {
                id: resp.device_id,
                name: resp.name,
                created: resp.created,
                last_updated: resp.updated,
                is_current_device: resp.is_current_device,
            }
        }
    }
}

pub mod device_delete {
    use super::*;
    use crate::{internal::user_api::DeviceId, IronOxideErr};

    #[derive(Deserialize)]
    pub struct DeviceDeleteResponse {
        pub(crate) id: DeviceId,
    }

    pub async fn device_delete(
        auth: &RequestAuth,
        device_id: &DeviceId,
    ) -> Result<DeviceDeleteResponse, IronOxideErr> {
        auth.request
            .delete_with_no_body(
                &format!(
                    "users/{}/devices/{}",
                    rest::url_encode(&auth.account_id().0),
                    device_id.0
                ),
                RequestErrorCode::UserDeviceDelete,
                AuthV2Builder::new(&auth, Utc::now()),
            )
            .await
    }

    pub async fn device_delete_current(
        auth: &RequestAuth,
    ) -> Result<DeviceDeleteResponse, IronOxideErr> {
        auth.request
            .delete_with_no_body(
                &format!(
                    "users/{}/devices/current",
                    rest::url_encode(&auth.account_id().0)
                ),
                RequestErrorCode::UserDeviceDelete,
                AuthV2Builder::new(&auth, Utc::now()),
            )
            .await
    }
}
