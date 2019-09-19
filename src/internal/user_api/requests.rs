//! User operation requests.
//! Types and functions defined here should remain private to `user_api`

use chrono::Utc;
use futures::Future;

use crate::{
    crypto::aes::EncryptedMasterKey,
    internal::{
        rest::{
            self,
            json::{Base64Standard, PublicKey},
            Authorization, IronCoreRequest,
        },
        user_api::{DeviceName, UserId},
        IronOxideErr, Jwt, RequestAuth, RequestErrorCode, TryFrom,
    },
};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct PrivateKey(#[serde(with = "Base64Standard")] pub Vec<u8>);

impl From<EncryptedMasterKey> for PrivateKey {
    fn from(enc_master_key: EncryptedMasterKey) -> Self {
        PrivateKey(enc_master_key.bytes().to_vec())
    }
}

impl TryFrom<PrivateKey> for EncryptedMasterKey {
    type Error = IronOxideErr;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        EncryptedMasterKey::new_from_slice(&value.0)
    }
}

pub mod user_verify {
    use crate::internal::{user_api::UserVerifyResult, TryInto};

    use super::*;

    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct UserVerifyResponse {
        pub(crate) id: String,
        status: usize,
        pub(crate) segment_id: usize,
        pub(crate) user_private_key: PrivateKey,
        pub(crate) user_master_public_key: PublicKey,
        pub(crate) needs_rotation: bool,
    }

    pub fn user_verify(
        jwt: &Jwt,
        request: &IronCoreRequest,
    ) -> impl Future<Item = Option<UserVerifyResponse>, Error = IronOxideErr> {
        request.get_with_empty_result(
            "users/verify?returnKeys=true",
            RequestErrorCode::UserVerify,
            &Authorization::JwtAuth(jwt),
        )
    }

    impl TryFrom<UserVerifyResponse> for UserVerifyResult {
        type Error = IronOxideErr;

        fn try_from(body: UserVerifyResponse) -> Result<Self, Self::Error> {
            Ok(UserVerifyResult {
                account_id: body.id.try_into()?,
                segment_id: body.segment_id,
                user_public_key: body.user_master_public_key.try_into()?,
                needs_rotation: body.needs_rotation,
            })
        }
    }
    mod test {
        use super::*;
        use recrypt::prelude::*;
        use crate::internal;

        #[test]
        fn user_verify_resp_to_result() {
            let mut r = recrypt::api::Recrypt::new();
            let (, pk) = r.generate_key_pair().unwrap();

            //            UserVerifyResponse {
            //                id: "valid_user_id".to_string(),
            //                status: 100
            //                segment_id: 200,
            //                user_private_key
            //            }
        }
    }
}

pub mod user_create {
    use crate::internal::{user_api::UserCreateKeyPair, TryInto};

    use super::*;

    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct UserCreateResponse {
        id: String,
        status: usize,
        segment_id: usize,
        pub user_private_key: PrivateKey,
        pub user_master_public_key: PublicKey,
        needs_rotation: bool,
    }

    #[derive(Serialize, Debug)]
    #[serde(rename_all = "camelCase")]
    struct UserCreateReq {
        user_public_key: PublicKey,
        user_private_key: PrivateKey,
        needs_rotation: bool,
    }

    pub fn user_create(
        jwt: &Jwt,
        user_public_key: PublicKey,
        encrypted_user_private_key: PrivateKey,
        needs_rotation: bool,
        request: IronCoreRequest,
    ) -> impl Future<Item = UserCreateResponse, Error = IronOxideErr> {
        let req_body = UserCreateReq {
            user_private_key: encrypted_user_private_key,
            user_public_key,
            needs_rotation,
        };
        request.post(
            "users",
            &req_body,
            RequestErrorCode::UserCreate,
            &Authorization::JwtAuth(jwt),
        )
    }
    impl TryFrom<UserCreateResponse> for UserCreateKeyPair {
        type Error = IronOxideErr;

        fn try_from(resp: UserCreateResponse) -> Result<Self, Self::Error> {
            Ok(UserCreateKeyPair {
                user_encrypted_master_key: resp.user_private_key.try_into()?,
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

    pub fn user_key_list_request(
        auth: &RequestAuth,
        users: &Vec<UserId>,
    ) -> impl Future<Item = UserKeyListResponse, Error = IronOxideErr> {
        let encoded_user_ids: Vec<_> = users.iter().map(|user| rest::url_encode(&user.0)).collect();

        auth.request.get(
            &format!("users?id={}", encoded_user_ids.join(",")),
            RequestErrorCode::UserKeyList,
            &auth.create_signature(Utc::now()),
        )
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

    pub fn user_device_add(
        jwt: &Jwt,
        device_add: &DeviceAdd,
        name: &Option<DeviceName>,
        request: &IronCoreRequest,
    ) -> impl Future<Item = DeviceAddResponse, Error = IronOxideErr> {
        let req_body: DeviceAddReq = DeviceAddReq {
            timestamp: device_add.signature_ts.timestamp_millis() as u64,
            user_public_key: device_add.user_public_key.clone().into(),
            signature: device_add.signature.clone().into(),
            device: Device {
                transform_key: device_add.transform_key.clone().into(),
                name: name.clone(),
            },
        };
        request.post(
            "users/devices",
            &req_body,
            RequestErrorCode::UserDeviceAdd,
            &Authorization::JwtAuth(jwt),
        )
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
        pub result: Vec<DeviceListItem>,
    }

    pub fn device_list(
        auth: &RequestAuth,
    ) -> impl Future<Item = DeviceListResponse, Error = IronOxideErr> {
        auth.request.get(
            &format!("users/{}/devices", rest::url_encode(&auth.account_id().0)),
            RequestErrorCode::UserDeviceList,
            &auth.create_signature(Utc::now()),
        )
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

    pub fn device_delete(
        auth: &RequestAuth,
        device_id: &DeviceId,
    ) -> Box<dyn Future<Item = DeviceDeleteResponse, Error = IronOxideErr>> {
        Box::new(auth.request.delete_with_no_body(
            &format!(
                "users/{}/devices/{}",
                rest::url_encode(&auth.account_id().0),
                device_id.0
            ),
            RequestErrorCode::UserDeviceDelete,
            &auth.create_signature(Utc::now()),
        ))
    }

    pub fn device_delete_current(
        auth: &RequestAuth,
    ) -> Box<dyn Future<Item = DeviceDeleteResponse, Error = IronOxideErr>> {
        Box::new(auth.request.delete_with_no_body(
            &format!(
                "users/{}/devices/current",
                rest::url_encode(&auth.account_id().0)
            ),
            RequestErrorCode::UserDeviceDelete,
            &auth.create_signature(Utc::now()),
        ))
    }
}
