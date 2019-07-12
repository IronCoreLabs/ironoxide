use crate::{
    crypto::aes::{self, EncryptedMasterKey},
    internal::{rest::IronCoreRequest, *},
};
use chrono::{DateTime, Utc};
use futures::prelude::*;
use itertools::{Either, Itertools};
use recrypt::prelude::*;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    result::Result,
};

/// private module that handles interaction with ironcore-id
mod requests;

/// ID of a user. Unique with in a segment. Must match the regex `^[a-zA-Z0-9_.$#|@/:;=+'-]+$`
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone, Eq, Hash)]
pub struct UserId(pub(crate) String);
impl UserId {
    pub fn id(&self) -> &str {
        &self.0
    }

    /// Create a UserId from a string with no validation. Useful for ids coming back from the web service.
    pub fn unsafe_from_string(id: String) -> UserId {
        UserId(id)
    }
}
impl TryFrom<String> for UserId {
    type Error = IronOxideErr;
    fn try_from(user_id: String) -> Result<Self, Self::Error> {
        user_id.as_str().try_into()
    }
}
impl TryFrom<&str> for UserId {
    type Error = IronOxideErr;
    fn try_from(user_id: &str) -> Result<Self, Self::Error> {
        validate_id(user_id, "user_id").map(UserId)
    }
}

/// Device ID type. Validates that the provided ID is greater than 0
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct DeviceId(pub(crate) u64);
impl DeviceId {
    pub fn id(&self) -> &u64 {
        &self.0
    }
}
impl TryFrom<u64> for DeviceId {
    type Error = IronOxideErr;
    fn try_from(device_id: u64) -> Result<Self, Self::Error> {
        //Validate the range of the device ID to always be positive, but also be
        //less than i64 (i.e. no high bit set) for compatibility with other
        //languages (i.e. Java)
        if device_id < 1 || device_id > (std::i64::MAX as u64) {
            Err(IronOxideErr::ValidationError(
                "device_id".to_string(),
                format!("'{}' must be a number greater than 0", device_id),
            ))
        } else {
            Ok(DeviceId(device_id))
        }
    }
}

/// Device name type. Validates that the provided name isn't an empty string
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceName(pub(crate) String);
impl DeviceName {
    pub fn name(&self) -> &String {
        &self.0
    }
}
impl TryFrom<&str> for DeviceName {
    type Error = IronOxideErr;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        validate_name(name, "device_name").map(DeviceName)
    }
}

/// Keypair for a newly created user
#[derive(Debug)]
pub struct UserCreateKeyPair {
    /// user's private key encrypted with the provided passphrase
    user_encrypted_master_key: EncryptedMasterKey,
    user_public_key: PublicKey,
}

impl UserCreateKeyPair {
    pub fn user_encrypted_master_key(&self) -> &EncryptedMasterKey {
        &self.user_encrypted_master_key
    }

    pub fn user_encrypted_master_key_bytes(&self) -> [u8; 92] {
        self.user_encrypted_master_key.bytes()
    }

    pub fn user_public_key(&self) -> &PublicKey {
        &self.user_public_key
    }
}

/// Bundle of information for adding a device
pub struct DeviceAdd {
    /// public key of the user
    user_public_key: PublicKey,
    /// transform key from user private key to the device public key
    transform_key: TransformKey,
    /// public/private keypair for the device
    device_keys: KeyPair,
    /// signing keypair for the device, used for device auth'd requests
    signing_keys: DeviceSigningKeyPair,
    /// signature needed for device auth'd requests
    signature: SchnorrSignature,
    /// timestamp used in the schnorr signature
    signature_ts: DateTime<Utc>,
}

/// IDs and public key for existing user on verify result
#[derive(Debug)]
pub struct UserVerifyResult {
    account_id: UserId,
    segment_id: usize,
    user_public_key: PublicKey,
}
impl UserVerifyResult {
    pub fn user_public_key(&self) -> &PublicKey {
        &self.user_public_key
    }

    pub fn account_id(&self) -> &UserId {
        &self.account_id
    }

    pub fn segment_id(&self) -> usize {
        self.segment_id
    }
}

#[derive(Debug)]
/// Devices for a user, sorted by the device id
pub struct UserDeviceListResult {
    result: Vec<UserDevice>,
}
impl UserDeviceListResult {
    fn new(result: Vec<UserDevice>) -> UserDeviceListResult {
        UserDeviceListResult { result }
    }

    pub fn result(&self) -> &Vec<UserDevice> {
        &self.result
    }
}

#[derive(Clone, PartialEq, Debug)]
/// Metadata about a user device
pub struct UserDevice {
    id: DeviceId,
    name: Option<DeviceName>,
    /// time the device was created
    created: DateTime<Utc>,
    /// time the device was last updated
    last_updated: DateTime<Utc>,
    /// true if this UserDevice is the device making the query
    is_current_device: bool,
}
impl UserDevice {
    /// Get the unique id for the device
    pub fn id(&self) -> &DeviceId {
        &self.id
    }
    /// Get the devices optional non-unique readable name
    pub fn name(&self) -> Option<&DeviceName> {
        self.name.as_ref()
    }
    /// Get the time the device was created
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }
    /// Get the time the device was last updated
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.last_updated
    }
    /// Determine whether this device instance is the one that was used to make
    /// the API request
    pub fn is_current_device(&self) -> bool {
        self.is_current_device
    }
}

/// Verify an existing user given a valid JWT.
pub fn user_verify(
    jwt: Jwt,
    request: IronCoreRequest,
) -> impl Future<Item = Option<UserVerifyResult>, Error = IronOxideErr> {
    requests::user_verify::user_verify(&jwt, &request)
        .and_then(|e| e.map(|resp| resp.try_into()).transpose())
}

/// Create a user
pub fn user_create<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    jwt: Jwt,
    passphrase: Password,
    request: IronCoreRequest<'static>,
) -> impl Future<Item = UserCreateKeyPair, Error = IronOxideErr> {
    recrypt
        .generate_key_pair()
        .map_err(IronOxideErr::from)
        .and_then(|(recrypt_priv, recrypt_pub)| {
            Ok(aes::encrypt_user_master_key(
                &mut rand::thread_rng(),
                passphrase.0.as_str(),
                recrypt_priv.bytes(),
            )
            .map(|encrypted_private_key| (encrypted_private_key, recrypt_pub))?)
        })
        .into_future()
        .and_then(move |(encrypted_priv_key, recrypt_pub)| {
            requests::user_create::user_create(
                &jwt,
                recrypt_pub.into(),
                encrypted_priv_key.into(),
                request,
            )
        })
        .and_then(|resp| resp.try_into())
}

/// Generate a device key for the user specified in the JWT.
pub fn generate_device_key<'a, CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &'a mut Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    jwt: &'a Jwt,
    password: Password,
    device_name: Option<DeviceName>,
    signing_ts: &'a DateTime<Utc>,
    request: IronCoreRequest<'static>,
) -> impl Future<Item = DeviceContext, Error = IronOxideErr> + 'a {
    // verify that this user exists
    requests::user_verify::user_verify(&jwt, &request)
        .and_then(|maybe_user| {
            maybe_user.ok_or(IronOxideErr::UserDoesNotExist(
                "Device cannot be added to a user that doesn't exist".to_string(),
            ))
        })
        // unpack the verified user and create a DeviceAdd
        .and_then(
            move |requests::user_verify::UserVerifyResponse {
                      user_private_key,
                      user_master_public_key,
                      id: account_id,
                      segment_id,
                      ..
                  }| {
                Ok((
                    {
                        let user_public_key: RecryptPublicKey =
                            PublicKey::try_from(user_master_public_key)?.into();
                        let user_private_key =
                            EncryptedMasterKey::new_from_slice(&user_private_key.0)?;

                        // decrypt the user's master key using the provided password
                        let user_private_key =
                            aes::decrypt_user_master_key(&password.0, &user_private_key)?;

                        let user_keypair: KeyPair =
                            KeyPair::new(user_public_key, RecryptPrivateKey::new(user_private_key));

                        // generate info needed to add a device
                        let device_add =
                            generate_device_add(recrypt, &jwt, &user_keypair, &signing_ts)?;
                        device_add
                    },
                    account_id.try_into()?,
                    segment_id,
                ))
            },
        )
        // call device_add
        .and_then(move |(device_add, account_id, segment_id)| {
            // discard successful response as it only has the device public key in it, which we already have
            requests::device_add::user_device_add(&jwt, &device_add, &device_name, &request)
                // on successful response, assemble a DeviceContext for the caller
                .map(move |_| {
                    DeviceContext::new(
                        account_id,
                        segment_id,
                        device_add.device_keys.private_key,
                        device_add.signing_keys,
                    )
                })
        })
}

pub fn device_list(
    auth: &RequestAuth,
) -> impl Future<Item = UserDeviceListResult, Error = IronOxideErr> {
    requests::device_list::device_list(auth).map(|resp| {
        let mut vec: Vec<UserDevice> = resp.result.into_iter().map(UserDevice::from).collect();
        // sort the devices by device_id
        vec.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        UserDeviceListResult::new(vec)
    })
}

pub fn device_delete(
    auth: &RequestAuth,
    device_id: Option<&DeviceId>,
) -> impl Future<Item = DeviceId, Error = IronOxideErr> {
    match device_id {
        Some(device_id) => requests::device_delete::device_delete(auth, device_id),
        None => requests::device_delete::device_delete_current(auth),
    }
    .map(|resp| resp.id)
}

/// Get a list of users public keys given a list of user account IDs
pub fn user_key_list<'a>(
    auth: &RequestAuth,
    user_ids: &'a Vec<UserId>,
) -> impl Future<Item = HashMap<UserId, PublicKey>, Error = IronOxideErr> + 'a {
    requests::user_key_list::user_key_list_request(auth, user_ids).map(
        move |requests::user_key_list::UserKeyListResponse { result }| {
            result
                .into_iter()
                .fold(HashMap::with_capacity(user_ids.len()), |mut acc, user| {
                    let maybe_pub_key = PublicKey::try_from(user.user_master_public_key.clone());
                    maybe_pub_key.into_iter().for_each(|pub_key| {
                        //We asked the api for valid user ids. We're assuming here that the response has valid user ids.
                        acc.insert(UserId::unsafe_from_string(user.id.clone()), pub_key);
                    });
                    acc
                })
        },
    )
}

///Get the keys for users. The result should be either a failure for a specific UserId (Left) or the id with their public key (Right).
/// The resulting lists will have the same combined size as the incoming list.
/// Calling this with an empty `users` list will not result in a call to the server.
pub(crate) fn get_user_keys<'a>(
    auth: &'a RequestAuth,
    users: &'a Vec<UserId>,
) -> Box<Future<Item = (Vec<UserId>, Vec<WithKey<UserId>>), Error = IronOxideErr> + 'a> {
    // if there aren't any users in the list, just return with empty results
    if users.len() == 0 {
        return Box::new(futures::future::ok((vec![], vec![])));
    }

    let cloned_users = users.clone();
    let fetch_users = user_api::user_key_list(auth, &users);
    Box::new(fetch_users.map(|ids_with_keys| {
        cloned_users.into_iter().partition_map(|user_id| {
            let maybe_public_key = ids_with_keys.get(&user_id).cloned();
            match maybe_public_key {
                Some(pk) => Either::Right(WithKey::new(user_id, pk)),
                None => Either::Left(user_id),
            }
        })
    }))
}

/// Generate all the necessary device keys, transform keys, and signatures to be able to add a new user device.
/// Specifically, it creates a device key pair and signing key pair, then a transform key between the provided
/// user private key and device public key. Also generated is a device add signature that is necessary to hit the API.
fn generate_device_add<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    jwt: &Jwt,
    user_master_keypair: &KeyPair,
    signing_ts: &DateTime<Utc>,
) -> Result<DeviceAdd, IronOxideErr> {
    let signing_keypair = recrypt.generate_ed25519_key_pair();
    let (recrypt_priv_key, recrypt_pub_key) = recrypt.generate_key_pair()?;
    let device_keypair = KeyPair::new(recrypt_pub_key, recrypt_priv_key);

    // generate a transform key from the user's private key to the new device
    let trans_key: TransformKey = recrypt
        .generate_transform_key(
            &user_master_keypair.private_key().recrypt_key(),
            &device_keypair.public_key().into(),
            &signing_keypair,
        )?
        .into();

    let sig = gen_device_add_signature(recrypt, jwt, &user_master_keypair, &trans_key, signing_ts);
    Ok(DeviceAdd {
        user_public_key: user_master_keypair.public_key().clone(),
        transform_key: trans_key.into(),
        device_keys: device_keypair.into(),
        signing_keys: signing_keypair.into(),
        signature: sig,
        signature_ts: signing_ts.to_owned(),
    })
}

/// Generate a schnorr signature for calling the device add endpoint in ironcore-id
fn gen_device_add_signature<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &mut Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    jwt: &Jwt,
    user_master_keypair: &KeyPair,
    transform_key: &TransformKey,
    signing_ts: &DateTime<Utc>,
) -> SchnorrSignature {
    struct SignedMessage<'a> {
        timestamp: &'a DateTime<Utc>,
        transform_key: &'a TransformKey,
        jwt: &'a Jwt,
        user_public_key: &'a PublicKey,
    };

    impl<'a> recrypt::api::Hashable for SignedMessage<'a> {
        fn to_bytes(&self) -> Vec<u8> {
            let mut vec: Vec<u8> = vec![];
            vec.extend_from_slice(&self.timestamp.timestamp_millis().to_string().as_bytes());
            vec.extend_from_slice(&self.transform_key.to_bytes());
            vec.extend_from_slice(&self.jwt.to_utf8());
            vec.extend_from_slice(&self.user_public_key.as_bytes());
            vec
        }
    }

    let msg = SignedMessage {
        timestamp: signing_ts,
        transform_key,
        jwt,
        user_public_key: &user_master_keypair.public_key(),
    };

    recrypt
        .schnorr_sign(
            &user_master_keypair.private_key().recrypt_key(),
            &user_master_keypair.public_key().into(),
            &msg,
        )
        .into()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn user_id_validate_good() {
        let user_id1 = "a_fo_real_good_group_id$";
        let user_id2 = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        assert_eq!(
            UserId(user_id1.to_string()),
            UserId::try_from(user_id1).unwrap()
        );
        assert_eq!(
            UserId(user_id2.to_string()),
            UserId::try_from(user_id2).unwrap()
        )
    }

    #[test]
    fn user_id_rejects_invalid() {
        let user_id1 = UserId::try_from("not a good ID!");
        let user_id2 = UserId::try_from("!!");
        let user_id3 = UserId::try_from("01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567891");

        assert_that!(
            &user_id1.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(
            &user_id2.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(
            &user_id3.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
    }

    #[test]
    fn user_id_rejects_empty() {
        let user_id = UserId::try_from("");
        assert_that!(&user_id, is_variant!(Err));
        assert_that!(
            &user_id.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );

        let user_id = UserId::try_from("\n \t  ");
        assert_that!(&user_id, is_variant!(Err));
        assert_that!(
            &user_id.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
    }
}
