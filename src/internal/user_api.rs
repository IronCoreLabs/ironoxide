use crate::{
    crypto::aes::{self, EncryptedMasterKey},
    internal::{rest::IronCoreRequest, *},
};
use itertools::{Either, Itertools};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rand::rngs::OsRng;
use recrypt::prelude::*;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    result::Result,
    sync::Mutex,
};
use time::OffsetDateTime;

/// private module that handles interaction with the IronCore webservice
mod requests;

/// ID of a user.
///
/// The ID can be validated from a `String` or `&str` using `UserId::try_from`.
///
/// # Requirements
/// - Must be unique within the user's segment.
/// - Must match the regex `^[a-zA-Z0-9_.$#|@/:;=+'-]+$`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct UserId(pub(crate) String);
impl UserId {
    /// Constructs a `UserId` with no validation. Useful for IDs coming back from the web service.
    pub fn unsafe_from_string(id: String) -> UserId {
        UserId(id)
    }
    /// ID of the user
    pub fn id(&self) -> &str {
        &self.0
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

/// ID of a device.
///
/// The ID can be validated from a `u64` using `DeviceId::try_from`.
///
/// # Requirements
/// - Must be greater than 0.
/// - Must be less than or equal to `i64::max_value()`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DeviceId(pub(crate) u64);
impl DeviceId {
    /// ID of the device
    pub fn id(&self) -> &u64 {
        &self.0
    }
}
impl TryFrom<u64> for DeviceId {
    type Error = IronOxideErr;
    fn try_from(device_id: u64) -> Result<Self, Self::Error> {
        // Validate the range of the device ID to always be positive, but also be
        // less than i64 (i.e. no high bit set) for compatibility with other
        // languages (i.e. Java)
        if device_id < 1 || device_id > (i64::max_value() as u64) {
            Err(IronOxideErr::ValidationError(
                "device_id".to_string(),
                format!("'{}' must be a number greater than 0", device_id),
            ))
        } else {
            Ok(DeviceId(device_id))
        }
    }
}

/// Name of a device.
///
/// The name can be validated from a `String` or `&str` using `DeviceName::try_from`.
///
/// # Requirements
/// - Must be between 1 and 100 characters long.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceName(pub(crate) String);
impl DeviceName {
    /// Name of the device
    pub fn name(&self) -> &String {
        &self.0
    }
}
impl TryFrom<String> for DeviceName {
    type Error = IronOxideErr;
    fn try_from(device_name: String) -> Result<Self, Self::Error> {
        device_name.as_str().try_into()
    }
}
impl TryFrom<&str> for DeviceName {
    type Error = IronOxideErr;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        validate_name(name, "device_name").map(DeviceName)
    }
}

/// Metadata for a newly created user.
///
/// Includes the user's public key and whether the user's private key needs rotation.
///
/// Result from [user_create](trait.UserOps.html#tymethod.user_create).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserCreateResult {
    user_public_key: PublicKey,
    needs_rotation: bool,
}

impl UserCreateResult {
    /// Public key for the user
    ///
    /// For most use cases, this public key can be discarded, as IronCore escrows the user's keys. The escrowed keys are unlocked
    /// by the provided password.
    pub fn user_public_key(&self) -> &PublicKey {
        &self.user_public_key
    }
    /// Whether the user's private key needs to be rotated
    pub fn needs_rotation(&self) -> bool {
        self.needs_rotation
    }
}

/// Public and private key pair used for document encryption and decryption.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}
impl KeyPair {
    /// Constructs a new `KeyPair` from the `recrypt` versions of the public and private keys.
    pub fn new(public_key: RecryptPublicKey, private_key: RecryptPrivateKey) -> Self {
        KeyPair {
            public_key: public_key.into(),
            private_key: private_key.into(),
        }
    }
    /// Public key of the user
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
    /// Private key of the user
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

/// Bundle of information for adding a device
pub(crate) struct DeviceAdd {
    /// Public key of the user
    user_public_key: PublicKey,
    /// Transform key from the user's private key to the device's public key
    transform_key: TransformKey,
    /// Public/private encryption key pair for the device
    device_keys: KeyPair,
    /// Signing key pair for the device, used for authorized device requests
    signing_keys: DeviceSigningKeyPair,
    /// Signature needed for authorized device requests
    signature: SchnorrSignature,
    /// Timestamp used in the schnorr signature
    signature_ts: OffsetDateTime,
}

/// Metadata for a user.
///
/// Result from [user_verify](trait.UserOps.html#tymethod.user_verify).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserResult {
    account_id: UserId,
    segment_id: usize,
    user_public_key: PublicKey,
    needs_rotation: bool,
}
impl UserResult {
    /// ID of the user
    pub fn account_id(&self) -> &UserId {
        &self.account_id
    }
    /// Public key of the user
    pub fn user_public_key(&self) -> &PublicKey {
        &self.user_public_key
    }
    /// Segment ID for the user
    pub fn segment_id(&self) -> usize {
        self.segment_id
    }
    /// Whether the user's private key needs rotation
    pub fn needs_rotation(&self) -> bool {
        self.needs_rotation
    }
}

/// Metadata for each device the user has authorized.
///
/// The results are sorted based on the device's ID.
///
/// Result from [user_list_devices](trait.UserOps.html#tymethod.user_list_devices).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserDeviceListResult {
    result: Vec<UserDevice>,
}
impl UserDeviceListResult {
    fn new(result: Vec<UserDevice>) -> UserDeviceListResult {
        UserDeviceListResult { result }
    }
    /// Metadata for each device the user has authorized
    pub fn result(&self) -> &Vec<UserDevice> {
        &self.result
    }
}

/// Metadata for a device.
///
/// Result from [`UserDeviceListResult.result()](struct.UserDeviceListResult.html#method.result).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserDevice {
    id: DeviceId,
    name: Option<DeviceName>,
    /// time the device was created
    created: OffsetDateTime,
    /// time the device was last updated
    last_updated: OffsetDateTime,
    /// true if this UserDevice is the device making the query
    is_current_device: bool,
}
impl UserDevice {
    /// ID of the device
    pub fn id(&self) -> &DeviceId {
        &self.id
    }
    /// Name of the device
    pub fn name(&self) -> Option<&DeviceName> {
        self.name.as_ref()
    }
    /// Date and time when the device was created
    pub fn created(&self) -> &OffsetDateTime {
        &self.created
    }
    /// Date and time when the device was last updated
    pub fn last_updated(&self) -> &OffsetDateTime {
        &self.last_updated
    }
    /// Whether this is the device that was used to make the API request
    pub fn is_current_device(&self) -> bool {
        self.is_current_device
    }
}

/// Claims required to form a valid [Jwt](struct.Jwt.html).
///
/// These are a mixture of public claims (predefined by the JWT standard - sub, iat, exp)
/// and private claims (pid, sid, kid, uid). The private claims can be protected from
/// collision by prefixing the claim names with "http://ironcore/". Some JWT generators
/// such as Auth0 require a namespace on private claims.
/// Note that the uid claim is a claim that is added by Auth0 - the sub claim is populated
/// by the identity provider (if Auth0 is doing authentication via GitHub or another IDP),
/// and the user's ID (email address) is placed in the uid claim. The Identity service
/// currently looks for the uid claim, and if it is present, uses that instead of the sub
/// claim as the source of the user's provided ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Unique user ID
    pub sub: String,
    /// Issued time (seconds)
    pub iat: u64,
    /// Expiration time (seconds)
    ///
    /// We recommend it be set to `iat + 120`. The IronCore server will not use the value,
    /// and it will automatically reject JWTs that are received more than 120 seconds past `iat`.
    pub exp: u64,
    /// Project ID
    #[serde(alias = "http://ironcore/pid")]
    pub pid: u32,
    /// Segment ID
    #[serde(alias = "http://ironcore/sid")]
    pub sid: String,
    /// Service key ID
    #[serde(alias = "http://ironcore/kid")]
    pub kid: u32,
    /// User ID
    #[serde(alias = "http://ironcore/uid")]
    pub uid: Option<String>,
}

/// IronCore JWT.
///
/// Must be either ES256 or RS256 and have a payload similar to [JwtClaims](struct.JwtClaims.html), but could be
/// generated from an external source.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Jwt {
    jwt: String,
    header: jsonwebtoken::Header,
    claims: JwtClaims,
}
impl Jwt {
    /// Constructs a new Jwt.
    ///
    /// Verifies that the provided jwt uses a compatible algorithm and contains the required claims.
    pub fn new(jwt: &str) -> Result<Jwt, IronOxideErr> {
        let bogus_key = DecodingKey::from_secret(&[]);
        let validation = {
            let mut temp: Validation = Default::default();
            temp.insecure_disable_signature_validation();
            temp.validate_exp = false;
            temp
        };
        // This suspect key/validation is acceptable here because the server will do the actual
        // signature verification and validation. We just want to do a little initial validation
        // to catch issues earlier.
        let token_data = jsonwebtoken::decode::<JwtClaims>(jwt, &bogus_key, &validation)
            .map_err(|e| IronOxideErr::ValidationError("jwt".to_string(), e.to_string()))?;
        let alg = token_data.header.alg;
        if alg == Algorithm::ES256 || alg == Algorithm::RS256 {
            Ok(Jwt {
                jwt: jwt.to_string(),
                header: token_data.header,
                claims: token_data.claims,
            })
        } else {
            Err(IronOxideErr::ValidationError(
                "jwt".to_string(),
                "Unsupported JWT algorithm. Supported algorithms: ES256 and RS256.".to_string(),
            ))
        }
    }

    /// Raw JWT
    pub fn jwt(&self) -> &str {
        self.jwt.as_str()
    }

    /// JWT claims
    pub fn claims(&self) -> &JwtClaims {
        &self.claims
    }

    /// JWT header
    pub fn header(&self) -> &jsonwebtoken::Header {
        &self.header
    }

    fn to_utf8(&self) -> Vec<u8> {
        self.jwt.as_bytes().to_vec()
    }
}
impl TryFrom<String> for Jwt {
    type Error = IronOxideErr;
    fn try_from(maybe_jwt: String) -> Result<Self, Self::Error> {
        Jwt::new(&maybe_jwt)
    }
}
impl TryFrom<&str> for Jwt {
    type Error = IronOxideErr;
    fn try_from(maybe_jwt: &str) -> Result<Self, Self::Error> {
        Jwt::new(maybe_jwt)
    }
}
impl std::fmt::Display for Jwt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.jwt)
    }
}

/// Verify an existing user given a valid JWT.
pub async fn user_verify(
    jwt: &Jwt,
    request: IronCoreRequest,
) -> Result<Option<UserResult>, IronOxideErr> {
    requests::user_verify::user_verify(jwt, &request)
        .await?
        .map(|resp| resp.try_into())
        .transpose()
}

/// Create a user
pub async fn user_create<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    jwt: &Jwt,
    passphrase: Password,
    needs_rotation: bool,
    request: IronCoreRequest,
) -> Result<UserCreateResult, IronOxideErr> {
    let (encrypted_priv_key, recrypt_pub) = recrypt
        .generate_key_pair()
        .map_err(IronOxideErr::from)
        .and_then(|(recrypt_priv, recrypt_pub)| {
            Ok(aes::encrypt_user_master_key(
                &Mutex::new(rand::thread_rng()),
                passphrase.0.as_str(),
                recrypt_priv.bytes(),
            )
            .map(|encrypted_private_key| (encrypted_private_key, recrypt_pub))?)
        })?;

    requests::user_create::user_create(
        jwt,
        recrypt_pub.into(),
        encrypted_priv_key.into(),
        needs_rotation,
        request,
    )
    .await?
    .try_into()
}

/// A user's encrypted private key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EncryptedPrivateKey(Vec<u8>);
impl EncryptedPrivateKey {
    /// The bytes of the user's encrypted private key
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Metadata from user private key rotation.
///
/// Result from [user_rotate_private_key](trait.UserOps.html#tymethod.user_rotate_private_key).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserUpdatePrivateKeyResult {
    user_master_private_key: EncryptedPrivateKey,
    needs_rotation: bool,
}
impl UserUpdatePrivateKeyResult {
    /// Updated encrypted private key of the user
    pub fn user_master_private_key(&self) -> &EncryptedPrivateKey {
        &self.user_master_private_key
    }
    /// Whether this user's private key needs further rotation
    pub fn needs_rotation(&self) -> bool {
        self.needs_rotation
    }
}

/// Get metadata about the current user
pub async fn user_get_current(auth: &RequestAuth) -> Result<UserResult, IronOxideErr> {
    requests::user_get::get_curr_user(auth)
        .await
        .and_then(|result| {
            Ok(UserResult {
                needs_rotation: result.needs_rotation,
                user_public_key: result.user_master_public_key.try_into()?,
                segment_id: result.segment_id,
                account_id: result.id,
            })
        })
}

/// Rotate the user's private key. The public key for the user remains unchanged.
pub async fn user_rotate_private_key<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    password: Password,
    auth: &RequestAuth,
) -> Result<UserUpdatePrivateKeyResult, IronOxideErr> {
    let requests::user_get::CurrentUserResponse {
        user_private_key: encrypted_priv_key,
        current_key_id,
        id: curr_user_id,
        ..
    } = requests::user_get::get_curr_user(auth).await?;
    let (user_id, curr_key_id, new_encrypted_priv_key, aug_factor) = {
        let priv_key: PrivateKey = aes::decrypt_user_master_key(
            &password.0,
            &aes::EncryptedMasterKey::new_from_slice(&encrypted_priv_key.0)?,
        )?
        .into();

        let (new_priv_key, aug_factor) = augment_private_key_with_retry(recrypt, &priv_key)?;
        let new_encrypted_priv_key = aes::encrypt_user_master_key(
            &Mutex::new(OsRng::default()),
            &password.0,
            new_priv_key.as_bytes(),
        )?;
        (
            curr_user_id,
            current_key_id,
            new_encrypted_priv_key,
            aug_factor,
        )
    };
    Ok(requests::user_update_private_key::update_private_key(
        auth,
        user_id,
        curr_key_id,
        new_encrypted_priv_key.into(),
        aug_factor.into(),
    )
    .await?
    .into())
}

/// Metadata for a newly created device.
///
/// Can be converted into a `DeviceContext` with `DeviceContext::from`.
///
/// Result from [generate_new_device](trait.UserOps.html#tymethod.generate_new_device).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DeviceAddResult {
    account_id: UserId,
    segment_id: usize,
    device_private_key: PrivateKey,
    signing_private_key: DeviceSigningKeyPair,
    device_id: DeviceId,
    name: Option<DeviceName>,
    created: OffsetDateTime,
    last_updated: OffsetDateTime,
}
impl DeviceAddResult {
    /// ID of the device
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }
    /// Name of the device
    pub fn name(&self) -> Option<&DeviceName> {
        self.name.as_ref()
    }
    /// ID of the user who owns the device
    pub fn account_id(&self) -> &UserId {
        &self.account_id
    }
    /// Segment of the user
    pub fn segment_id(&self) -> usize {
        self.segment_id
    }
    /// The signing key pair for the device
    pub fn signing_private_key(&self) -> &DeviceSigningKeyPair {
        &self.signing_private_key
    }
    /// Private encryption key of the device
    ///
    /// This is different from the user's private key.
    pub fn device_private_key(&self) -> &PrivateKey {
        &self.device_private_key
    }
    /// The date and time when the device was created
    pub fn created(&self) -> &OffsetDateTime {
        &self.created
    }
    /// The date and time when the device was last updated
    pub fn last_updated(&self) -> &OffsetDateTime {
        &self.last_updated
    }
}
impl From<DeviceAddResult> for DeviceContext {
    fn from(dar: DeviceAddResult) -> Self {
        DeviceContext::new(
            dar.account_id,
            dar.segment_id,
            dar.device_private_key,
            dar.signing_private_key,
        )
    }
}

/// Generate a device key for the user specified in the JWT.
pub async fn generate_device_key<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    jwt: &Jwt,
    password: Password,
    device_name: Option<DeviceName>,
    signing_ts: &OffsetDateTime,
    request: &IronCoreRequest,
) -> Result<DeviceAddResult, IronOxideErr> {
    // verify that this user exists
    let requests::user_verify::UserVerifyResponse {
        user_private_key,
        user_master_public_key,
        id: account_id,
        segment_id,
        ..
    } = requests::user_verify::user_verify(jwt, request)
        .await?
        .ok_or_else(|| {
            IronOxideErr::UserDoesNotExist(
                "Device cannot be added to a user that doesn't exist".to_string(),
            )
        })?;
    // unpack the verified user and create a DeviceAdd
    let (device_add, account_id) = (
        {
            let user_public_key: RecryptPublicKey =
                PublicKey::try_from(user_master_public_key)?.into();
            let user_private_key = EncryptedMasterKey::new_from_slice(&user_private_key.0)?;

            // decrypt the user's master key using the provided password
            let user_private_key = aes::decrypt_user_master_key(&password.0, &user_private_key)?;

            let user_keypair: KeyPair =
                KeyPair::new(user_public_key, RecryptPrivateKey::new(user_private_key));

            // generate info needed to add a device
            generate_device_add(recrypt, jwt, &user_keypair, signing_ts)?
        },
        account_id.try_into()?,
    );

    // call device_add
    let device_add_response =
        requests::device_add::user_device_add(jwt, &device_add, &device_name, request).await?;
    // on successful response, assemble a DeviceContext for the caller
    Ok(DeviceAddResult {
        account_id,
        segment_id,
        device_private_key: device_add.device_keys.private_key,
        signing_private_key: device_add.signing_keys,
        device_id: device_add_response.device_id,
        name: device_add_response.name,
        created: device_add_response.created,
        last_updated: device_add_response.updated,
    })
}

pub async fn device_list(auth: &RequestAuth) -> Result<UserDeviceListResult, IronOxideErr> {
    let resp = requests::device_list::device_list(auth).await?;
    let devices = {
        let mut vec: Vec<UserDevice> = resp.result.into_iter().map(UserDevice::from).collect();
        // sort the devices by device_id
        vec.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        vec
    };
    Ok(UserDeviceListResult::new(devices))
}

pub async fn device_delete(
    auth: &RequestAuth,
    device_id: Option<&DeviceId>,
) -> Result<DeviceId, IronOxideErr> {
    match device_id {
        Some(device_id) => requests::device_delete::device_delete(auth, device_id).await,
        None => requests::device_delete::device_delete_current(auth).await,
    }
    .map(|resp| resp.id)
}

/// Get a list of users public keys given a list of user account IDs
pub async fn user_key_list(
    auth: &RequestAuth,
    user_ids: &[UserId],
) -> Result<HashMap<UserId, PublicKey>, IronOxideErr> {
    requests::user_key_list::user_key_list_request(auth, user_ids)
        .await
        .map(
            move |requests::user_key_list::UserKeyListResponse { result }| {
                result
                    .into_iter()
                    .fold(HashMap::with_capacity(user_ids.len()), |mut acc, user| {
                        let maybe_pub_key =
                            PublicKey::try_from(user.user_master_public_key.clone());
                        maybe_pub_key.into_iter().for_each(|pub_key| {
                            //We asked the api for valid user ids. We're assuming here that the response has valid user ids.
                            acc.insert(UserId::unsafe_from_string(user.id.clone()), pub_key);
                        });
                        acc
                    })
            },
        )
}

/// Get the keys for users. The result should be either a failure for a specific UserId (Left) or the id with their public key (Right).
/// The resulting lists will have the same combined size as the incoming list.
/// Calling this with an empty `users` list will not result in a call to the server.
pub(crate) async fn get_user_keys(
    auth: &RequestAuth,
    users: &[UserId],
) -> Result<(Vec<UserId>, Vec<WithKey<UserId>>), IronOxideErr> {
    // if there aren't any users in the list, just return with empty results
    if users.is_empty() {
        Ok((vec![], vec![]))
    } else {
        user_api::user_key_list(auth, users)
            .await
            .map(|ids_with_keys| {
                users.iter().cloned().partition_map(|user_id| {
                    let maybe_public_key = ids_with_keys.get(&user_id).cloned();
                    match maybe_public_key {
                        Some(pk) => Either::Right(WithKey::new(user_id, pk)),
                        None => Either::Left(user_id),
                    }
                })
            })
    }
}

/// Generate all the necessary device keys, transform keys, and signatures to be able to add a new user device.
/// Specifically, it creates a device key pair and signing key pair, then a transform key between the provided
/// user private key and device public key. Also generated is a device add signature that is necessary to hit the API.
fn generate_device_add<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    jwt: &Jwt,
    user_master_keypair: &KeyPair,
    signing_ts: &OffsetDateTime,
) -> Result<DeviceAdd, IronOxideErr> {
    let signing_keypair = recrypt.generate_ed25519_key_pair();
    let (recrypt_priv_key, recrypt_pub_key) = recrypt.generate_key_pair()?;
    let device_keypair = KeyPair::new(recrypt_pub_key, recrypt_priv_key);

    // generate a transform key from the user's private key to the new device
    let trans_key: TransformKey = recrypt
        .generate_transform_key(
            user_master_keypair.private_key().recrypt_key(),
            &device_keypair.public_key().into(),
            &signing_keypair,
        )?
        .into();

    let sig = gen_device_add_signature(recrypt, jwt, user_master_keypair, &trans_key, signing_ts);
    Ok(DeviceAdd {
        user_public_key: user_master_keypair.public_key().clone(),
        transform_key: trans_key,
        device_keys: device_keypair,
        signing_keys: signing_keypair.into(),
        signature: sig,
        signature_ts: signing_ts.to_owned(),
    })
}

/// Generate a schnorr signature for calling the device add endpoint in the IronCore service
fn gen_device_add_signature<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    jwt: &Jwt,
    user_master_keypair: &KeyPair,
    transform_key: &TransformKey,
    signing_ts: &OffsetDateTime,
) -> SchnorrSignature {
    struct SignedMessage<'a> {
        timestamp: &'a OffsetDateTime,
        transform_key: &'a TransformKey,
        jwt: &'a Jwt,
        user_public_key: &'a PublicKey,
    }

    impl<'a> recrypt::api::Hashable for SignedMessage<'a> {
        fn to_bytes(&self) -> Vec<u8> {
            let mut vec: Vec<u8> = vec![];
            vec.extend_from_slice(
                rest::as_unix_timestamp_millis(*self.timestamp)
                    .to_string()
                    .as_bytes(),
            );
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
        user_public_key: user_master_keypair.public_key(),
    };

    recrypt
        .schnorr_sign(
            user_master_keypair.private_key().recrypt_key(),
            &user_master_keypair.public_key().into(),
            &msg,
        )
        .into()
}

/// Change the password for the user
pub async fn user_change_password(
    password: Password,
    new_password: Password,
    auth: &RequestAuth,
) -> Result<UserCreateResult, IronOxideErr> {
    let requests::user_get::CurrentUserResponse {
        user_private_key: encrypted_priv_key,
        id: curr_user_id,
        ..
    } = requests::user_get::get_curr_user(auth).await?;
    let (user_id, new_encrypted_priv_key) = {
        let priv_key: PrivateKey = aes::decrypt_user_master_key(
            &password.0,
            &aes::EncryptedMasterKey::new_from_slice(&encrypted_priv_key.0)?,
        )?
        .into();

        let new_encrypted_priv_key = aes::encrypt_user_master_key(
            &Mutex::new(OsRng::default()),
            &new_password.0,
            priv_key.as_bytes(),
        )?;
        (curr_user_id, new_encrypted_priv_key)
    };
    Ok(
        requests::user_update::user_update(auth, &user_id, Some(new_encrypted_priv_key.into()))
            .await?
            .try_into()?,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use galvanic_assert::*;

    pub fn create_user_result(
        account_id: UserId,
        segment_id: usize,
        user_public_key: PublicKey,
        needs_rotation: bool,
    ) -> UserResult {
        UserResult {
            account_id,
            segment_id,
            user_public_key,
            needs_rotation,
        }
    }

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

    #[test]
    fn invalid_jwt_non_ascii() {
        let jwt = Jwt::try_from("❤️.💣.💝");
        assert!(jwt.is_err())
    }

    #[test]
    fn invalid_jwt_format() {
        let jwt = Jwt::try_from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ");
        assert!(jwt.is_err())
    }

    #[test]
    fn valid_jwt_construction() {
        let jwt = Jwt::try_from("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhYmNBQkMwMTJfLiQjfEAvOjs9KyctZDEyMjZkMWItNGMzOS00OWRhLTkzM2MtNjQyZTIzYWMxOTQ1IiwicGlkIjo0MzgsInNpZCI6Imlyb25veGlkZS1kZXYxIiwia2lkIjo1OTMsImlhdCI6MTU5MTkwMTc0MCwiZXhwIjoxNTkxOTAxODYwfQ.wgs_tnh89SlKnIkoQHdlC0REjkxTl1P8qtDSQwWTFKwo8KQKXUQdpp4BfwqUqLcxA0BW6_XfVRlqMX5zcvCc6w");
        assert!(jwt.is_ok())
    }

    #[test]
    fn valid_jwt_namespace_construction() {
        // This is a JWT with the following claims (generated by Auth0):
        // { "http://ironcore/pid": 1, "http://ironcore/kid": 1859, "http://ironcore/sid": "IronHide",
        //    "http://ironcore/uid": "bob.wall@ironcorelabs.com", "iss": "https://ironcorelabs.auth0.com/",
        //    "sub": "github|11368122", "aud": "hGELxuBKD64ltS4VNaIy2mzVwtqgJa5f", "iat": 1593130255, "exp": 1593133855 }
        let jwt = Jwt::try_from("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlEwWXhNekUwTlVJeE9UVTNRakZFTlRZM01rVkNRakE0UkVNMk1UTkZOVGRETVRBNE9EQTVNUSJ9.eyJodHRwOi8vaXJvbmNvcmUvcGlkIjoxLCJodHRwOi8vaXJvbmNvcmUva2lkIjoxODU5LCJodHRwOi8vaXJvbmNvcmUvc2lkIjoiSXJvbkhpZGUiLCJodHRwOi8vaXJvbmNvcmUvdWlkIjoiYm9iLndhbGxAaXJvbmNvcmVsYWJzLmNvbSIsImlzcyI6Imh0dHBzOi8vaXJvbmNvcmVsYWJzLmF1dGgwLmNvbS8iLCJzdWIiOiJnaXRodWJ8MTEzNjgxMjIiLCJhdWQiOiJoR0VMeHVCS0Q2NGx0UzRWTmFJeTJtelZ3dHFnSmE1ZiIsImlhdCI6MTU5MzEzMDI1NSwiZXhwIjoxNTkzMTMzODU1fQ.Y3DsoS-TctytMNpEFnewJ5TT33yRblRmNkNPIQ2EDmfka070y5egpMsVtjqqck05cpdShxfZG2n2JWr5LQF6--jEa8mHy73V36ZbBHkcvjhEcHdH3OxhQQPUNwrXN-jIFOD58G7K5ZNCZub8IsEpWPD8PwghWlwiLKSFMb_j12SEs1rQwoVs1NaYsVZk04G6fWwooyrpuulXVc6S8g8Cr6_FeHDkb8747UY2GmL3Qp0R3iCPjao0ESSqP9gwPMroQGiNhjfJhYwxM8_sin4skfWoEirj0IRk2M8LAEOszI6gTdMcFX8Bw-0kFw4LWYBOi1eHcmvzNFMgCJUB5I4rcg");
        assert!(jwt.is_ok())
    }

    #[test]
    fn invalid_jwt_namespace_construction() {
        // This is a JWT with the following claims (generated by Auth0):
        // { "http://ironcore1/pid": 1, "http://ironcore1/kid": 1859, "http://ironcore1/sid": "IronHide",
        //    "http://ironcore1/uid": "bob.wall@ironcorelabs.com", "iss": "https://ironcorelabs.auth0.com/",
        //    "sub": "github|11368122", "aud": "hGELxuBKD64ltS4VNaIy2mzVwtqgJa5f", "iat": 1593130255, "exp": 1593133855 }
        let jwt = Jwt::try_from("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlEwWXhNekUwTlVJeE9UVTNRakZFTlRZM01rVkNRakE0UkVNMk1UTkZOVGRETVRBNE9EQTVNUSJ9.eyJodHRwOi8vaXJvbmNvcmUxL3BpZCI6MSwiaHR0cDovL2lyb25jb3JlMS9raWQiOjE4NTksImh0dHA6Ly9pcm9uY29yZTEvc2lkIjoiSXJvbkhpZGUiLCJodHRwOi8vaXJvbmNvcmUxL3VpZCI6ImJvYi53YWxsQGlyb25jb3JlbGFicy5jb20iLCJpc3MiOiJodHRwczovL2lyb25jb3JlbGFicy5hdXRoMC5jb20vIiwic3ViIjoiZ2l0aHVifDExMzY4MTIyIiwiYXVkIjoiaEdFTHh1QktENjRsdFM0Vk5hSXkybXpWd3RxZ0phNWYiLCJpYXQiOjE1OTMxMzAyNTUsImV4cCI6MTU5MzEzMzg1NX0.J9sPgSFjucLQHpGOsEJ3xJf66nNK6Rf1n-C4YTsqWjPGwHlA8qyY4YIfNhwAjSstwvx2ImUb-Rf2Ghjq_4gpnArVfzkqa2HN06p_kRvwlL_kJoKTP8fo9LSpceNAbv75S4_EzOAWHTTNzDVjriQ1sjZYCYuD9BBjCG7ie0vSATb9uE4BtE_fSrlRkXlEW_608PDajNpwcCzSC-rMcWa1vDCYEuk405MzxkMJIi65ghMs9AEi6QotEhimf1gbrSaJFyyAqVKBPwA5--z64cK1vSwsX3mO2bCWIKbqLgXXWU0zr7saP9jVeMKXXetBW5KHHjYKRZ6lY9CquhtsnjSxvQ");
        assert!(!jwt.is_ok())
    }
}
