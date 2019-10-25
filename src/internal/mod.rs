//! Common types, traits, and functions needed across user/group/document apis
//! If it can be defined in API specific file, it should go there to keep this file's
//! size to a minimum.

use crate::internal::{
    rest::{Authorization, IronCoreRequest, SignatureUrlString},
    user_api::{DeviceId, UserId},
};
use chrono::{DateTime, Utc};
use log::error;
use protobuf::{self, ProtobufError};
use recrypt::api::{
    Hashable, KeyGenOps, PrivateKey as RecryptPrivateKey, PublicKey as RecryptPublicKey,
    RecryptErr, SigningKeypair as RecryptSigningKeypair,
};
use regex::Regex;
use reqwest::Method;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    convert::{TryFrom, TryInto},
    result::Result,
    sync::{Mutex, MutexGuard},
};

pub mod document_api;
pub mod group_api;
mod rest;
pub mod user_api;

#[cfg(feature = "senv")]
pub const OUR_REQUEST: IronCoreRequest =
    IronCoreRequest::new("https://api-staging.ironcorelabs.com/api/1/");

#[cfg(not(feature = "senv"))]
pub const OUR_REQUEST: IronCoreRequest =
    IronCoreRequest::new("https://api.ironcorelabs.com/api/1/");

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RequestErrorCode {
    UserVerify,
    UserCreate,
    UserDeviceAdd,
    UserDeviceDelete,
    UserDeviceList,
    UserKeyList,
    UserKeyUpdate,
    GroupCreate,
    GroupDelete,
    GroupList,
    GroupGet,
    GroupAddMember,
    GroupUpdate,
    GroupMemberRemove,
    GroupAdminRemove,
    DocumentList,
    DocumentGet,
    DocumentCreate,
    DocumentUpdate,
    DocumentGrantAccess,
    DocumentRevokeAccess,
    EdekTransform,
    PolicyGet,
}

quick_error! {
    /// Errors generated by IronOxide SDK operations
    #[derive(Debug)]
    pub enum IronOxideErr {
        ValidationError(field_name: String, err: String) {
            display("'{}' failed validation with the error '{}'", field_name, err)
        }
        DocumentHeaderParseFailure(message: String) {
            display("{}", message)
        }
        WrongSizeError(actual_size: Option<usize>, expected_size: Option<usize>) {
        }
        KeyGenerationError {
            display("Key generation failed")
        }
        AesError(err: ring::error::Unspecified) {
            cause(err)
        }
        AesEncryptedDocSizeError{
            display("Provided document is not long enough to be an encrypted document.")
        }
        InvalidRecryptEncryptedValue(msg: String) {
            display("Got an unexpected Recrypt EncryptedValue: '{}'", msg)
        }
        RecryptError(msg: String) {
            display("Recrypt operation failed with error '{}'", msg)
        }
        UserDoesNotExist(msg: String) {
            display("Operation failed with error '{}'", msg)
        }
        InitializeError {
            display("Initialization failed as device info provided was not valid.")
        }
        RequestError { message: String, code: RequestErrorCode, http_status: Option<u16> } {
            display("Request failed with HTTP status code '{:?}' message '{}' and code '{:?}'", http_status, message, code)
        }
        ///This is used if the response from the server was an error. In that case we know that the format of the errors will be `ServerError`.
        RequestServerErrors {errors: Vec<rest::ServerError>, code: RequestErrorCode, http_status: Option<u16> } {
            display("Request failed with HTTP status code '{:?}' errors list is '{:?}' and code '{:?}'", http_status, errors, code)
        }
        MissingTransformBlocks {
            display("Expected at least one TransformBlock in transformed value but received none.")
        }
        ///The operation failed because the accessing user was not a group admin, but must be for the operation to work.
        NotGroupAdmin(group_id:group_api::GroupId) {
            display("You're are not an administrator of group '{}'", group_id.0)
        }
        /// Protobuf encode/decode error
        ProtobufSerdeError(err: protobuf::ProtobufError) {
            cause(err)
        }
        /// Protobuf decode succeeded, but the result is not valid
        ProtobufValidationError(msg: String) {
            display("Protobuf validation failed with '{}'", msg)
        }
        UnmanagedDecryptionError(edek_doc_id: String, edek_segment_id: i32,
                                 edoc_doc_id: String, edoc_segment_id: i32) {
            display("Edeks and EncryptedDocument do not match. \
            Edeks are for DocumentId({}) and SegmentId({}) and\
            Encrypted Document is DocumentId({}) and SegmentId({})",
            edek_doc_id, edek_segment_id, edoc_doc_id, edoc_segment_id)
        }
        UserPrivateKeyRotationError(msg: String) {
            display("User private key rotation failed with '{}'", msg)
        }
    }
}

impl From<RecryptErr> for IronOxideErr {
    fn from(recrypt_err: RecryptErr) -> Self {
        match recrypt_err {
            RecryptErr::InputWrongSize(_, expected_size) => {
                IronOxideErr::WrongSizeError(None, Some(expected_size))
            }
            RecryptErr::InvalidPublicKey(_) => IronOxideErr::KeyGenerationError,
            //Fallback for all other error types that Recrypt can have that we don't have specific mappings for
            other_recrypt_err => IronOxideErr::RecryptError(format!("{}", other_recrypt_err)),
        }
    }
}

impl From<ProtobufError> for IronOxideErr {
    fn from(e: ProtobufError) -> Self {
        IronOxideErr::ProtobufSerdeError(e)
    }
}

impl From<recrypt::nonemptyvec::NonEmptyVecError> for IronOxideErr {
    fn from(_: recrypt::nonemptyvec::NonEmptyVecError) -> Self {
        IronOxideErr::MissingTransformBlocks
    }
}

const NAME_AND_ID_MAX_LEN: usize = 100;

/// Validate that the provided id is valid for our user/document/group IDs. Validates that the
/// ID has a length and that it matches our restricted set of characters. Also takes the readable
/// type of ID for usage within any resulting error messages.
pub fn validate_id(id: &str, id_type: &str) -> Result<String, IronOxideErr> {
    let id_regex = Regex::new("^[a-zA-Z0-9_.$#|@/:;=+'-]+$").expect("regex is valid");
    let trimmed_id = id.trim();
    if trimmed_id.is_empty() || trimmed_id.len() > NAME_AND_ID_MAX_LEN {
        Err(IronOxideErr::ValidationError(
            id_type.to_string(),
            format!("'{}' must have length between 1 and 100", trimmed_id),
        ))
    } else if !id_regex.is_match(trimmed_id) {
        Err(IronOxideErr::ValidationError(
            id_type.to_string(),
            format!("'{}' contains invalid characters", trimmed_id),
        ))
    } else {
        Ok(trimmed_id.to_string())
    }
}

/// Validate that the provided document/group name is valid. Ensures that the length of
/// the name is between 1-100 characters. Also takes the readable type of the name for
/// usage within any resulting error messages.
pub fn validate_name(name: &str, name_type: &str) -> Result<String, IronOxideErr> {
    let trimmed_name = name.trim();
    if trimmed_name.trim().is_empty() || trimmed_name.len() > NAME_AND_ID_MAX_LEN {
        Err(IronOxideErr::ValidationError(
            name_type.to_string(),
            format!("'{}' must have length between 1 and 100", trimmed_name),
        ))
    } else {
        Ok(trimmed_name.trim().to_string())
    }
}

pub mod auth_v2 {
    use super::*;

    /// API Auth version 2.
    /// Fully constructing a valid auth v2 header is a two step process.
    /// Step 1 is done on construction via `new`
    /// Step 2 is done via `finish_with` as a request is being sent out and the bytes of the body are available.
    pub struct AuthV2Builder<'a> {
        pub(in crate::internal::auth_v2) req_auth: &'a RequestAuth,
        pub(in crate::internal::auth_v2) timestamp: DateTime<Utc>,
    }

    impl<'a> AuthV2Builder<'a> {
        pub fn new(req_auth: &'a RequestAuth, timestamp: DateTime<Utc>) -> AuthV2Builder {
            AuthV2Builder {
                req_auth,
                timestamp,
            }
        }

        /// Always returns Authorization::Version2
        /// # Arguments
        /// `sig_url`       URL path to be signed over
        /// `method`        Method of request (POST, GET, PUT, etc)
        /// `body_bytes`    Reference to the bytes of the body (or none)
        ///
        /// # Returns
        /// Authorization::Version2 that contains all the information necessary to make an
        /// IronCore authenticated request to the webservice.
        pub fn finish_with(
            &self,
            sig_url: SignatureUrlString,
            method: Method,
            body_bytes: Option<&'a [u8]>,
        ) -> Authorization<'a> {
            self.req_auth
                .create_signature_v2(self.timestamp, sig_url, method, body_bytes)
        }
    }
}

///Structure that contains all the info needed to make a signed API request from a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestAuth {
    device_id: DeviceId,
    ///The users given id, which uniquely identifies them inside the segment.
    account_id: UserId,
    ///The segment_id for the above user.
    segment_id: usize,
    ///The signing key which was generated for the device. “expanded private key” (both pub/priv)
    signing_private_key: DeviceSigningKeyPair,
    #[serde(skip_serializing, skip_deserializing)]
    pub(crate) request: IronCoreRequest<'static>,
}

impl RequestAuth {
    pub fn create_signature_v2<'a>(
        &'a self,
        current_time: DateTime<Utc>,
        sig_url: SignatureUrlString,
        method: Method,
        body: Option<&'a [u8]>,
    ) -> Authorization<'a> {
        Authorization::create_signatures_v2(
            current_time,
            self.segment_id,
            &self.account_id,
            method,
            sig_url,
            body,
            &self.signing_private_key,
        )
    }

    pub fn account_id(&self) -> &UserId {
        &self.account_id
    }

    pub fn segment_id(&self) -> usize {
        self.segment_id
    }

    pub fn signing_private_key(&self) -> &DeviceSigningKeyPair {
        &self.signing_private_key
    }
}

/// Account's device context. Needed to initialize the Sdk with a set of device keys. See `IronOxide.initialize()`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceContext {
    #[serde(flatten)]
    auth: RequestAuth,
    ///The private key which was generated for a particular device for the user. Not the user's master private key.
    device_private_key: PrivateKey,
}

impl DeviceContext {
    /// Create a new DeviceContext to get an SDK instance for the provided context. Takes an accounts UserID,
    /// segment id, private device keys, and signing keys. An instance of this structure is returned directly
    /// from the `IronOxide.generate_new_device()` method.
    pub fn new(
        device_id: DeviceId,
        account_id: UserId,
        segment_id: usize,
        device_private_key: PrivateKey,
        signing_private_key: DeviceSigningKeyPair,
    ) -> DeviceContext {
        DeviceContext {
            auth: RequestAuth {
                device_id,
                account_id,
                segment_id,
                signing_private_key,
                request: IronCoreRequest::new(OUR_REQUEST.base_url()),
            },
            device_private_key,
        }
    }

    pub(crate) fn auth(&self) -> &RequestAuth {
        &self.auth
    }

    pub fn account_id(&self) -> &UserId {
        &self.auth.account_id
    }

    pub fn segment_id(&self) -> usize {
        self.auth.segment_id
    }

    pub fn signing_private_key(&self) -> &DeviceSigningKeyPair {
        &self.auth.signing_private_key
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.auth.device_id
    }

    pub fn device_private_key(&self) -> &PrivateKey {
        &self.device_private_key
    }
}

/// Newtype wrapper around Recrypt TransformKey type
#[derive(Clone, PartialEq, Debug)]
pub struct TransformKey(recrypt::api::TransformKey);
impl From<recrypt::api::TransformKey> for TransformKey {
    fn from(tk: recrypt::api::TransformKey) -> Self {
        TransformKey(tk)
    }
}

impl Hashable for TransformKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

/// Newtype wrapper around Recrypt SchnorrSignature type
#[derive(Clone, PartialEq, Debug)]
pub struct SchnorrSignature(recrypt::api::SchnorrSignature);
impl From<recrypt::api::SchnorrSignature> for SchnorrSignature {
    fn from(s: recrypt::api::SchnorrSignature) -> Self {
        SchnorrSignature(s)
    }
}

impl From<SchnorrSignature> for Vec<u8> {
    fn from(sig: SchnorrSignature) -> Self {
        sig.0.bytes().to_vec()
    }
}

/// Represents an asymmetric public key that wraps the underlying bytes
/// of the key.
#[derive(PartialEq, Debug, Clone)]
pub struct PublicKey(RecryptPublicKey);

impl From<RecryptPublicKey> for PublicKey {
    fn from(recrypt_pub: RecryptPublicKey) -> Self {
        PublicKey(recrypt_pub)
    }
}

impl From<PublicKey> for RecryptPublicKey {
    fn from(public_key: PublicKey) -> Self {
        public_key.0
    }
}
impl From<&PublicKey> for RecryptPublicKey {
    fn from(public_key: &PublicKey) -> Self {
        public_key.0.clone()
    }
}
impl From<PublicKey> for crate::proto::transform::PublicKey {
    fn from(pubk: PublicKey) -> Self {
        let mut proto_pub_key = crate::proto::transform::PublicKey::default();
        proto_pub_key.set_x(pubk.to_bytes_x_y().0.into());
        proto_pub_key.set_y(pubk.to_bytes_x_y().1.into());
        proto_pub_key
    }
}
impl TryFrom<&[u8]> for PublicKey {
    type Error = IronOxideErr;
    fn try_from(key_bytes: &[u8]) -> Result<PublicKey, IronOxideErr> {
        if key_bytes.len() == RecryptPublicKey::ENCODED_SIZE_BYTES {
            PublicKey::new_from_slice(key_bytes.split_at(RecryptPublicKey::ENCODED_SIZE_BYTES / 2))
        } else {
            Err(IronOxideErr::WrongSizeError(
                Some(RecryptPublicKey::ENCODED_SIZE_BYTES),
                Some(key_bytes.len()),
            ))
        }
    }
}
impl PublicKey {
    fn to_bytes_x_y(&self) -> (Vec<u8>, Vec<u8>) {
        let (x, y) = self.0.bytes_x_y();
        (x.to_vec(), y.to_vec())
    }
    pub fn new_from_slice(bytes: (&[u8], &[u8])) -> Result<Self, IronOxideErr> {
        let re_pub = RecryptPublicKey::new_from_slice(bytes)?;
        Ok(PublicKey(re_pub))
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        let (mut x, mut y) = self.to_bytes_x_y();
        x.append(&mut y);
        x
    }
}

/// Represents an asymmetric private key that wraps the underlying bytes
/// of the key.
#[derive(Debug, Clone)]
pub struct PrivateKey(RecryptPrivateKey);
impl PrivateKey {
    const BYTES_SIZE: usize = RecryptPrivateKey::ENCODED_SIZE_BYTES;
    pub fn as_bytes(&self) -> &[u8; PrivateKey::BYTES_SIZE] {
        &self.0.bytes()
    }
    fn recrypt_key(&self) -> &RecryptPrivateKey {
        &self.0
    }
}
impl From<RecryptPrivateKey> for PrivateKey {
    fn from(recrypt_priv: RecryptPrivateKey) -> Self {
        PrivateKey(recrypt_priv)
    }
}
impl From<PrivateKey> for RecryptPrivateKey {
    fn from(priv_key: PrivateKey) -> Self {
        priv_key.0
    }
}
impl From<[u8; 32]> for PrivateKey {
    fn from(bytes: [u8; 32]) -> Self {
        PrivateKey(RecryptPrivateKey::new(bytes))
    }
}
impl TryFrom<&[u8]> for PrivateKey {
    type Error = IronOxideErr;
    fn try_from(key_bytes: &[u8]) -> Result<PrivateKey, IronOxideErr> {
        RecryptPrivateKey::new_from_slice(key_bytes)
            .map(PrivateKey)
            .map_err(|e| e.into())
    }
}

impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(&self.0.bytes().to_vec()))
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let keys_bytes = base64::decode(&s).map_err(|e| Error::custom(e.to_string()))?;
        PrivateKey::try_from(&keys_bytes[..]).map_err(|e| Error::custom(e.to_string()))
    }
}

impl PrivateKey {
    /// Augment this private key with another, producing a new PrivateKey
    fn augment(&self, augmenting_key: &AugmentationFactor) -> Result<PrivateKey, IronOxideErr> {
        use recrypt::Revealed;
        let zero: RecryptPrivateKey = RecryptPrivateKey::new([0u8; 32]);
        if Revealed((augmenting_key.clone().0).0) == Revealed(zero.clone()) {
            Err(IronOxideErr::UserPrivateKeyRotationError(
                "Augmenting key cannot be zero".into(),
            ))
        } else {
            // this subtraction needs to be the additive inverse of what the service is doing
            let augmented_key = self.0.clone().augment_minus(&augmenting_key.clone().into());
            // This clone can be removed once https://github.com/IronCoreLabs/recrypt-rs/issues/91 is fixed
            if Revealed(augmented_key.clone()) == Revealed(zero) {
                Err(IronOxideErr::UserPrivateKeyRotationError(
                    "PrivateKey augmentation failed with a zero value".into(),
                ))
            } else {
                Ok(augmented_key.into())
            }
        }
    }
}

/// Private key used to augment another PrivateKey
#[derive(Clone, Debug)]
pub(crate) struct AugmentationFactor(PrivateKey);

impl AugmentationFactor {
    /// Use recrypt to generate a new AugmentationFactor
    pub fn generate_new<R: KeyGenOps>(recrypt: &R) -> AugmentationFactor {
        AugmentationFactor(recrypt.random_private_key().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl From<AugmentationFactor> for RecryptPrivateKey {
    fn from(aug: AugmentationFactor) -> Self {
        (aug.0).0
    }
}

/// Public/Private asymmetric keypair that is used for decryption/encryption.
#[derive(Clone)]
pub struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}
impl KeyPair {
    pub fn new(public_key: RecryptPublicKey, private_key: RecryptPrivateKey) -> Self {
        KeyPair {
            public_key: public_key.into(),
            private_key: private_key.into(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

/// Signing keypair specific to a device. Used to sign all requests to the IronCore API
/// endpoints. Needed to create a `DeviceContext`.
#[derive(Debug, Clone)]
pub struct DeviceSigningKeyPair(RecryptSigningKeypair);
impl From<&DeviceSigningKeyPair> for RecryptSigningKeypair {
    fn from(dsk: &DeviceSigningKeyPair) -> RecryptSigningKeypair {
        dsk.0.clone()
    }
}
impl From<RecryptSigningKeypair> for DeviceSigningKeyPair {
    fn from(rsk: RecryptSigningKeypair) -> DeviceSigningKeyPair {
        DeviceSigningKeyPair(rsk)
    }
}
impl TryFrom<&[u8]> for DeviceSigningKeyPair {
    type Error = IronOxideErr;
    fn try_from(signing_key_bytes: &[u8]) -> Result<DeviceSigningKeyPair, Self::Error> {
        RecryptSigningKeypair::from_byte_slice(signing_key_bytes)
            .map(|dsk| DeviceSigningKeyPair(dsk))
            .map_err(|e| {
                IronOxideErr::ValidationError("DeviceSigningKeyPair".to_string(), format!("{}", e))
            })
    }
}

impl PartialEq for DeviceSigningKeyPair {
    fn eq(&self, other: &DeviceSigningKeyPair) -> bool {
        self.0.bytes().to_vec() == other.0.bytes().to_vec()
    }
}

impl Serialize for DeviceSigningKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let base64 = base64::encode(&self.0.bytes().to_vec());
        serializer.serialize_str(&base64)
    }
}

impl<'de> Deserialize<'de> for DeviceSigningKeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let keys_bytes = base64::decode(&s).map_err(|e| Error::custom(e.to_string()))?;
        DeviceSigningKeyPair::try_from(&keys_bytes[..]).map_err(|e| Error::custom(e.to_string()))
    }
}

impl DeviceSigningKeyPair {
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.0.sign(&payload).into()
    }
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0.bytes()
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.0.public_key().into()
    }
}

/// IronCore JWT.
/// Should be either ES256 or RS256 and have a payload similar to:
///
/// let jwt_payload = json!({
///     "pid" : project_id,
///     "sid" : seg_id,
///     "kid" : service_key_id,
///     "iat" : issued_time_seconds,
///     "exp" : expire_time_seconds,
///     "sub" : unique_user_id
/// });
///
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct Jwt(String);
impl TryFrom<&str> for Jwt {
    type Error = IronOxideErr;
    fn try_from(maybe_jwt: &str) -> Result<Self, Self::Error> {
        //Valid JWTs are base64 encoded and have 3 segments separated by periods
        if maybe_jwt.is_ascii() && maybe_jwt.matches(".").count() == 2 {
            Ok(Jwt(maybe_jwt.to_string()))
        } else {
            Err(IronOxideErr::ValidationError(
                "JWT".to_string(),
                "must be valid ascii and be formatted correctly".to_string(),
            ))
        }
    }
}
impl Jwt {
    pub fn to_utf8(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

/// Newtype wrapper around a string which represents the users master private key escrow password
#[derive(Debug, PartialEq)]
pub struct Password(String);
impl TryFrom<&str> for Password {
    type Error = IronOxideErr;
    fn try_from(maybe_password: &str) -> Result<Self, Self::Error> {
        if maybe_password.trim().len() > 0 {
            Ok(Password(maybe_password.to_string()))
        } else {
            Err(IronOxideErr::ValidationError(
                "maybe_password".to_string(),
                "length must be > 0".to_string(),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct WithKey<T> {
    pub(crate) id: T,
    pub(crate) public_key: PublicKey,
}
impl<T> WithKey<T> {
    pub fn new(id: T, public_key: PublicKey) -> WithKey<T> {
        WithKey { id, public_key }
    }
}

/// Acquire mutex in a blocking fashion. If the Mutex is or becomes poisoned, write out an error
/// message and panic.
///
/// The lock is released when the returned MutexGuard falls out of scope.
///
/// # Usage:
/// single statement (mut)
/// `let result = take_lock(&t).deref_mut().call_method_on_t();`
///
/// mutli-statement (mut)
///
/// ```ignore
/// let t = T {};
/// let result = {
///     let g = &mut *take_lock(&t);
///     g.call_method_on_t()
/// }; // lock released here
/// ```
///
pub(crate) fn take_lock<T>(m: &Mutex<T>) -> MutexGuard<T> {
    m.lock().unwrap_or_else(|e| {
        let error = format!("Error when acquiring lock: {}", e);
        error!("{}", error);
        panic!(error);
    })
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use galvanic_assert::{matchers::*, MatchResultBuilder, Matcher};
    use recrypt::api::KeyGenOps;
    use std::fmt::Debug;

    /// String contains matcher to assert that the provided substring exists in the provided value
    pub fn contains<'a>(expected: &'a str) -> Box<dyn Matcher<String> + 'a> {
        Box::new(move |actual: &String| {
            let builder = MatchResultBuilder::for_("contains");
            if actual.contains(expected) {
                builder.matched()
            } else {
                let expected_string: String = expected.to_string();
                builder.failed_comparison(actual, &expected_string)
            }
        })
    }

    /// Length matcher to assert that the provided iterable value has the expected size
    pub fn length<'a, I, T>(expected: &'a usize) -> Box<dyn Matcher<I> + 'a>
    where
        T: 'a,
        &'a I: Debug + Sized + IntoIterator<Item = &'a T> + 'a,
    {
        Box::new(move |actual: &'a I| {
            let actual_list: Vec<_> = actual.into_iter().collect();
            let builder = MatchResultBuilder::for_("contains");
            if &actual_list.len() == expected {
                builder.matched()
            } else {
                builder.failed_because(&format!(
                    "Expected '{:?}' to have length of {} but found length of {}",
                    actual,
                    expected,
                    actual_list.len()
                ))
            }
        })
    }

    #[test]
    fn serde_devicecontext_roundtrip() -> Result<(), IronOxideErr> {
        use serde_json;
        let priv_key: recrypt::api::PrivateKey = recrypt::api::PrivateKey::new_from_slice(
            base64::decode("bzb0Rlg0u7gx9wDuk1ppRI77OH/0ferXleenJ3Ag6Jg=")
                .unwrap()
                .as_slice(),
        )?;
        let dev_keys = recrypt::api::SigningKeypair::from_byte_slice(&[
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202,
            103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
        ])
        .unwrap();
        let context = DeviceContext::new(
            314.try_into()?,
            "account_id".try_into()?,
            22,
            priv_key.into(),
            DeviceSigningKeyPair::from(dev_keys),
        );
        let json = serde_json::to_string(&context).unwrap();
        let expect_json = r#"{"deviceId":314,"accountId":"account_id","segmentId":22,"signingPrivateKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQGKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXA==","devicePrivateKey":"bzb0Rlg0u7gx9wDuk1ppRI77OH/0ferXleenJ3Ag6Jg="}"#;

        assert_eq!(json, expect_json);

        let de: DeviceContext = serde_json::from_str(&json).unwrap();

        assert_eq!(context.account_id(), de.account_id());
        assert_eq!(context.device_id(), de.device_id());
        assert_eq!(
            context.auth.signing_private_key.as_bytes().to_vec(),
            de.auth.signing_private_key.as_bytes().to_vec()
        );
        assert_eq!(
            context.device_private_key.as_bytes().to_vec(),
            de.device_private_key.as_bytes().to_vec()
        );
        Ok(())
    }

    #[test]
    fn validate_id_success() {
        let valid_id = "abcABC012_.$#|@/:;=+'-";
        let id = validate_id(valid_id, "id_type");
        assert_that!(&id, is_variant!(Ok));
        assert_that!(&id.unwrap(), eq(valid_id.to_string()))
    }

    #[test]
    fn valid_id_whitespace() {
        let valid_id = " abc212     ";
        let id = validate_id(valid_id, "id_type");
        assert_that!(&id, is_variant!(Ok));
        assert_that!(&id.unwrap(), eq("abc212".to_string()))
    }

    #[test]
    fn validate_id_failure() {
        let invalid_id = "with spaces";
        let id_type = "id_type";
        let id = validate_id(invalid_id, id_type);
        assert_that!(&id, is_variant!(Err));
        let validation_error = id.unwrap_err();
        assert_that!(
            &validation_error,
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(&format!("{}", validation_error), contains(id_type));
        assert_that!(&format!("{}", validation_error), contains(invalid_id));
    }

    #[test]
    fn validate_id_all_whitespace() {
        let invalid_id = "     ";
        let id_type = "id_type";
        let id = validate_id(invalid_id, id_type);
        assert_that!(&id, is_variant!(Err));
        let validation_error = id.unwrap_err();
        assert_that!(
            &validation_error,
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(&format!("{}", validation_error), contains(id_type));
    }

    #[test]
    fn validate_name_success() {
        let valid_name = "name with any char _.$#|@/:;=+'-";
        let id = validate_name(valid_name, "name_type");
        assert_that!(&id, is_variant!(Ok));
        assert_that!(&id.unwrap(), eq(valid_name.to_string()))
    }

    #[test]
    fn validate_name_surrounding_whitespace() {
        let valid_name = "   a good name    ";
        let id = validate_name(valid_name, "name_type");
        assert_that!(&id, is_variant!(Ok));
        assert_that!(&id.unwrap(), eq("a good name".to_string()))
    }

    #[test]
    fn validate_name_failure() {
        let name_type = "name_type";
        let invalid_name = "too many chars 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        let name = validate_name(invalid_name, name_type);
        assert_that!(&name, is_variant!(Err));
        let validation_error = name.unwrap_err();
        assert_that!(
            &validation_error,
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(&format!("{}", validation_error), contains(invalid_name));
        assert_that!(&format!("{}", validation_error), contains(name_type));
    }

    #[test]
    fn validate_name_all_whitespace() {
        let invalid_name = "        ";
        let name_type = "name_type";

        let name = validate_name(invalid_name, name_type);
        assert_that!(&name, is_variant!(Err));
        let validation_error = name.unwrap_err();
        assert_that!(
            &validation_error,
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(&format!("{}", validation_error), contains(name_type));
    }

    #[test]
    fn passphrase_validation() {
        let result = Password::try_from("");
        assert!(result.is_err())
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
        let jwt = Jwt::try_from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        assert!(jwt.is_ok())
    }

    #[test]
    fn encode_proto_public_key() -> Result<(), IronOxideErr> {
        let recr = recrypt::api::Recrypt::new();
        let (_, re_pubk) = recr.generate_key_pair()?;
        let pubk: PublicKey = re_pubk.into();

        let proto_pubk: crate::proto::transform::PublicKey = pubk.clone().into();
        assert_eq!(
            (&pubk.to_bytes_x_y().0, &pubk.to_bytes_x_y().1),
            (&proto_pubk.get_x().to_vec(), &proto_pubk.get_y().to_vec())
        );
        Ok(())
    }

    #[test]
    fn public_key_try_from_slice() -> Result<(), IronOxideErr> {
        let recr = recrypt::api::Recrypt::new();
        let (_, re_pubk) = recr.generate_key_pair()?;
        let pubk: PublicKey = re_pubk.into();
        let pubk2: PublicKey = pubk.as_bytes().as_slice().try_into()?;
        assert_eq!(pubk, pubk2);
        Ok(())
    }

    #[test]
    fn public_key_try_from_slice_invalid() {
        let bytes = [1u8; 8];
        let maybe_public_key: Result<PublicKey, IronOxideErr> = bytes[..].try_into();
        assert!(maybe_public_key.is_err())
    }

    pub fn gen_priv_key() -> PrivateKey {
        let recr = recrypt::api::Recrypt::new();
        let (re_privk, _) = recr.generate_key_pair().unwrap();
        re_privk.into()
    }

    #[test]
    fn private_key_augment_with_self_is_none() {
        let privk = gen_priv_key();

        let result = privk.augment(&AugmentationFactor(privk.clone()));
        assert_that!(&result, is_variant!(Err));
        assert_that!(
            &result.unwrap_err(),
            is_variant!(IronOxideErr::UserPrivateKeyRotationError)
        )
    }

    #[test]
    fn private_key_augmentation_is_augment_minus() {
        use recrypt::Revealed;
        let p1 = gen_priv_key();
        let p2 = gen_priv_key();

        let p3 = p1.clone().0.augment_minus(&p2.clone().0).into();

        let aug_p = p1.augment(&AugmentationFactor(p2)).unwrap();
        assert_eq!(Revealed(aug_p.0), Revealed(p3))
    }

    #[test]
    fn private_key_augmentation_aug_key_of_zero_is_err() {
        let priv_key_orig = gen_priv_key();
        let zero_aug_factor = AugmentationFactor(PrivateKey(RecryptPrivateKey::new([0u8; 32])));
        let new_priv_key = priv_key_orig.augment(&zero_aug_factor);
        assert_that!(&new_priv_key, is_variant!(Err));
        assert_that!(
            &new_priv_key.unwrap_err(),
            is_variant!(IronOxideErr::UserPrivateKeyRotationError)
        )
    }
}
