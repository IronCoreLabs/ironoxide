use crate::{
    config::{IronOxideConfig, PolicyCachingConfig},
    crypto::{
        aes::{self, AesEncryptedValue},
        transform,
    },
    internal::{
        self,
        document_api::requests::UserOrGroupWithKey,
        group_api::{GroupId, GroupName},
        take_lock,
        user_api::UserId,
        validate_id, validate_name, IronOxideErr, PrivateKey, PublicKey, RequestAuth, WithKey,
    },
    policy::PolicyGrant,
    proto::transform::{
        EncryptedDek as EncryptedDekP, EncryptedDekData as EncryptedDekDataP,
        EncryptedDeks as EncryptedDeksP,
    },
    DeviceSigningKeyPair, PolicyCache,
};
use chrono::{DateTime, Utc};
use futures::{try_join, Future};
use hex::encode;
use itertools::{Either, Itertools};
use protobuf::{Message, RepeatedField};
use rand::{self, CryptoRng, RngCore};
use recrypt::{api::Plaintext, prelude::*};
use requests::{
    document_create,
    document_list::{DocumentListApiResponse, DocumentListApiResponseItem},
    policy_get::PolicyResponse,
    DocumentMetaApiResponse,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Formatter,
    ops::DerefMut,
    sync::Mutex,
};

mod requests;

const DOC_VERSION_HEADER_LENGTH: usize = 1;
const HEADER_META_LENGTH_LENGTH: usize = 2;
const CURRENT_DOCUMENT_ID_VERSION: u8 = 2;

/// ID of a document.
///
/// The ID can be validated from a `String` or `&str` using `DocumentId::try_from`.
///
/// # Requirements
/// - Must be unique within the document's segment.
/// - Must match the regex `^[a-zA-Z0-9_.$#|@/:;=+'-]+$`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DocumentId(pub(crate) String);
impl DocumentId {
    /// ID of the document.
    pub fn id(&self) -> &str {
        &self.0
    }

    /// Generate a random id for a document
    pub(crate) fn goo_id<R: CryptoRng + RngCore>(rng: &Mutex<R>) -> DocumentId {
        let mut id = [0u8; 16];
        take_lock(rng).deref_mut().fill_bytes(&mut id);
        DocumentId(encode(id))
    }
}
impl TryFrom<&str> for DocumentId {
    type Error = IronOxideErr;
    fn try_from(id: &str) -> Result<Self, Self::Error> {
        validate_id(id, "document_id").map(DocumentId)
    }
}
impl TryFrom<String> for DocumentId {
    type Error = IronOxideErr;
    fn try_from(doc_id: String) -> Result<Self, Self::Error> {
        doc_id.as_str().try_into()
    }
}

/// Name of a document.
///
/// The name should be human-readable and does not have to be unique.
/// It can be validated from a `String` or `&str` using `DocumentName::try_from`.
///
/// # Requirements
/// - Must be between 1 and 100 characters long.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DocumentName(pub(crate) String);
impl DocumentName {
    /// Name of the document.
    pub fn name(&self) -> &String {
        &self.0
    }
}
impl TryFrom<&str> for DocumentName {
    type Error = IronOxideErr;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        validate_name(name, "document_name").map(DocumentName)
    }
}
impl TryFrom<String> for DocumentName {
    type Error = IronOxideErr;
    fn try_from(doc_name: String) -> Result<Self, Self::Error> {
        doc_name.as_str().try_into()
    }
}

/// Binary version of the document header. Appropriate for using in edoc serialization.
struct DocHeaderPacked(Vec<u8>);

/// Represents a parsed document header which is decoded from JSON
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct DocumentHeader {
    #[serde(rename = "_did_")]
    document_id: DocumentId,
    #[serde(rename = "_sid_")]
    segment_id: usize,
}
impl DocumentHeader {
    fn new(document_id: DocumentId, segment_id: usize) -> DocumentHeader {
        DocumentHeader {
            document_id,
            segment_id,
        }
    }
    /// Generate a documents header given its ID and internal segment ID that is is associated with. Generates
    /// a Vec<u8> which includes the document version, header size, and header JSON as bytes.
    fn pack(&self) -> DocHeaderPacked {
        let mut header_json_bytes =
            serde_json::to_vec(&self).expect("Serialization of DocumentHeader failed."); //Serializing a string and number shouldn't fail
        let header_json_len = header_json_bytes.len();
        //Make header vector with size of header plus 1 byte for version and 2 bytes for header length
        let mut header = Vec::with_capacity(header_json_len + 3);
        header.push(CURRENT_DOCUMENT_ID_VERSION);
        //Push the header length representation as two bytes, most significant digit first (BigEndian)
        header.push((header_json_len >> 8) as u8);
        header.push(header_json_len as u8);
        header.append(&mut header_json_bytes);
        DocHeaderPacked(header)
    }
}

/// Take an encrypted document and extract out the header metadata. Return that metadata as well as the AESEncryptedValue
/// that contains the AES IV and encrypted content. Will fail if the provided document doesn't contain the latest version
/// which contains the header bytes.
fn parse_document_parts(
    encrypted_document: &[u8],
) -> Result<(DocumentHeader, aes::AesEncryptedValue), IronOxideErr> {
    //We're explicitly erroring on version 1 documents since there are so few of them and it seems extremely unlikely
    //that anybody will use them with this SDK which was released after we went to version 2.
    if encrypted_document[0] != CURRENT_DOCUMENT_ID_VERSION {
        Err(IronOxideErr::DocumentHeaderParseFailure(
            "Document is not a supported version and may not be an encrypted file.".to_string(),
        ))
    } else {
        let header_len_end = DOC_VERSION_HEADER_LENGTH + HEADER_META_LENGTH_LENGTH;
        //The 2nd and 3rd bytes of the header are a big-endian u16 that tell us how long the subsequent JSON
        //header is in bytes. So we need to convert these two u8s into a single u16.
        let encoded_header_size =
            encrypted_document[1] as usize * 256 + encrypted_document[2] as usize;
        serde_json::from_slice(
            &encrypted_document[header_len_end..(header_len_end + encoded_header_size)],
        )
        .map_err(|_| {
            IronOxideErr::DocumentHeaderParseFailure(
                "Unable to parse document header. Header value is corrupted.".to_string(),
            )
        })
        .and_then(|header_json| {
            //Convert the remaining document bytes into an AesEncryptedValue which splits out the IV/data
            Ok((
                header_json,
                encrypted_document[(header_len_end + encoded_header_size)..].try_into()?,
            ))
        })
    }
}

/// The reason a document can be viewed by the requesting user.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AssociationType {
    /// User created the document.
    Owner,
    /// User was directly granted access to the document.
    FromUser,
    /// User was granted access to the document via a group they are a member of.
    FromGroup,
}

/// User who is able to access a document.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct VisibleUser {
    id: UserId,
}
impl VisibleUser {
    /// ID of the user
    pub fn id(&self) -> &UserId {
        &self.id
    }
}

/// Group that is able to access a document.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct VisibleGroup {
    id: GroupId,
    name: Option<GroupName>,
}
impl VisibleGroup {
    /// ID of the group
    pub fn id(&self) -> &GroupId {
        &self.id
    }
    /// Name of the group
    pub fn name(&self) -> Option<&GroupName> {
        self.name.as_ref()
    }
}

/// Abbreviated document metadata.
///
/// Result from [DocumentListResult.result()](struct.DocumentListResult.html#method.result).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocumentListMeta(DocumentListApiResponseItem);
impl DocumentListMeta {
    /// ID of the document
    pub fn id(&self) -> &DocumentId {
        &self.0.id
    }
    /// Name of the document
    pub fn name(&self) -> Option<&DocumentName> {
        self.0.name.as_ref()
    }
    /// How the requesting user has access to the document
    pub fn association_type(&self) -> &AssociationType {
        &self.0.association.typ
    }
    /// Date and time when the document was created
    pub fn created(&self) -> &DateTime<Utc> {
        &self.0.created
    }
    /// Date and time when the document was last updated
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.0.updated
    }
}

/// Metadata for each document the current user has access to.
///
/// Result from [document_list](trait.DocumentOps.html#tymethod.document_list).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocumentListResult {
    result: Vec<DocumentListMeta>,
}
impl DocumentListResult {
    /// Metadata for each document the current user has access to
    pub fn result(&self) -> &Vec<DocumentListMeta> {
        &self.result
    }
}

/// Full metadata for a document.
///
/// Result from [document_get_metadata](trait.DocumentOps.html#tymethod.document_get_metadata) and
/// [document_update_name](trait.DocumentOps.html#tymethod.document_update_name).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocumentMetadataResult(DocumentMetaApiResponse);
impl DocumentMetadataResult {
    /// ID of the document
    pub fn id(&self) -> &DocumentId {
        &self.0.id
    }
    /// Name of the document
    pub fn name(&self) -> Option<&DocumentName> {
        self.0.name.as_ref()
    }
    /// Date and time when the document was created
    pub fn created(&self) -> &DateTime<Utc> {
        &self.0.created
    }
    /// Date and time when the document was last updated
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.0.updated
    }
    /// How the requesting user has access to the document
    pub fn association_type(&self) -> &AssociationType {
        &self.0.association.typ
    }
    /// List of users who have access to the document
    pub fn visible_to_users(&self) -> &Vec<VisibleUser> {
        &self.0.visible_to.users
    }
    /// List of groups that have access to the document
    pub fn visible_to_groups(&self) -> &Vec<VisibleGroup> {
        &self.0.visible_to.groups
    }

    // Not exposed outside of the crate
    fn to_encrypted_symmetric_key(&self) -> Result<recrypt::api::EncryptedValue, IronOxideErr> {
        self.0.encrypted_symmetric_key.clone().try_into()
    }
}

/// Encrypted document bytes and metadata.
///
/// Unmanaged encryption does not store document access information with the webservice,
/// but rather returns the access information as `encrypted_deks`. Both the `encrypted_data` and
/// `encrypted_deks` must be used to decrypt the document.
///
/// Result from [document_encrypt_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_encrypt_unmanaged).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocumentEncryptUnmanagedResult {
    id: DocumentId,
    encrypted_data: Vec<u8>,
    encrypted_deks: Vec<u8>,
    grants: Vec<UserOrGroup>,
    access_errs: Vec<DocAccessEditErr>,
}
impl DocumentEncryptUnmanagedResult {
    fn new(
        encryption_result: EncryptedDoc,
        access_errs: Vec<DocAccessEditErr>,
    ) -> Result<Self, IronOxideErr> {
        let edek_bytes = encryption_result.edek_bytes()?;
        Ok(DocumentEncryptUnmanagedResult {
            id: encryption_result.header.document_id.clone(),
            access_errs,
            encrypted_data: encryption_result.edoc_bytes().to_vec(),
            encrypted_deks: edek_bytes,
            grants: encryption_result
                .value
                .edeks
                .iter()
                .map(|edek| edek.grant_to.id.clone())
                .collect(),
        })
    }

    /// Bytes of encrypted document data
    pub fn encrypted_data(&self) -> &[u8] {
        &self.encrypted_data
    }
    /// Bytes of EDEKs of users/groups that have been granted access to `encrypted_data`
    pub fn encrypted_deks(&self) -> &[u8] {
        &self.encrypted_deks
    }
    /// ID of the document
    pub fn id(&self) -> &DocumentId {
        &self.id
    }
    /// Users and groups the document was successfully encrypted to
    pub fn grants(&self) -> &[UserOrGroup] {
        &self.grants
    }
    /// Errors resulting from failure to encrypt
    pub fn access_errs(&self) -> &[DocAccessEditErr] {
        &self.access_errs
    }
}

/// Encrypted document bytes and metadata.
///
/// Result from [document_encrypt](trait.DocumentOps.html#tymethod.document_encrypt) and
/// [document_update_bytes](trait.DocumentOps.html#tymethod.document_update_bytes).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocumentEncryptResult {
    id: DocumentId,
    name: Option<DocumentName>,
    updated: DateTime<Utc>,
    created: DateTime<Utc>,
    encrypted_data: Vec<u8>,
    grants: Vec<UserOrGroup>,
    access_errs: Vec<DocAccessEditErr>,
}
impl DocumentEncryptResult {
    /// Bytes of encrypted document data
    pub fn encrypted_data(&self) -> &[u8] {
        &self.encrypted_data
    }
    /// ID of the document
    pub fn id(&self) -> &DocumentId {
        &self.id
    }
    /// Name of the document
    pub fn name(&self) -> Option<&DocumentName> {
        self.name.as_ref()
    }
    /// Date and time when the document was created
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }
    /// Date and time when the document was last updated
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.updated
    }
    /// Users and groups the document was successfully encrypted to
    pub fn grants(&self) -> &[UserOrGroup] {
        &self.grants
    }
    /// Errors resulting from failure to encrypt
    pub fn access_errs(&self) -> &[DocAccessEditErr] {
        &self.access_errs
    }
}
/// Decrypted document bytes and metadata.
///
/// Result from [document_decrypt](trait.DocumentOps.html#tymethod.document_decrypt).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocumentDecryptResult {
    id: DocumentId,
    name: Option<DocumentName>,
    updated: DateTime<Utc>,
    created: DateTime<Utc>,
    decrypted_data: Vec<u8>,
}
impl DocumentDecryptResult {
    /// Bytes of decrypted document data
    pub fn decrypted_data(&self) -> &[u8] {
        &self.decrypted_data
    }
    /// ID of the document
    pub fn id(&self) -> &DocumentId {
        &self.id
    }
    /// Name of the document
    pub fn name(&self) -> Option<&DocumentName> {
        self.name.as_ref()
    }
    /// Date and time when the document was created
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }
    /// Date and time when the document was last updated
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.updated
    }
}

/// Failure to edit a document's access list.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocAccessEditErr {
    /// User or group that was unable to have access granted/revoked.
    pub user_or_group: UserOrGroup,
    /// The error encountered when attempting to grant/revoke access.
    pub err: String,
}
impl DocAccessEditErr {
    pub(crate) fn new(user_or_group: UserOrGroup, err_msg: String) -> DocAccessEditErr {
        DocAccessEditErr {
            user_or_group,
            err: err_msg,
        }
    }
}

/// Successful and failed changes to a document's access list.
///
/// Both grant and revoke support partial success.
///
/// Result from [document_grant_access](trait.DocumentOps.html#tymethod.document_grant_access) and
/// [document_revoke_access](trait.DocumentOps.html#tymethod.document_revoke_access).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocumentAccessResult {
    succeeded: Vec<UserOrGroup>,
    failed: Vec<DocAccessEditErr>,
}
impl DocumentAccessResult {
    pub(crate) fn new(
        succeeded: Vec<UserOrGroup>,
        failed: Vec<DocAccessEditErr>,
    ) -> DocumentAccessResult {
        DocumentAccessResult { succeeded, failed }
    }

    /// Users and groups whose access was successfully changed.
    pub fn succeeded(&self) -> &[UserOrGroup] {
        &self.succeeded
    }

    /// Users and groups whose access failed to be changed.
    pub fn failed(&self) -> &[DocAccessEditErr] {
        &self.failed
    }
}
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DecryptedData(Vec<u8>);

/// Decrypted document bytes and metadata.
///
/// Result from [document_decrypt_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_decrypt_unmanaged).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocumentDecryptUnmanagedResult {
    id: DocumentId,
    access_via: UserOrGroup,
    decrypted_data: DecryptedData,
}
impl DocumentDecryptUnmanagedResult {
    /// ID of the document
    pub fn id(&self) -> &DocumentId {
        &self.id
    }
    /// User or group that granted access to the encrypted data
    ///
    /// More specifically, the user or group associated with the EDEK that was chosen and transformed by the webservice
    pub fn access_via(&self) -> &UserOrGroup {
        &self.access_via
    }
    /// Bytes of decrypted document data
    pub fn decrypted_data(&self) -> &[u8] {
        &self.decrypted_data.0
    }
}

/// A user or a group.
///
/// Can be created from `UserId`, `&UserId`, `GroupId`, or `&GroupId` with `UserOrGroup::from()`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum UserOrGroup {
    User { id: UserId },
    Group { id: GroupId },
}
impl std::fmt::Display for UserOrGroup {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            UserOrGroup::User { id } => write!(f, "'{}' [user]", &id.0),
            UserOrGroup::Group { id } => write!(f, "'{}' [group]", &id.0),
        }
    }
}
impl From<UserId> for UserOrGroup {
    fn from(u: UserId) -> Self {
        UserOrGroup::User { id: u }
    }
}
impl From<GroupId> for UserOrGroup {
    fn from(g: GroupId) -> Self {
        UserOrGroup::Group { id: g }
    }
}
impl From<&UserId> for UserOrGroup {
    fn from(u: &UserId) -> Self {
        u.to_owned().into()
    }
}
impl From<&GroupId> for UserOrGroup {
    fn from(g: &GroupId) -> Self {
        g.to_owned().into()
    }
}

/// List all documents that the current user has the ability to see. Either documents that are encrypted
/// to them directly (owner) or documents shared to them via user (fromUser) or group (fromGroup).
pub async fn document_list(
    auth: &RequestAuth,
    client: &Client,
) -> Result<DocumentListResult, IronOxideErr> {
    let DocumentListApiResponse { result } =
        requests::document_list::document_list_request(auth, client).await?;
    Ok(DocumentListResult {
        result: result.into_iter().map(DocumentListMeta).collect(),
    })
}

/// Get the metadata ane encrypted key for a specific document given its ID.
pub async fn document_get_metadata(
    auth: &RequestAuth,
    id: &DocumentId,
    client: &Client,
) -> Result<DocumentMetadataResult, IronOxideErr> {
    Ok(DocumentMetadataResult(
        requests::document_get::document_get_request(auth, id, client).await?,
    ))
}

/// Attempt to parse the provided encrypted document header and extract out the ID if present
pub fn get_id_from_bytes(encrypted_document: &[u8]) -> Result<DocumentId, IronOxideErr> {
    parse_document_parts(encrypted_document).map(|header| header.0.document_id)
}

/// Encrypt a new document and share it with explicit users/groups and with users/groups specified by a policy
pub async fn encrypt_document<
    R1: rand::CryptoRng + rand::RngCore,
    R2: rand::CryptoRng + rand::RngCore,
>(
    auth: &RequestAuth,
    config: &IronOxideConfig,
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<R1>>,
    user_master_pub_key: &PublicKey,
    rng: &Mutex<R2>,
    plaintext: &[u8],
    document_id: Option<DocumentId>,
    document_name: Option<DocumentName>,
    grant_to_author: bool,
    user_grants: &Vec<UserId>,
    group_grants: &Vec<GroupId>,
    policy_grant: Option<&PolicyGrant>,
    policy_cache: &PolicyCache,
    client: &Client,
) -> Result<DocumentEncryptResult, IronOxideErr> {
    let (dek, doc_sym_key) = transform::generate_new_doc_key(recrypt);
    let doc_id = document_id.unwrap_or_else(|| DocumentId::goo_id(rng));
    let pt_bytes = plaintext.to_vec();

    let (encrypted_doc, (grants, key_errs)) = try_join!(
        aes::encrypt_async(rng, &pt_bytes, *doc_sym_key.bytes()),
        resolve_keys_for_grants(
            auth,
            config,
            user_grants,
            group_grants,
            policy_grant,
            if grant_to_author {
                Some(&user_master_pub_key)
            } else {
                None
            },
            policy_cache,
            client
        )
    )?;
    let r = recrypt_document(
        &auth.signing_private_key,
        recrypt,
        dek,
        encrypted_doc,
        &doc_id,
        grants,
    )?;
    let encryption_errs = r.encryption_errs.clone();
    document_create(
        auth,
        r.into_edoc(DocumentHeader::new(doc_id.clone(), auth.segment_id)),
        doc_id,
        &document_name,
        [key_errs, encryption_errs].concat(),
        client,
    )
    .await
}

type UserMasterPublicKey = PublicKey;
/// Get the public keys for a document grant.
///
/// # Arguments
/// `auth`          - info to make webservice requests
/// `user_grants`   - list of user ids to which document access should be granted
/// `group_grants`  - list of groups ids to which document access should be granted
/// `policy_grant`  - policy to apply for document access
/// `maybe_user_master_pub_key`
///                 - if Some, contains the logged in user's master public key for self-grant
///
/// # Returns
/// A Future that will resolve to:
/// (Left)  list of keys for all users and groups that should be granted access to the document
/// (Right) errors for any invalid users/groups that were passed
async fn resolve_keys_for_grants(
    auth: &RequestAuth,
    config: &IronOxideConfig,
    user_grants: &Vec<UserId>,
    group_grants: &Vec<GroupId>,
    policy_grant: Option<&PolicyGrant>,
    maybe_user_master_pub_key: Option<&UserMasterPublicKey>,
    policy_cache: &PolicyCache,
    client: &Client,
) -> Result<(Vec<WithKey<UserOrGroup>>, Vec<DocAccessEditErr>), IronOxideErr> {
    let get_user_keys_f = internal::user_api::get_user_keys(auth, user_grants, client);
    let get_group_keys_f = internal::group_api::get_group_keys(auth, group_grants, client);

    let maybe_policy_grants_f =
        policy_grant.map(|p| (p, requests::policy_get::policy_get_request(auth, p, client)));

    let policy_grants_f = async {
        if let Some((p, policy_eval_f)) = maybe_policy_grants_f {
            get_cached_policy_or(&config.policy_caching, p, policy_cache, policy_eval_f).await
        } else {
            // No policies were included
            Ok((vec![], vec![]))
        }
    };
    let (users, groups, policy_result) =
        try_join!(get_user_keys_f, get_group_keys_f, policy_grants_f)?;
    let (group_errs, groups_with_key) = process_groups(groups);
    let (user_errs, users_with_key) = process_users(users);
    let explicit_grants = [users_with_key, groups_with_key].concat();

    let (policy_errs, applied_policy_grants) = policy_result;
    let maybe_self_grant = {
        if let Some(user_master_pub_key) = maybe_user_master_pub_key {
            vec![WithKey::new(
                UserOrGroup::User {
                    id: auth.account_id.clone(),
                },
                user_master_pub_key.clone(),
            )]
        } else {
            vec![]
        }
    };

    Ok((
        { [maybe_self_grant, explicit_grants, applied_policy_grants].concat() },
        [group_errs, user_errs, policy_errs].concat(),
    ))
}

/// Get a cached policy or run the given Future to get the evaluated policy from the webservice.
/// Policies that evaluate cleanly with no invalid users or groups are cached for future use.
async fn get_cached_policy_or<F>(
    config: &PolicyCachingConfig,
    grant: &PolicyGrant,
    policy_cache: &PolicyCache,
    get_policy_f: F,
) -> Result<(Vec<DocAccessEditErr>, Vec<WithKey<UserOrGroup>>), IronOxideErr>
where
    F: Future<Output = Result<PolicyResponse, IronOxideErr>>,
{
    // if there's a value in the cache, use it
    if let Some(cached_policy) = policy_cache.get(grant) {
        Ok((vec![], cached_policy.clone()))
    } else {
        // otherwise query the webservice and cache the result if there are no errors
        get_policy_f
            .await
            .map(|policy_resp| {
                let (errs, public_keys) = process_policy(&policy_resp);
                if errs.is_empty() {
                    //if the cache has grown too large, clear it prior to adding new entries
                    if policy_cache.len() >= config.max_entries {
                        policy_cache.clear()
                    }
                    policy_cache.insert(grant.clone(), public_keys.clone());
                }
                (errs, public_keys)
            })
            .map_err(|x| match x {
                IronOxideErr::RequestError {
                    http_status: Some(code),
                    ..
                } if code == 404 => IronOxideErr::PolicyDoesNotExist,
                e => e,
            })
    }
}

/// Encrypts a document but does not create the document in the IronCore system.
/// The resultant DocumentDetachedEncryptResult contains both the EncryptedDeks and the AesEncryptedValue
/// Both pieces will be required for decryption.
pub async fn encrypt_document_unmanaged<R1, R2>(
    auth: &RequestAuth,
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<R1>>,
    user_master_pub_key: &PublicKey,
    rng: &Mutex<R2>,
    plaintext: &[u8],
    document_id: Option<DocumentId>,
    grant_to_author: bool,
    user_grants: &Vec<UserId>,
    group_grants: &Vec<GroupId>,
    policy_grant: Option<&PolicyGrant>,
    client: &Client,
) -> Result<DocumentEncryptUnmanagedResult, IronOxideErr>
where
    R1: rand::CryptoRng + rand::RngCore,
    R2: rand::CryptoRng + rand::RngCore,
{
    let policy_cache = dashmap::DashMap::new();
    let config = IronOxideConfig::default();

    let (dek, doc_sym_key) = transform::generate_new_doc_key(recrypt);
    let doc_id = document_id.unwrap_or_else(|| DocumentId::goo_id(rng));
    let pt_bytes = plaintext.to_vec();

    let (encryption_result, (grants, key_errs)) = try_join!(
        aes::encrypt_async(rng, &pt_bytes, *doc_sym_key.bytes()),
        resolve_keys_for_grants(
            auth,
            &config,
            user_grants,
            group_grants,
            policy_grant,
            if grant_to_author {
                Some(&user_master_pub_key)
            } else {
                None
            },
            &policy_cache,
            client
        )
    )?;
    let r = recrypt_document(
        &auth.signing_private_key,
        recrypt,
        dek,
        encryption_result,
        &doc_id,
        grants,
    )?;
    let enc_result = EncryptedDoc {
        header: DocumentHeader::new(doc_id.clone(), auth.segment_id),
        value: r,
    };
    let access_errs = [&key_errs[..], &enc_result.value.encryption_errs[..]].concat();
    DocumentEncryptUnmanagedResult::new(enc_result, access_errs)
}
/// Remove any duplicates in the grant list. Uses ids (not keys) for comparison.
fn dedupe_grants(grants: &[WithKey<UserOrGroup>]) -> Vec<WithKey<UserOrGroup>> {
    grants
        .iter()
        .unique_by(|i| &i.id)
        .map(Clone::clone)
        .collect_vec()
}

/// Encrypt the document using transform crypto (recrypt).
/// Can be called once you have public keys for users/groups that should have access as well as the
/// AES encrypted data.
fn recrypt_document<CR: rand::CryptoRng + rand::RngCore>(
    signing_keys: &DeviceSigningKeyPair,
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    dek: Plaintext,
    encrypted_doc: AesEncryptedValue,
    doc_id: &DocumentId,
    grants: Vec<WithKey<UserOrGroup>>,
) -> Result<RecryptionResult, IronOxideErr> {
    // check to make sure that we are granting to something
    if grants.is_empty() {
        Err(IronOxideErr::ValidationError(
            "grants".into(),
            format!(
                "Access must be granted to document {:?} by explicit grant or via a policy",
                &doc_id
            ),
        ))
    } else {
        Ok({
            // encrypt to all the users and groups
            let (encrypt_errs, grants) = transform::encrypt_to_with_key(
                recrypt,
                &dek,
                &signing_keys.into(),
                dedupe_grants(&grants),
            );

            RecryptionResult {
                edeks: grants
                    .into_iter()
                    .map(|(wk, ev)| EncryptedDek {
                        grant_to: wk,
                        encrypted_dek_data: ev,
                    })
                    .collect(),
                encrypted_data: encrypted_doc,
                encryption_errs: vec![encrypt_errs.into_iter().map(|e| e.into()).collect()]
                    .into_iter()
                    .concat(),
            }
        })
    }
}

/// An encrypted document encryption key.
///
/// Once decrypted, the DEK serves as a symmetric encryption key.
///
/// It can also be useful to think of an EDEK as representing a "document access grant" to a user/group.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EncryptedDek {
    grant_to: WithKey<UserOrGroup>,
    encrypted_dek_data: recrypt::api::EncryptedValue,
}

impl TryFrom<&EncryptedDek> for EncryptedDekP {
    type Error = IronOxideErr;
    fn try_from(edek: &EncryptedDek) -> Result<Self, Self::Error> {
        use crate::proto::transform;
        use recrypt::api as re;

        // encode the recrypt EncryptedValue to a edek proto
        let proto_edek_data = match edek.encrypted_dek_data {
            re::EncryptedValue::EncryptedOnceValue {
                ephemeral_public_key,
                encrypted_message,
                auth_hash,
                public_signing_key,
                signature,
            } => {
                let mut proto_edek_data = EncryptedDekDataP::default();

                proto_edek_data.set_encryptedBytes(encrypted_message.bytes().to_vec().into());
                proto_edek_data
                    .set_ephemeralPublicKey(PublicKey::from(ephemeral_public_key).into());
                proto_edek_data.set_signature(signature.bytes().to_vec().into());
                proto_edek_data.set_authHash(auth_hash.bytes().to_vec().into());
                proto_edek_data.set_publicSigningKey(public_signing_key.bytes().to_vec().into());

                Ok(proto_edek_data)
            }
            re::EncryptedValue::TransformedValue { .. } => Err(
                IronOxideErr::InvalidRecryptEncryptedValue("Expected".to_string()),
            ),
        }?;

        //convert the grants
        let proto_uog = match edek.grant_to.clone() {
            WithKey {
                id:
                    UserOrGroup::User {
                        id: UserId(user_string),
                    },
                public_key,
            } => {
                let mut proto_uog = transform::UserOrGroup::default();
                proto_uog.set_userId(user_string.into());
                proto_uog.set_masterPublicKey(public_key.into());
                proto_uog
            }
            WithKey {
                id:
                    UserOrGroup::Group {
                        id: GroupId(group_string),
                    },
                public_key,
            } => {
                let mut proto_uog = transform::UserOrGroup::default();
                proto_uog.set_groupId(group_string.into());
                proto_uog.set_masterPublicKey(public_key.into());
                proto_uog
            }
        };

        let mut proto_edek = EncryptedDekP::default();
        proto_edek.set_userOrGroup(proto_uog);
        proto_edek.set_encryptedDekData(proto_edek_data);
        Ok(proto_edek)
    }
}
/// Result of recrypt encryption. Contains the encrypted DEKs and the encrypted (user) data.
/// `RecryptionResult` is an intermediate value as it cannot be serialized to bytes directly.
/// To serialize to bytes, first construct an `EncryptedDoc`
#[derive(Clone, Debug)]
struct RecryptionResult {
    edeks: Vec<EncryptedDek>,
    encrypted_data: AesEncryptedValue,
    encryption_errs: Vec<DocAccessEditErr>,
}

impl RecryptionResult {
    fn into_edoc(self, header: DocumentHeader) -> EncryptedDoc {
        EncryptedDoc {
            value: self,
            header,
        }
    }
}

/// An ironoxide encrypted document
#[derive(Debug)]
struct EncryptedDoc {
    header: DocumentHeader,
    value: RecryptionResult,
}

impl EncryptedDoc {
    /// bytes of the encrypted data with the edoc header prepended
    fn edoc_bytes(&self) -> Vec<u8> {
        [
            &self.header.pack().0[..],
            &self.value.encrypted_data.bytes(),
        ]
        .concat()
    }

    /// associated EncryptedDeks for this EncryptedDoc
    fn edek_vec(&self) -> Vec<EncryptedDek> {
        self.value.edeks.clone()
    }

    /// binary blob for associated edeks, or error if encoding the edeks failed
    fn edek_bytes(&self) -> Result<Vec<u8>, IronOxideErr> {
        let proto_edek_vec_results: Result<Vec<_>, _> = self
            .value
            .edeks
            .iter()
            .map(|edek| edek.try_into())
            .collect();
        let proto_edek_vec = proto_edek_vec_results?;

        let mut proto_edeks = EncryptedDeksP::default();
        proto_edeks.edeks = RepeatedField::from_vec(proto_edek_vec);
        proto_edeks.documentId = self.header.document_id.id().into();
        proto_edeks.segmentId = self.header.segment_id as i32; // okay since the ironcore-ws defines this to be an i32

        let edek_bytes = proto_edeks.write_to_bytes()?;
        Ok(edek_bytes)
    }
}

/// Creates an encrypted document entry in the IronCore webservice.
async fn document_create(
    auth: &RequestAuth,
    edoc: EncryptedDoc,
    doc_id: DocumentId,
    doc_name: &Option<DocumentName>,
    accum_errs: Vec<DocAccessEditErr>,
    client: &Client,
) -> Result<DocumentEncryptResult, IronOxideErr> {
    let api_resp = document_create::document_create_request(
        auth,
        doc_id.clone(),
        doc_name.clone(),
        edoc.edek_vec(),
        client,
    )
    .await?;

    Ok(DocumentEncryptResult {
        id: api_resp.id,
        name: api_resp.name,
        created: api_resp.created,
        updated: api_resp.updated,
        encrypted_data: edoc.edoc_bytes().to_vec(),
        grants: api_resp.shared_with.iter().map(|sw| sw.into()).collect(),
        access_errs: [accum_errs, edoc.value.encryption_errs].concat(),
    })
}

/// Encrypt the provided plaintext using the DEK from the provided document ID but with a new AES IV. Allows updating the encrypted bytes
/// of a document without having to change document access.
pub async fn document_update_bytes<
    R1: rand::CryptoRng + rand::RngCore,
    R2: rand::CryptoRng + rand::RngCore,
>(
    auth: &RequestAuth,
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<R1>>,
    device_private_key: &PrivateKey,
    rng: &Mutex<R2>,
    document_id: &DocumentId,
    plaintext: &[u8],
    client: &Client,
) -> Result<DocumentEncryptResult, IronOxideErr> {
    let doc_meta = document_get_metadata(auth, document_id, client).await?;
    let sym_key = transform::decrypt_as_symmetric_key(
        recrypt,
        doc_meta.0.encrypted_symmetric_key.clone().try_into()?,
        device_private_key.recrypt_key(),
    )?;
    Ok(
        aes::encrypt(rng, &plaintext.to_vec(), *sym_key.bytes()).map(move |encrypted_doc| {
            let mut encrypted_payload =
                DocumentHeader::new(document_id.clone(), auth.segment_id()).pack();
            encrypted_payload.0.append(&mut encrypted_doc.bytes());
            DocumentEncryptResult {
                id: doc_meta.0.id,
                name: doc_meta.0.name,
                created: doc_meta.0.created,
                updated: doc_meta.0.updated,
                encrypted_data: encrypted_payload.0,
                grants: vec![],      // grants can't currently change via update
                access_errs: vec![], // no grants, no access errs
            }
        })?,
    )
}

/// Decrypt the provided document with the provided device private key. Return metadata about the document
/// that was decrypted along with its decrypted bytes.
pub async fn decrypt_document<CR: rand::CryptoRng + rand::RngCore + Send + Sync + 'static>(
    auth: &RequestAuth,
    recrypt: std::sync::Arc<Recrypt<Sha256, Ed25519, RandomBytes<CR>>>,
    device_private_key: &PrivateKey,
    encrypted_doc: &[u8],
    client: &Client,
) -> Result<DocumentDecryptResult, IronOxideErr> {
    let (doc_header, mut enc_doc) = parse_document_parts(encrypted_doc)?;
    let doc_meta = document_get_metadata(auth, &doc_header.document_id, client).await?;
    let device_private_key = device_private_key.clone();
    tokio::task::spawn_blocking(move || {
        let sym_key = transform::decrypt_as_symmetric_key(
            &recrypt,
            doc_meta.0.encrypted_symmetric_key.clone().try_into()?,
            device_private_key.recrypt_key(),
        )?;

        Ok(
            aes::decrypt(&mut enc_doc, *sym_key.bytes()).map(move |decrypted_doc| {
                DocumentDecryptResult {
                    id: doc_meta.0.id,
                    name: doc_meta.0.name,
                    created: doc_meta.0.created,
                    updated: doc_meta.0.updated,
                    decrypted_data: decrypted_doc.to_vec(),
                }
            })?,
        )
    })
    .await?
}

/// Decrypt the unmanaged document. The caller must provide both the encrypted data as well as the
/// encrypted DEKs. Most use cases would want `decrypt_document` instead.
pub async fn decrypt_document_unmanaged<CR: rand::CryptoRng + rand::RngCore>(
    auth: &RequestAuth,
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    device_private_key: &PrivateKey,
    encrypted_doc: &[u8],
    encrypted_deks: &[u8],
    client: &Client,
) -> Result<DocumentDecryptUnmanagedResult, IronOxideErr> {
    // attempt to parse the proto as fail-fast validation. If it fails decrypt will fail

    let ((proto_edeks, (doc_meta, mut aes_encrypted_value)), transform_resp) = try_join!(
        async {
            Ok((
                EncryptedDeksP::parse_from_bytes(encrypted_deks).map_err(IronOxideErr::from)?,
                parse_document_parts(encrypted_doc)?,
            ))
        },
        requests::edek_transform::edek_transform(&auth, encrypted_deks, client)
    )?;

    edeks_and_header_match_or_err(&proto_edeks, &doc_meta)?;
    let requests::edek_transform::EdekTransformResponse {
        user_or_group,
        encrypted_symmetric_key,
    } = transform_resp;

    let sym_key = transform::decrypt_as_symmetric_key(
        recrypt,
        encrypted_symmetric_key.try_into()?,
        device_private_key.recrypt_key(),
    )?;
    aes::decrypt(&mut aes_encrypted_value, *sym_key.bytes())
        .map_err(|e| e.into())
        .map(move |decrypted_doc| DocumentDecryptUnmanagedResult {
            id: doc_meta.document_id,
            access_via: user_or_group,
            decrypted_data: DecryptedData(decrypted_doc.to_vec()),
        })
}

/// Check to see if a set of edeks match a document header
fn edeks_and_header_match_or_err(
    edeks: &EncryptedDeksP,
    doc_meta: &DocumentHeader,
) -> Result<(), IronOxideErr> {
    if doc_meta.document_id.id() != edeks.get_documentId()
        || doc_meta.segment_id as i32 != edeks.get_segmentId()
    {
        Err(IronOxideErr::UnmanagedDecryptionError(
            edeks.get_documentId().into(),
            edeks.get_segmentId(),
            doc_meta.document_id.clone().0,
            doc_meta.segment_id as i32,
        ))
    } else {
        Ok(())
    }
}

// Update a documents name. Value can be updated to either a new name with a Some or the name value can be cleared out
// by providing a None.
pub async fn update_document_name(
    auth: &RequestAuth,
    id: &DocumentId,
    name: Option<&DocumentName>,
    client: &Client,
) -> Result<DocumentMetadataResult, IronOxideErr> {
    requests::document_update::document_update_request(auth, id, name, client)
        .await
        .map(DocumentMetadataResult)
}

pub async fn document_grant_access<CR: rand::CryptoRng + rand::RngCore>(
    auth: &RequestAuth,
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    id: &DocumentId,
    user_master_pub_key: &PublicKey,
    priv_device_key: &PrivateKey,
    user_grants: &Vec<UserId>,
    group_grants: &Vec<GroupId>,
    client: &Client,
) -> Result<DocumentAccessResult, IronOxideErr> {
    let (doc_meta, users, groups) = try_join!(
        document_get_metadata(auth, id, client),
        // and the public keys for the users and groups
        internal::user_api::get_user_keys(auth, user_grants, client),
        internal::group_api::get_group_keys(auth, group_grants, client),
    )?;
    let (grants, other_errs) = {
        // decrypt the dek
        let edek = doc_meta.to_encrypted_symmetric_key()?;
        let dek = recrypt.decrypt(edek, priv_device_key.recrypt_key())?;

        let (group_errs, groups_with_key) = process_groups(groups);
        let (user_errs, users_with_key) = process_users(users);
        let users_and_groups = dedupe_grants(&[&users_with_key[..], &groups_with_key[..]].concat());

        // encrypt to all the users and groups
        let (grant_errs, grants) = transform::encrypt_to_with_key(
            recrypt,
            &dek,
            &auth.signing_private_key().into(),
            users_and_groups,
        );

        // squish all accumulated errors into one list
        let other_errs = vec![
            group_errs,
            user_errs,
            grant_errs.into_iter().map(|e| e.into()).collect(),
        ]
        .into_iter()
        .concat();
        (grants, other_errs)
    };

    let resp = requests::document_access::grant_access_request(
        auth,
        id,
        user_master_pub_key,
        grants,
        client,
    )
    .await?;
    Ok(requests::document_access::resp::document_access_api_resp_to_result(resp, other_errs))
}

/// Remove access to a document from the provided list of users and/or groups
pub async fn document_revoke_access(
    auth: &RequestAuth,
    id: &DocumentId,
    revoke_list: &Vec<UserOrGroup>,
    client: &Client,
) -> Result<DocumentAccessResult, IronOxideErr> {
    use requests::document_access::{self, resp};

    let revoke_request_list: Vec<_> = revoke_list
        .iter()
        .map(|entity| match entity {
            UserOrGroup::User { id } => resp::UserOrGroupAccess::User { id: id.0.clone() },
            UserOrGroup::Group { id } => resp::UserOrGroupAccess::Group { id: id.0.clone() },
        })
        .collect();

    let resp =
        document_access::revoke_access_request(auth, id, revoke_request_list, client).await?;
    Ok(resp::document_access_api_resp_to_result(resp, vec![]))
}

/// Map the groups that come back from the server into a common value/err structure
fn process_groups(
    (group_errs, groups_with_key): (Vec<GroupId>, Vec<WithKey<GroupId>>),
) -> (Vec<DocAccessEditErr>, Vec<WithKey<UserOrGroup>>) {
    let group_errs = group_errs
        .into_iter()
        .map(|gid| {
            DocAccessEditErr::new(
                UserOrGroup::Group { id: gid },
                "Group could not be found".to_string(),
            )
        })
        .collect();

    let groups_with_key: Vec<WithKey<UserOrGroup>> = groups_with_key
        .into_iter()
        .map(|WithKey { id, public_key }| WithKey {
            id: UserOrGroup::Group { id },
            public_key,
        })
        .collect();

    (group_errs, groups_with_key)
}

/// Map the users that come back from the server into a common value/err structure
fn process_users(
    (user_errs, users_with_key): (Vec<UserId>, Vec<WithKey<UserId>>),
) -> (Vec<DocAccessEditErr>, Vec<WithKey<UserOrGroup>>) {
    let users_with_key: Vec<WithKey<UserOrGroup>> = users_with_key
        .into_iter()
        .map(|WithKey { id, public_key }| WithKey {
            id: UserOrGroup::User { id },
            public_key,
        })
        .collect();

    // convert all user list errors to AccessErr
    let user_errs: Vec<DocAccessEditErr> = user_errs
        .into_iter()
        .map(|uid| {
            DocAccessEditErr::new(
                UserOrGroup::User { id: uid },
                "User could not be found".to_string(),
            )
        })
        .collect();
    (user_errs, users_with_key)
}

/// Extract users/groups + keys from a PolicyResult (Right). Errors from applying the policy are Left.
fn process_policy(
    policy_result: &PolicyResponse,
) -> (Vec<DocAccessEditErr>, Vec<WithKey<UserOrGroup>>) {
    let (pubkey_errs, policy_eval_results): (Vec<DocAccessEditErr>, Vec<WithKey<UserOrGroup>>) =
        policy_result
            .users_and_groups
            .iter()
            .partition_map(|uog| match uog {
                UserOrGroupWithKey::User {
                    id,
                    master_public_key: Some(key),
                } => {
                    let user = UserOrGroup::User {
                        // okay since these came back from the service
                        id: UserId::unsafe_from_string(id.clone()),
                    };

                    Either::from(
                        key.clone()
                            .try_into()
                            .map(|k| WithKey::new(user.clone(), k))
                            .map_err(|_e| {
                                DocAccessEditErr::new(
                                    user,
                                    format!("Error parsing user public key {:?}", &key),
                                )
                            }),
                    )
                }
                UserOrGroupWithKey::Group {
                    id,
                    master_public_key: Some(key),
                } => {
                    let group = UserOrGroup::Group {
                        // okay since these came back from the service
                        id: GroupId::unsafe_from_string(id.clone()),
                    };

                    Either::from(
                        key.clone()
                            .try_into()
                            .map(|k| WithKey::new(group.clone(), k))
                            .map_err(|_e| {
                                DocAccessEditErr::new(
                                    group,
                                    format!("Error parsing group public key {:?}", &key),
                                )
                            }),
                    )
                }

                any => {
                    let uog: UserOrGroup = any.clone().into();
                    let err_msg = format!("{} does not have associated public key", &uog);
                    Either::Left(DocAccessEditErr::new(uog, err_msg))
                }
            });

    (
        [
            pubkey_errs,
            policy_result
                .invalid_users_and_groups
                .iter()
                .map(|uog| {
                    DocAccessEditErr::new(
                        uog.clone(),
                        format!("Policy refers to unknown user or group '{}'", &uog),
                    )
                })
                .collect(),
        ]
        .concat(),
        policy_eval_results,
    )
}

#[cfg(test)]
mod tests {
    use crate::internal::tests::contains;
    use base64::decode;
    use galvanic_assert::{
        matchers::{collection::*, *},
        *,
    };

    use super::*;
    use crate::internal::RequestErrorCode;
    use dashmap::DashMap;
    use std::borrow::Borrow;

    #[tokio::test]
    async fn get_policy_or() -> Result<(), IronOxideErr> {
        let policy_json = r#"{ "usersAndGroups": [ { "type": "group", "id": "data_recovery_abcABC012_.$#|@/:;=+'-f1e11a54-8aa9-4641-aaf3-fb92079499f0", "masterPublicKey": { "x": "GE5XQYcRDRhBcyDpNwlu79x6tshNi111ym1IfxOTIxk=", "y": "amgLgcCEYIPQ4oxinLoAvsO3VG7XTFdRfkG/3tooaZE=" } } ], "invalidUsersAndGroups": [] }"#;

        let policy_grant = PolicyGrant::default();
        let policy_cache = DashMap::new();
        let config = PolicyCachingConfig::default();
        let policy_resp: PolicyResponse =
            serde_json::from_str(policy_json).expect("json should parse");

        // as a baseline, show that the get_policy_f runs if there is a cache miss
        let err_result = get_cached_policy_or(&config, &policy_grant, &policy_cache, async {
            Err(IronOxideErr::InitializeError("".into()))
        })
        .await;

        assert!(err_result.is_err());

        // now try again, but with a valid get_policy_f that will both return the policy evaluation and cache it
        let policy = get_cached_policy_or(&config, &policy_grant, &policy_cache, async {
            Ok(policy_resp.clone())
        })
        .await?;

        // we've now cached a policy and it's the same as the one that was returned
        assert_eq!(1, policy_cache.len());
        assert_eq!(policy.1, policy_cache.get(&policy_grant).unwrap().clone());

        // let's get the policy again, but if the policy future executes (cache miss) error
        get_cached_policy_or(&config, &policy_grant, &policy_cache, async {
            Err(IronOxideErr::InitializeError("".into()))
        })
        .await?;
        assert_eq!(1, policy_cache.len());

        Ok(())
    }

    #[tokio::test]
    async fn policy_404_gives_nice_error() -> Result<(), IronOxideErr> {
        let policy_grant = PolicyGrant::default();
        let policy_cache = DashMap::new();
        let config = PolicyCachingConfig::default();

        // show transformation of RequestError - 404 for Policy GET to PolicyDoesNotExist
        let err_result = get_cached_policy_or(&config, &policy_grant, &policy_cache, async {
            Err(IronOxideErr::RequestError {
                message: "".into(),
                code: RequestErrorCode::PolicyGet,
                http_status: Some(404),
            })
        })
        .await;
        assert!(err_result.is_err());
        assert_that!(
            &err_result.unwrap_err(),
            is_variant!(IronOxideErr::PolicyDoesNotExist)
        );

        Ok(())
    }

    #[tokio::test]
    async fn policy_cache_max_size_honored() -> Result<(), IronOxideErr> {
        let policy_json = r#"{ "usersAndGroups": [ { "type": "group", "id": "data_recovery_abcABC012_.$#|@/:;=+'-f1e11a54-8aa9-4641-aaf3-fb92079499f0", "masterPublicKey": { "x": "GE5XQYcRDRhBcyDpNwlu79x6tshNi111ym1IfxOTIxk=", "y": "amgLgcCEYIPQ4oxinLoAvsO3VG7XTFdRfkG/3tooaZE=" } } ], "invalidUsersAndGroups": [] }"#;
        let policy_grant = PolicyGrant::default();
        let policy_cache = DashMap::new();
        let config = PolicyCachingConfig { max_entries: 3 };
        let policy_resp: PolicyResponse =
            serde_json::from_str(policy_json).expect("json should parse");

        get_cached_policy_or(&config, &policy_grant, &policy_cache, async {
            Ok(policy_resp.clone())
        })
        .await?;
        assert_eq!(1, policy_cache.len());

        let policy_grant2 = PolicyGrant::new(Some("foo".try_into()?), None, None, None);
        get_cached_policy_or(&config, &policy_grant2, &policy_cache, async {
            Ok(policy_resp.clone())
        })
        .await?;
        assert_eq!(2, policy_cache.len());

        let policy_grant3 = PolicyGrant::new(Some("bar".try_into()?), None, None, None);
        get_cached_policy_or(&config, &policy_grant3, &policy_cache, async {
            Ok(policy_resp.clone())
        })
        .await?;
        assert_eq!(3, policy_cache.len());

        let policy_grant4 = PolicyGrant::new(Some("baz".try_into()?), None, None, None);
        get_cached_policy_or(&config, &policy_grant4, &policy_cache, async {
            Ok(policy_resp.clone())
        })
        .await?;

        // we should be over the configured max_entries, so the cache should reset prior to storing the value
        assert_eq!(1, policy_cache.len());

        Ok(())
    }

    #[tokio::test]
    async fn policy_cache_unclean_entries_not_cached() -> Result<(), IronOxideErr> {
        // policy with 1 "good" group and one "bad" one
        let policy_json = r#"{ "usersAndGroups": [ { "type": "group", "id": "data_recovery_abcABC012_.$#|@/:;=+'-f1e11a54-8aa9-4641-aaf3-fb92079499f0", "masterPublicKey": { "x": "GE5XQYcRDRhBcyDpNwlu79x6tshNi111ym1IfxOTIxk=", "y": "amgLgcCEYIPQ4oxinLoAvsO3VG7XTFdRfkG/3tooaZE=" } } ], "invalidUsersAndGroups": [{ "type": "group", "id": "group-that-does-not-exist" }] }"#;
        let policy_grant = PolicyGrant::default();
        let policy_cache = DashMap::new();
        let config = PolicyCachingConfig::default();
        let policy_resp: PolicyResponse =
            serde_json::from_str(policy_json).expect("json should parse");

        get_cached_policy_or(&config, &policy_grant, &policy_cache, async {
            Ok(policy_resp.clone())
        })
        .await?;
        assert_eq!(0, policy_cache.len());

        Ok(())
    }
    #[test]
    fn document_id_validate_good() {
        let doc_id1 = "an_actual_good_doc_id$";
        let doc_id2 = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        assert_eq!(
            DocumentId(doc_id1.to_string()),
            DocumentId::try_from(doc_id1).unwrap()
        );
        assert_eq!(
            DocumentId(doc_id2.to_string()),
            DocumentId::try_from(doc_id2).unwrap()
        )
    }

    #[test]
    fn document_id_rejects_invalid() {
        let doc_id1 = DocumentId::try_from("not a good ID!");
        let doc_id2 = DocumentId::try_from("!!");
        let doc_id3 = DocumentId::try_from("01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567891");

        assert_that!(
            &doc_id1.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(
            &doc_id2.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
        assert_that!(
            &doc_id3.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
    }

    #[test]
    fn doc_id_rejects_empty() {
        let doc_id = DocumentId::try_from("");
        assert_that!(&doc_id, is_variant!(Err));
        assert_that!(
            &doc_id.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );

        let doc_id = DocumentId::try_from("\n \t  ");
        assert_that!(&doc_id, is_variant!(Err));
        assert_that!(
            &doc_id.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
    }

    #[test]
    fn doc_name_rejects_empty() {
        let doc_name = DocumentName::try_from("");
        assert_that!(&doc_name, is_variant!(Err));
        assert_that!(
            &doc_name.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );

        let doc_name = DocumentName::try_from("\n \t  ");
        assert_that!(&doc_name, is_variant!(Err));
        assert_that!(
            &doc_name.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        );
    }

    #[test]
    fn doc_name_rejects_too_long() {
        let doc_name = DocumentName::try_from("01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567891");

        assert_that!(
            &doc_name.unwrap_err(),
            is_variant!(IronOxideErr::ValidationError)
        )
    }

    #[test]
    fn err_on_bad_doc_header() {
        let doc_with_wrong_version = decode("AQA4eyJfZGlkXyI6ImNjOTIyZTA3NzRhM2MwZWViZTI2NDM2Yzk2ZjdiYzkzIiwiX3NpZF8iOjYwOH1ciL4su5SPZh4eFGuG+5rJ+/I2gDSZAs+2dXw097gU8fBkMWzRo0dDIW0dOxHg/1mio1yMRdDZDA==").unwrap();
        let doc_with_invalid_json = decode("AgA4Z2NfZGlkXyI6ImNjOTIyZTA3NzRhM2MwZWViZTI2NDM2Yzk2ZjdiYzkzIiwiX3NpZF8iOjYwOH1ciL4su5SPZh4eFGuG+5rJ+/I2gDSZAs+2dXw097gU8fBkMWzRo0dDIW0dOxHg/1mio1yMRdDZDA==").unwrap();

        assert_that!(
            &get_id_from_bytes(&doc_with_wrong_version).unwrap_err(),
            has_structure!(
                IronOxideErr::DocumentHeaderParseFailure
                    [contains(&"not a supported version".to_string())]
            )
        );

        assert_that!(
            &get_id_from_bytes(&doc_with_invalid_json).unwrap_err(),
            has_structure!(
                IronOxideErr::DocumentHeaderParseFailure
                    [contains(&"Header value is corrupted".to_string())]
            )
        );
    }

    #[test]
    fn read_good_document_header_test() {
        let enc_doc = decode("AgA4eyJfZGlkXyI6ImNjOTIyZTA3NzRhM2MwZWViZTI2NDM2Yzk2ZjdiYzkzIiwiX3NpZF8iOjYwOH1ciL4su5SPZh4eFGuG+5rJ+/I2gDSZAs+2dXw097gU8fBkMWzRo0dDIW0dOxHg/1mio1yMRdDZDA==").unwrap();

        let doc_id = get_id_from_bytes(&enc_doc).unwrap();

        assert_that!(
            &doc_id,
            has_structure!(DocumentId[eq("cc922e0774a3c0eebe26436c96f7bc93".to_string())])
        );

        let doc_parts = parse_document_parts(&enc_doc).unwrap();

        assert_that!(
            &doc_parts.0,
            has_structure!(DocumentHeader {
                document_id: eq(DocumentId("cc922e0774a3c0eebe26436c96f7bc93".to_string())),
                segment_id: eq(608),
            })
        );

        assert_that!(
            &doc_parts.1.bytes(),
            eq(vec![
                92, 136, 190, 44, 187, 148, 143, 102, 30, 30, 20, 107, 134, 251, 154, 201, 251,
                242, 54, 128, 52, 153, 2, 207, 182, 117, 124, 52, 247, 184, 20, 241, 240, 100, 49,
                108, 209, 163, 71, 67, 33, 109, 29, 59, 17, 224, 255, 89, 162, 163, 92, 140, 69,
                208, 217, 12
            ])
        )
    }

    #[test]
    fn generate_document_header_test() {
        let header = DocumentHeader::new("123abc".try_into().unwrap(), 18usize);

        assert_that!(
            &header.pack().0,
            eq(vec![
                2, 0, 29, 123, 34, 95, 100, 105, 100, 95, 34, 58, 34, 49, 50, 51, 97, 98, 99, 34,
                44, 34, 95, 115, 105, 100, 95, 34, 58, 49, 56, 125
            ])
        );
    }
    #[test]
    fn process_policy_good() {
        let recrypt = recrypt::api::Recrypt::new();
        let (_, pubk) = recrypt.generate_key_pair().unwrap();

        let policy = PolicyResponse {
            users_and_groups: vec![
                UserOrGroupWithKey::User {
                    id: "userid1".to_string(),
                    master_public_key: Some(pubk.into()),
                },
                UserOrGroupWithKey::Group {
                    id: "groupid1".to_string(),
                    master_public_key: Some(pubk.into()),
                },
            ],
            invalid_users_and_groups: vec![],
        };

        let (errs, results) = process_policy(&policy);
        assert_that!(results.len() == 2);
        assert_that!(errs.is_empty());

        let ex_user = WithKey {
            id: UserOrGroup::User {
                id: UserId::unsafe_from_string("userid1".to_string()),
            },
            public_key: pubk.into(),
        };

        let ex_group = WithKey {
            id: UserOrGroup::Group {
                id: GroupId::unsafe_from_string("groupid1".to_string()),
            },
            public_key: pubk.into(),
        };

        assert_that!(&results, contains_in_any_order(vec![ex_user, ex_group]));
    }

    #[test]
    fn dedupe_grants_removes_dupes() {
        let recrypt = recrypt::api::Recrypt::new();
        let (_, pubk) = recrypt.generate_key_pair().unwrap();

        let u1 = &UserId::unsafe_from_string("user1".into());
        let g1 = &GroupId::unsafe_from_string("group1".into());
        let grants_w_dupes: Vec<WithKey<UserOrGroup>> = vec![
            WithKey::new(u1.into(), pubk.into()),
            WithKey::new(g1.into(), pubk.into()),
            WithKey::new(u1.into(), pubk.into()),
            WithKey::new(g1.into(), pubk.into()),
        ];

        let deduplicated_grants = dedupe_grants(&grants_w_dupes);
        assert_that!(&deduplicated_grants.len(), eq(2))
    }

    #[test]
    fn encode_encrypted_dek_proto() {
        use recrypt::{api::Hashable, prelude::*};
        let recrypt_api = recrypt::api::Recrypt::new();
        let (_, pubk) = recrypt_api.generate_key_pair().unwrap();
        let signing_keys = recrypt_api.generate_ed25519_key_pair();
        let plaintext = recrypt_api.gen_plaintext();
        let encrypted_value = recrypt_api
            .encrypt(&plaintext, &pubk, &signing_keys)
            .unwrap();
        let user_str = "userid".to_string();

        let edek = EncryptedDek {
            encrypted_dek_data: encrypted_value.clone(),
            grant_to: WithKey {
                public_key: pubk.into(),
                id: UserId::unsafe_from_string(user_str.clone()).borrow().into(),
            },
        };

        let proto_edek: EncryptedDekP = edek.borrow().try_into().unwrap();

        assert_eq!(
            &user_str,
            &proto_edek.get_userOrGroup().get_userId().to_string()
        );
        let (x, y) = pubk.bytes_x_y();
        assert_eq!(
            (x.to_vec(), y.to_vec()),
            (
                proto_edek
                    .get_userOrGroup()
                    .get_masterPublicKey()
                    .get_x()
                    .to_vec(),
                proto_edek
                    .get_userOrGroup()
                    .get_masterPublicKey()
                    .get_y()
                    .to_vec()
            )
        );

        if let recrypt::api::EncryptedValue::EncryptedOnceValue {
            ephemeral_public_key,
            encrypted_message,
            auth_hash,
            public_signing_key,
            signature,
        } = encrypted_value
        {
            assert_eq!(
                (
                    ephemeral_public_key.bytes_x_y().0.to_vec(),
                    ephemeral_public_key.bytes_x_y().1.to_vec()
                ),
                (
                    proto_edek
                        .get_encryptedDekData()
                        .get_ephemeralPublicKey()
                        .get_x()
                        .to_vec(),
                    proto_edek
                        .get_encryptedDekData()
                        .get_ephemeralPublicKey()
                        .get_y()
                        .to_vec()
                )
            );

            assert_eq!(
                encrypted_message.bytes().to_vec(),
                proto_edek
                    .get_encryptedDekData()
                    .get_encryptedBytes()
                    .to_vec()
            );

            assert_eq!(
                auth_hash.bytes().to_vec(),
                proto_edek.get_encryptedDekData().get_authHash().to_vec()
            );

            assert_eq!(
                public_signing_key.to_bytes(),
                proto_edek
                    .get_encryptedDekData()
                    .get_publicSigningKey()
                    .to_vec()
            );

            assert_eq!(
                signature.bytes().to_vec(),
                proto_edek.get_encryptedDekData().get_signature().to_vec()
            );
        } else {
            panic!("Should be EncryptedOnceValue");
        }
    }

    #[test]
    pub fn unmanaged_edoc_header_properly_encoded() -> Result<(), IronOxideErr> {
        use recrypt::prelude::*;

        let recr = recrypt::api::Recrypt::new();
        let signingkeys = DeviceSigningKeyPair::from(recr.generate_ed25519_key_pair());
        let aes_value = AesEncryptedValue::try_from(&[42u8; 32][..])?;
        let uid = UserId::unsafe_from_string("userid".into());
        let gid = GroupId::unsafe_from_string("groupid".into());
        let user: UserOrGroup = uid.borrow().into();
        let group: UserOrGroup = gid.borrow().into();
        let (_, pubk) = recr.generate_key_pair()?;
        let with_keys = vec![
            WithKey::new(user, pubk.clone().into()),
            WithKey::new(group, pubk.into()),
        ];
        let doc_id = DocumentId("docid".into());
        let seg_id = 33;

        let encryption_result = recrypt_document(
            &signingkeys,
            &recr,
            recr.gen_plaintext(),
            aes_value,
            &doc_id,
            with_keys,
        )?
        .into_edoc(DocumentHeader::new(doc_id.clone(), seg_id));

        assert_eq!(&encryption_result.header.document_id, &doc_id);
        assert_eq!(&encryption_result.header.segment_id, &seg_id);

        let edoc_bytes = encryption_result.edoc_bytes();
        let (parsed_header, _) = parse_document_parts(&edoc_bytes)?;
        assert_eq!(&encryption_result.header, &parsed_header);

        Ok(())
    }

    #[test]
    pub fn unmanaged_edoc_compare_grants() -> Result<(), IronOxideErr> {
        use crate::proto::transform::{
            UserOrGroup as UserOrGroupP, UserOrGroup_oneof_UserOrGroupId as UserOrGroupIdP,
        };
        use recrypt::prelude::*;

        let recr = recrypt::api::Recrypt::new();
        let signingkeys = DeviceSigningKeyPair::from(recr.generate_ed25519_key_pair());
        let aes_value = AesEncryptedValue::try_from(&[42u8; 32][..])?;
        let uid = UserId::unsafe_from_string("userid".into());
        let gid = GroupId::unsafe_from_string("groupid".into());
        let user: UserOrGroup = uid.borrow().into();
        let group: UserOrGroup = gid.borrow().into();
        let (_, pubk) = recr.generate_key_pair()?;
        let with_keys = vec![
            WithKey::new(user, pubk.clone().into()),
            WithKey::new(group, pubk.into()),
        ];
        let doc_id = DocumentId("docid".into());
        let seg_id = 33;

        let encryption_result = recrypt_document(
            &signingkeys,
            &recr,
            recr.gen_plaintext(),
            aes_value,
            &doc_id,
            with_keys,
        )?
        .into_edoc(DocumentHeader::new(doc_id.clone(), seg_id));

        // create an unmanaged result, which does the proto serialization
        let doc_encrypt_unmanaged_result =
            DocumentEncryptUnmanagedResult::new(encryption_result, vec![])?;

        // then deserialize and extract the user/groups from the edeks
        let proto_edeks =
            EncryptedDeksP::parse_from_bytes(doc_encrypt_unmanaged_result.encrypted_deks())?;
        let result: Result<Vec<UserOrGroup>, IronOxideErr> = proto_edeks
            .edeks
            .as_slice()
            .iter()
            .map(|edek| {
                if let Some(UserOrGroupP {
                    UserOrGroupId: Some(proto_uog),
                    ..
                }) = edek.userOrGroup.as_ref()
                {
                    match proto_uog {
                        UserOrGroupIdP::userId(user_chars) => Ok(UserOrGroup::User {
                            id: user_chars.to_string().try_into()?,
                        }),
                        UserOrGroupIdP::groupId(group_chars) => Ok(UserOrGroup::Group {
                            id: group_chars.to_string().try_into()?,
                        }),
                    }
                } else {
                    Err(IronOxideErr::ProtobufValidationError(format!(
                        "EncryptedDek does not have a valid user or group: {:?}",
                        &edek
                    )))
                }
            })
            .collect();

        // show that grants() and the edeks contain the same users/groups
        assert_that!(
            &result?,
            contains_in_any_order(vec![
                UserOrGroup::Group { id: gid.clone() },
                UserOrGroup::User { id: uid.clone() }
            ])
        );

        assert_that!(
            &doc_encrypt_unmanaged_result.grants().to_vec(),
            contains_in_any_order(vec![
                UserOrGroup::Group { id: gid },
                UserOrGroup::User { id: uid }
            ])
        );

        Ok(())
    }

    #[test]
    pub fn edek_edoc_no_match() -> Result<(), IronOxideErr> {
        use recrypt::prelude::*;

        let recr = recrypt::api::Recrypt::new();
        let signingkeys = DeviceSigningKeyPair::from(recr.generate_ed25519_key_pair());
        let aes_value = AesEncryptedValue::try_from(&[42u8; 32][..])?;
        let uid = UserId::unsafe_from_string("userid".into());
        let gid = GroupId::unsafe_from_string("groupid".into());
        let user: UserOrGroup = uid.borrow().into();
        let group: UserOrGroup = gid.borrow().into();
        let (_, pubk) = recr.generate_key_pair()?;
        let with_keys = vec![
            WithKey::new(user, pubk.clone().into()),
            WithKey::new(group, pubk.into()),
        ];
        let doc_id = DocumentId("docid".into());
        let seg_id = 33;

        let encryption_result = recrypt_document(
            &signingkeys,
            &recr,
            recr.gen_plaintext(),
            aes_value,
            &doc_id,
            with_keys,
        )?;

        // orig doc
        let edoc1 = encryption_result
            .clone()
            .into_edoc(DocumentHeader::new(doc_id.clone(), seg_id));

        // with wrong doc id
        let edoc2 = encryption_result.clone().into_edoc(DocumentHeader::new(
            DocumentId("other_docid".into()),
            seg_id,
        ));

        // with wrong seg id
        let edoc3 = encryption_result.into_edoc(DocumentHeader::new(doc_id.clone(), 42));

        let edoc1_bytes = edoc1.edoc_bytes();
        let edek2_bytes = edoc2.edek_bytes()?;
        let edek3_bytes = edoc3.edek_bytes()?;

        // test non matching doc ids
        {
            let proto_edeks =
                EncryptedDeksP::parse_from_bytes(&edek2_bytes).map_err(IronOxideErr::from)?;
            let (doc_meta, _) = parse_document_parts(&edoc1_bytes)?;
            let err = edeks_and_header_match_or_err(&proto_edeks, &doc_meta).unwrap_err();

            assert_that!(&err, is_variant!(IronOxideErr::UnmanagedDecryptionError));
            if let IronOxideErr::UnmanagedDecryptionError(
                edek_doc_id,
                edek_seg_id,
                edoc_doc_id,
                edoc_seg_id,
            ) = err
            {
                assert_eq!(&edek_doc_id, "other_docid");
                assert_eq!(edek_seg_id, seg_id as i32);
                assert_eq!(&edoc_doc_id, doc_id.id());
                assert_eq!(edoc_seg_id, seg_id as i32);
            }
        }

        // test non matching seg ids
        {
            let proto_edeks =
                EncryptedDeksP::parse_from_bytes(&edek3_bytes).map_err(IronOxideErr::from)?;
            let (doc_meta, _) = parse_document_parts(&edoc1_bytes)?;
            let err = edeks_and_header_match_or_err(&proto_edeks, &doc_meta).unwrap_err();

            assert_that!(&err, is_variant!(IronOxideErr::UnmanagedDecryptionError));
            if let IronOxideErr::UnmanagedDecryptionError(
                edek_doc_id,
                edek_seg_id,
                edoc_doc_id,
                edoc_seg_id,
            ) = err
            {
                assert_eq!(&edek_doc_id, doc_id.id());
                assert_eq!(edek_seg_id, 42i32);
                assert_eq!(&edoc_doc_id, doc_id.id());
                assert_eq!(edoc_seg_id, seg_id as i32);
            }
        }

        Ok(())
    }
}
