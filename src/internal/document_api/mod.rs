use crate::internal::take_lock;
use crate::proto::transform::EncryptedDek as EncryptedDekP;
use crate::proto::transform::EncryptedDekData as EncryptedDekDataP;
use crate::proto::transform::EncryptedDeks as EncryptedDeksP;
use crate::{
    crypto::{
        aes::{self, AesEncryptedValue},
        transform,
    },
    internal::{
        self,
        document_api::requests::UserOrGroupWithKey,
        group_api::{GroupId, GroupName},
        user_api::UserId,
        validate_id, validate_name, IronOxideErr, PrivateKey, PublicKey, RequestAuth, WithKey,
    },
    policy::PolicyGrant,
    DeviceSigningKeyPair,
};
use chrono::{DateTime, Utc};
use futures::prelude::*;
use hex::encode;
use itertools::{Either, Itertools};
use protobuf::{Message, ProtobufError, RepeatedField};
use rand::{self, CryptoRng, RngCore};
use recrypt::{api::Plaintext, prelude::*};
pub use requests::policy_get::PolicyResult;
use requests::{
    document_create,
    document_list::{DocumentListApiResponse, DocumentListApiResponseItem},
    DocumentMetaApiResponse,
};
use std::ops::DerefMut;
use std::sync::Mutex;
use std::{
    convert::{TryFrom, TryInto},
    fmt::Formatter,
};

mod requests;

const DOC_VERSION_HEADER_LENGTH: usize = 1;
const HEADER_META_LENGTH_LENGTH: usize = 2;
const CURRENT_DOCUMENT_ID_VERSION: u8 = 2;

/// Document ID. Unique within the segment. Must match the regex `^[a-zA-Z0-9_.$#|@/:;=+'-]+$`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentId(pub(crate) String);
impl DocumentId {
    pub fn id(&self) -> &String {
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

/// Document name type. Validates that the provided document name isn't an empty string
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentName(pub(crate) String);
impl DocumentName {
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

/// Binary version of the document header. Appropriate for using in edoc serialization.
struct DocHeaderPacked(Vec<u8>);

/// Represents a parsed document header which is decoded from JSON
#[derive(Debug, Serialize, Deserialize, PartialEq)]
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

/// Represents the reason a document can be viewed by the requesting user.
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AssociationType {
    /// User created the document
    Owner,
    /// User directly granted access to the document
    FromUser,
    /// User granted access to the document via a group they are a member of
    FromGroup,
}

/// Represents a User struct which is returned from doc get to show the IDs of users the document is visible to
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VisibleUser {
    id: UserId,
}
impl VisibleUser {
    pub fn id(&self) -> &UserId {
        &self.id
    }
}

/// Represents a Group struct which is returned from doc get to show the IDs and names of groups the document is visible to
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VisibleGroup {
    id: GroupId,
    name: Option<GroupName>,
}
impl VisibleGroup {
    pub fn id(&self) -> &GroupId {
        &self.id
    }
    pub fn name(&self) -> Option<&GroupName> {
        self.name.as_ref()
    }
}

/// Single document's (abbreviated) metadata. Returned as part of a `DocumentListResult`.
///
/// If you want full metadata for a document, see `DocumentMetadataResult`
#[derive(Clone, Debug)]
pub struct DocumentListMeta(DocumentListApiResponseItem);
impl DocumentListMeta {
    pub fn id(&self) -> &DocumentId {
        &self.0.id
    }
    pub fn name(&self) -> Option<&DocumentName> {
        self.0.name.as_ref()
    }
    pub fn association_type(&self) -> &AssociationType {
        &self.0.association.typ
    }
    pub fn created(&self) -> &DateTime<Utc> {
        &self.0.created
    }
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.0.updated
    }
}

/// Metadata for each of the documents that the current user has access to decrypt.
#[derive(Debug)]
pub struct DocumentListResult {
    result: Vec<DocumentListMeta>,
}
impl DocumentListResult {
    pub fn result(&self) -> &Vec<DocumentListMeta> {
        &self.result
    }
}

/// Full metadata for a document.
#[derive(Clone)]
pub struct DocumentMetadataResult(DocumentMetaApiResponse);
impl DocumentMetadataResult {
    pub fn id(&self) -> &DocumentId {
        &self.0.id
    }
    pub fn name(&self) -> Option<&DocumentName> {
        self.0.name.as_ref()
    }
    pub fn created(&self) -> &DateTime<Utc> {
        &self.0.created
    }
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.0.updated
    }
    pub fn association_type(&self) -> &AssociationType {
        &self.0.association.typ
    }
    pub fn visible_to_users(&self) -> &Vec<VisibleUser> {
        &self.0.visible_to.users
    }
    pub fn visible_to_groups(&self) -> &Vec<VisibleGroup> {
        &self.0.visible_to.groups
    }

    pub(crate) fn to_encrypted_symmetric_key(
        &self,
    ) -> Result<recrypt::api::EncryptedValue, IronOxideErr> {
        self.0.encrypted_symmetric_key.clone().try_into()
    }
}

/// Result for encrypt operations that do not store document access information with the webservice,
/// but rather return the access information as `encrypted_deks`. Both the `encrypted_data` and
/// `encrypted_deks` must be used to decrypt. See `document_edek_decrypt`
///
/// - `id` - Unique (within the segment) id of the document
/// - `encrypted_data` - Bytes of encrypted document content
/// - `encrypted_deks` - List of encrypted document encryption keys (EDEK) of users/groups that have been granted access to `encrypted_data`
/// - `access_errs` - Users and groups that could not be granted access
#[derive(Debug)]
pub struct DocumentEncryptUnmanagedResult {
    id: DocumentId,
    encrypted_data: Vec<u8>,
    encrypted_deks: Vec<u8>,
    grants: Vec<UserOrGroup>,
    access_errs: Vec<DocAccessEditErr>,
}

impl DocumentEncryptUnmanagedResult {
    fn new(
        doc_id: &DocumentId,
        segment_id: usize,
        encryption_result: EncryptedDocUnmanaged,
        access_errs: Vec<DocAccessEditErr>,
    ) -> Result<Self, IronOxideErr> {
        let proto_edek_vec_results: Result<Vec<_>, _> = encryption_result
            .value
            .edeks
            .iter()
            .map(|edek| edek.try_into())
            .collect();
        let proto_edek_vec = proto_edek_vec_results?;

        let mut proto_edeks = EncryptedDeksP::default();
        proto_edeks.edeks = RepeatedField::from_vec(proto_edek_vec);
        proto_edeks.documentId = doc_id.id().as_str().into();
        proto_edeks.segmentId = segment_id as i32; // okay since the ironcore-ws defines this to be an i32

        let edek_bytes = proto_edeks.write_to_bytes()?;

        Ok(DocumentEncryptUnmanagedResult {
            id: doc_id.clone(),
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

    pub fn id(&self) -> &DocumentId {
        &self.id
    }
    pub fn encrypted_data(&self) -> &[u8] {
        &self.encrypted_data
    }
    pub fn encrypted_deks(&self) -> &[u8] {
        &self.encrypted_deks
    }
    pub fn access_errs(&self) -> &[DocAccessEditErr] {
        &self.access_errs
    }
    pub fn grants(&self) -> &[UserOrGroup] {
        &self.grants
    }
}

/// Result for encrypt operations.
///
/// - `id` - Unique (within the segment) id of the document
/// - `name` Non-unique document name. The document name is *not* encrypted.
/// - `updated` - When the document was last updated
/// - `created` - When the document was created
/// - `encrypted_data` - Bytes of encrypted document content
/// - `grants` - Users and groups that have access to decrypt the `encrypted_data`
/// - `access_errs` - Users and groups that could not be granted access
#[derive(Debug)]
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
    pub fn id(&self) -> &DocumentId {
        &self.id
    }
    pub fn name(&self) -> Option<&DocumentName> {
        self.name.as_ref()
    }
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.updated
    }
    pub fn encrypted_data(&self) -> &[u8] {
        &self.encrypted_data
    }
    pub fn grants(&self) -> &[UserOrGroup] {
        &self.grants
    }
    pub fn access_errs(&self) -> &[DocAccessEditErr] {
        &self.access_errs
    }
}
/// Result of decrypting a document. Includes minimal metadata as well as the decrypted bytes.
#[derive(Debug)]
pub struct DocumentDecryptResult {
    id: DocumentId,
    name: Option<DocumentName>,
    updated: DateTime<Utc>,
    created: DateTime<Utc>,
    decrypted_data: Vec<u8>,
}
impl DocumentDecryptResult {
    pub fn id(&self) -> &DocumentId {
        &self.id
    }
    pub fn name(&self) -> Option<&DocumentName> {
        self.name.as_ref()
    }
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }
    pub fn last_updated(&self) -> &DateTime<Utc> {
        &self.updated
    }
    pub fn decrypted_data(&self) -> &[u8] {
        &self.decrypted_data
    }
}

/// A failure to edit the access list of a document.
#[derive(Debug, Clone)]
pub struct DocAccessEditErr {
    /// User or group whose access was to be granted/revoked
    pub user_or_group: UserOrGroup,
    /// Reason for failure
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

/// Result of granting or revoking access to a document. Both grant and revoke support partial
/// success.
#[derive(Debug)]
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

    /// Users whose access was successfully changed.
    pub fn succeeded(&self) -> &[UserOrGroup] {
        &self.succeeded
    }

    /// Users whose access was not changed.
    pub fn failed(&self) -> &[DocAccessEditErr] {
        &self.failed
    }
}

/// Either a user or a group. Allows for containing both.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

impl From<&UserId> for UserOrGroup {
    fn from(u: &UserId) -> Self {
        UserOrGroup::User { id: u.clone() }
    }
}

impl From<&GroupId> for UserOrGroup {
    fn from(g: &GroupId) -> Self {
        UserOrGroup::Group { id: g.clone() }
    }
}

/// List all documents that the current user has the ability to see. Either documents that are encrypted
/// to them directly (owner) or documents shared to them via user (fromUser) or group (fromGroup).
pub fn document_list(
    auth: &RequestAuth,
) -> impl Future<Item = DocumentListResult, Error = IronOxideErr> {
    requests::document_list::document_list_request(auth).map(
        |DocumentListApiResponse { result }| DocumentListResult {
            result: result.into_iter().map(DocumentListMeta).collect(),
        },
    )
}

/// Get the metadata ane encrypted key for a specific document given its ID.
pub fn document_get_metadata(
    auth: &RequestAuth,
    id: &DocumentId,
) -> impl Future<Item = DocumentMetadataResult, Error = IronOxideErr> {
    requests::document_get::document_get_request(auth, id).map(DocumentMetadataResult)
}

// Attempt to parse the provided encrypted document header and extract out the ID if present
pub fn get_id_from_bytes(encrypted_document: &[u8]) -> Result<DocumentId, IronOxideErr> {
    parse_document_parts(&encrypted_document).map(|header| header.0.document_id)
}

/// Encrypt a new document and share it with explicit users/groups and with users/groups specified by a policy
pub fn encrypt_document<
    'a,
    R1: rand::CryptoRng + rand::RngCore,
    R2: rand::CryptoRng + rand::RngCore,
>(
    auth: &'a RequestAuth,
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<R1>>,
    user_master_pub_key: &'a PublicKey,
    rng: &'a Mutex<R2>,
    plaintext: &'a [u8],
    document_id: Option<DocumentId>,
    document_name: Option<DocumentName>,
    grant_to_author: bool,
    user_grants: &'a Vec<UserId>,
    group_grants: &'a Vec<GroupId>,
    policy_grant: Option<&'a PolicyGrant>,
) -> impl Future<Item = DocumentEncryptResult, Error = IronOxideErr> + 'a {
    let (dek, doc_sym_key) = transform::generate_new_doc_key(recrypt);
    let doc_id = document_id.unwrap_or(DocumentId::goo_id(rng));
    aes::encrypt_future(rng, &plaintext.to_vec(), *doc_sym_key.bytes())
        .join(resolve_keys_for_grants(
            auth,
            user_grants,
            group_grants,
            policy_grant,
            if grant_to_author {
                Some(&user_master_pub_key)
            } else {
                None
            },
        ))
        .and_then(move |(encrypted_doc, (grants, key_errs))| {
            recrypt_document(
                &auth.signing_keys,
                recrypt,
                dek,
                encrypted_doc,
                &doc_id,
                grants,
            )
            .into_future()
            .and_then(move |r| {
                let encryption_errs = r.encryption_errs.clone();
                document_create(
                    &auth,
                    r.into_edoc_unmanaged(DocumentHeader::new(doc_id.clone(), auth.segment_id)),
                    doc_id,
                    &document_name,
                    [key_errs, encryption_errs].concat(),
                )
            })
        })
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
fn resolve_keys_for_grants<'a>(
    auth: &'a RequestAuth,
    user_grants: &'a Vec<UserId>,
    group_grants: &'a Vec<GroupId>,
    policy_grant: Option<&'a PolicyGrant>,
    maybe_user_master_pub_key: Option<&'a UserMasterPublicKey>,
) -> impl Future<Item = (Vec<WithKey<UserOrGroup>>, Vec<DocAccessEditErr>), Error = IronOxideErr> + 'a
{
    internal::user_api::get_user_keys(auth, user_grants)
        .join3(
            internal::group_api::get_group_keys(auth, group_grants),
            policy_grant.map(|p| requests::policy_get::policy_get_request(auth, p)),
        )
        .map(move |(users, groups, maybe_policy_res)| {
            let (group_errs, groups_with_key) = process_groups(groups);
            let (user_errs, users_with_key) = process_users(users);
            let explicit_grants = [users_with_key, groups_with_key].concat();
            let (policy_errs, applied_policy_grants) = match maybe_policy_res {
                None => (vec![], vec![]),
                Some(res) => process_policy(&res),
            };
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

            (
                { [maybe_self_grant, explicit_grants, applied_policy_grants].concat() },
                [group_errs, user_errs, policy_errs].concat(),
            )
        })
}

/// Encrypts a document but does not create the document in the IronCore system.
/// The resultant DocumentDetachedEncryptResult contains both the EncryptedDeks and the AesEncryptedValue
/// Both pieces will be required for decryption.
pub fn edek_encrypt_document<'a, R1, R2: 'a>(
    auth: &'a RequestAuth,
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<R1>>,
    user_master_pub_key: &'a PublicKey,
    rng: &Mutex<R2>,
    plaintext: &[u8],
    document_id: Option<DocumentId>,
    grant_to_author: bool,
    user_grants: &'a Vec<UserId>,
    group_grants: &'a Vec<GroupId>,
    policy_grant: Option<&'a PolicyGrant>,
) -> impl Future<Item = DocumentEncryptUnmanagedResult, Error = IronOxideErr> + 'a
where
    R1: rand::CryptoRng + rand::RngCore,
    R2: rand::CryptoRng + rand::RngCore,
{
    let (dek, doc_sym_key) = transform::generate_new_doc_key(recrypt);
    let doc_id = document_id.unwrap_or(DocumentId::goo_id(rng));

    aes::encrypt_future(rng, &plaintext.to_vec(), *doc_sym_key.bytes())
        .join(resolve_keys_for_grants(
            auth,
            user_grants,
            group_grants,
            policy_grant,
            if grant_to_author {
                Some(&user_master_pub_key)
            } else {
                None
            },
        ))
        .and_then(move |(encryption_result, (grants, key_errs))| {
            Ok({
                let r = recrypt_document(
                    &auth.signing_keys,
                    recrypt,
                    dek,
                    encryption_result,
                    &doc_id,
                    grants,
                )?;
                let enc_result = EncryptedDocUnmanaged {
                    header: DocumentHeader::new(doc_id.clone(), auth.segment_id),
                    value: r,
                };
                let access_errs = [&key_errs[..], &enc_result.value.encryption_errs[..]].concat();
                DocumentEncryptUnmanagedResult::new(
                    &doc_id,
                    auth.segment_id,
                    enc_result,
                    access_errs,
                )?
            })
        })
}

impl From<ProtobufError> for IronOxideErr {
    fn from(e: ProtobufError) -> Self {
        internal::IronOxideErr::ProtobufSerdeError(e)
    }
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
fn recrypt_document<'a, CR: rand::CryptoRng + rand::RngCore>(
    signing_keys: &'a DeviceSigningKeyPair,
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
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
#[derive(Debug, Clone, PartialEq)]
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

                proto_edek_data.set_encryptedBytes(encrypted_message.bytes()[..].into());
                proto_edek_data
                    .set_ephemeralPublicKey(PublicKey::from(ephemeral_public_key).into());
                proto_edek_data.set_signature(signature.bytes()[..].into());
                proto_edek_data.set_authHash(auth_hash.bytes()[..].into());
                proto_edek_data.set_publicSigningKey(public_signing_key.bytes()[..].into());

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

#[derive(Debug, Clone)]
struct RecryptionResult {
    edeks: Vec<EncryptedDek>,
    encrypted_data: AesEncryptedValue,
    encryption_errs: Vec<DocAccessEditErr>,
}

impl RecryptionResult {
    fn into_edoc_unmanaged(self, header: DocumentHeader) -> EncryptedDocUnmanaged {
        EncryptedDocUnmanaged {
            value: self,
            header,
        }
    }
}

struct EncryptedDocUnmanaged {
    header: DocumentHeader,
    value: RecryptionResult,
}

// TODO is this a reasonable name?
impl EncryptedDocUnmanaged {
    fn edoc_bytes(&self) -> Vec<u8> {
        [
            &self.header.pack().0[..],
            &self.value.encrypted_data.bytes(),
        ]
        .concat() //TODO
    }

    //    fn edek_bytes(&self) -> &[u8] {
    //        &self.value.edeks //TODO I could move the proto serialization here...
    //    }
}

/// Creates an encrypted document entry in the IronCore webservice.
fn document_create<'a>(
    auth: &'a RequestAuth,
    encryption_result: EncryptedDocUnmanaged,
    doc_id: DocumentId,
    doc_name: &Option<DocumentName>,
    accum_errs: Vec<DocAccessEditErr>,
) -> impl Future<Item = DocumentEncryptResult, Error = IronOxideErr> + 'a {
    document_create::document_create_request(
        auth,
        doc_id.clone(),
        doc_name.clone(),
        encryption_result.value.edeks.to_vec(),
    )
    .map(move |api_resp| DocumentEncryptResult {
        id: api_resp.id,
        name: api_resp.name,
        created: api_resp.created,
        updated: api_resp.updated,
        encrypted_data: encryption_result.edoc_bytes().to_vec(),
        grants: api_resp.shared_with.iter().map(|sw| sw.into()).collect(),
        access_errs: [accum_errs, encryption_result.value.encryption_errs].concat(),
    })
}

/// Encrypt the provided plaintext using the DEK from the provided document ID but with a new AES IV. Allows updating the encrypted bytes
/// of a document without having to change document access.
pub fn document_update_bytes<
    'a,
    R1: rand::CryptoRng + rand::RngCore,
    R2: rand::CryptoRng + rand::RngCore,
>(
    auth: &'a RequestAuth,
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<R1>>,
    device_private_key: &'a PrivateKey,
    rng: &'a Mutex<R2>,
    document_id: &'a DocumentId,
    plaintext: &'a [u8],
) -> impl Future<Item = DocumentEncryptResult, Error = IronOxideErr> + 'a {
    document_get_metadata(auth, &document_id).and_then(move |doc_meta| {
        let (_, sym_key) = transform::decrypt_plaintext(
            &recrypt,
            doc_meta.0.encrypted_symmetric_key.clone().try_into()?,
            &device_private_key.recrypt_key(),
        )?;
        Ok(
            aes::encrypt(&rng, &plaintext.to_vec(), *sym_key.bytes()).map(
                move |encrypted_doc| {
                    let mut encrypted_payload =
                        DocumentHeader::new(document_id.clone(), auth.segment_id()).pack();
                    encrypted_payload.0.append(&mut encrypted_doc.bytes());
                    DocumentEncryptResult {
                        id: doc_meta.0.id,
                        name: doc_meta.0.name,
                        created: doc_meta.0.created,
                        updated: doc_meta.0.updated,
                        encrypted_data: encrypted_payload.0,
                        grants: vec![], // grants can't currently change via update
                        access_errs: vec![], // no grants, no access errs
                    }
                },
            )?,
        )
    })
}

/// Decrypt the provided document with the provided device private key. Return metadata about the document
/// that was decrypted along with it's decrypted bytes.
pub fn decrypt_document<'a, CR: rand::CryptoRng + rand::RngCore>(
    auth: &'a RequestAuth,
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    device_private_key: &'a PrivateKey,
    encrypted_doc: &'a [u8],
) -> impl Future<Item = DocumentDecryptResult, Error = IronOxideErr> + 'a {
    parse_document_parts(encrypted_doc)
        .into_future()
        .and_then(move |mut enc_doc_parts| {
            document_get_metadata(auth, &enc_doc_parts.0.document_id).and_then(move |doc_meta| {
                let (_, sym_key) = transform::decrypt_plaintext(
                    &recrypt,
                    doc_meta.0.encrypted_symmetric_key.clone().try_into()?,
                    &device_private_key.recrypt_key(),
                )?;
                aes::decrypt(&mut enc_doc_parts.1, *sym_key.bytes())
                    .map_err(|e| e.into())
                    .map(move |decrypted_doc| DocumentDecryptResult {
                        id: doc_meta.0.id,
                        name: doc_meta.0.name,
                        created: doc_meta.0.created,
                        updated: doc_meta.0.updated,
                        decrypted_data: decrypted_doc.to_vec(),
                    })
            })
        })
}

/// Decrypt the unmanaged document. The caller must provide both the encrypted data as well as the
/// encrypted DEKs. Most use cases would want `decrypt_document` instead.
pub fn decrypt_document_unmanaged<'a, CR: rand::CryptoRng + rand::RngCore>(
    auth: &'a RequestAuth,
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    device_private_key: &'a PrivateKey,
    encrypted_doc: &'a [u8],
    encrypted_deks: &'a [u8],
) -> impl Future<Item = DocumentDecryptUnmanagedResult, Error = IronOxideErr> + 'a {
    requests::edek_transform::edek_transform(&auth, encrypted_deks) //TODO proto decode here?
        .join(parse_document_parts(encrypted_doc).into_future())
        .and_then(
            move |(
                requests::edek_transform::EdekTransformResponse {
                    user_or_group,
                    encrypted_symmetric_key,
                },
                (DocumentHeader { document_id, .. }, mut enc_data),
            )| {
                let (_, sym_key) = transform::decrypt_plaintext(
                    &recrypt,
                    encrypted_symmetric_key.try_into()?,
                    &device_private_key.recrypt_key(),
                )?;
                aes::decrypt(&mut enc_data, *sym_key.bytes())
                    .map_err(|e| e.into())
                    .map(move |decrypted_doc| DocumentDecryptUnmanagedResult {
                        id: document_id,
                        access_via: user_or_group,
                        decrypted_data: DecryptedData(decrypted_doc.to_vec()),
                    })
            },
        )
}

struct DecryptedData(Vec<u8>);
pub struct DocumentDecryptUnmanagedResult {
    id: DocumentId,
    access_via: UserOrGroup,
    decrypted_data: DecryptedData,
}

impl DocumentDecryptUnmanagedResult {
    pub fn id(&self) -> &DocumentId {
        &self.id
    }

    /// user or group that allowed the caller to decrypt the data
    pub fn access_via(&self) -> &UserOrGroup {
        &self.access_via
    }

    pub fn decrypted_data(&self) -> &[u8] {
        &self.decrypted_data.0
    }
}

// Update a documents name. Value can be updated to either a new name with a Some or the name value can be cleared out
// by providing a None.
pub fn update_document_name<'a>(
    auth: &'a RequestAuth,
    id: &'a DocumentId,
    name: Option<&'a DocumentName>,
) -> impl Future<Item = DocumentMetadataResult, Error = IronOxideErr> + 'a {
    requests::document_update::document_update_request(auth, id, name).map(DocumentMetadataResult)
}

pub fn document_grant_access<'a, CR: rand::CryptoRng + rand::RngCore>(
    auth: &'a RequestAuth,
    recrypt: &'a Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    id: &'a DocumentId,
    user_master_pub_key: &'a PublicKey,
    priv_device_key: &'a PrivateKey,
    user_grants: &'a Vec<UserId>,
    group_grants: &'a Vec<GroupId>,
) -> impl Future<Item = DocumentAccessResult, Error = IronOxideErr> + 'a {
    // get the document metadata
    document_get_metadata(auth, id)
        // and the public keys for the users and groups
        .join3(
            internal::user_api::get_user_keys(auth, user_grants),
            internal::group_api::get_group_keys(auth, group_grants),
        )
        .and_then(move |(doc_meta, users, groups)| {
            Ok({
                // decrypt the dek
                let edek = doc_meta.to_encrypted_symmetric_key()?;
                let dek = recrypt.decrypt(edek, &priv_device_key.clone().into())?;

                let (group_errs, groups_with_key) = process_groups(groups);
                let (user_errs, users_with_key) = process_users(users);
                let users_and_groups =
                    dedupe_grants(&[&users_with_key[..], &groups_with_key[..]].concat());

                // encrypt to all the users and groups
                let (grant_errs, grants) = transform::encrypt_to_with_key(
                    recrypt,
                    &dek,
                    &auth.signing_keys().into(),
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
            })
        })
        .and_then(move |(grants, other_errs)| {
            requests::document_access::grant_access_request(auth, id, user_master_pub_key, grants)
                .map(|resp| {
                    requests::document_access::resp::document_access_api_resp_to_result(
                        resp, other_errs,
                    )
                })
        })
}

/// Remove access to a document from the provided list of users and/or groups
pub fn document_revoke_access<'a>(
    auth: &'a RequestAuth,
    id: &'a DocumentId,
    revoke_list: &Vec<UserOrGroup>,
) -> impl Future<Item = DocumentAccessResult, Error = IronOxideErr> + 'a {
    use requests::document_access::{self, resp};

    let revoke_request_list: Vec<_> = revoke_list
        .into_iter()
        .map(|entity| match entity {
            UserOrGroup::User { id } => resp::UserOrGroupAccess::User { id: id.0.clone() },
            UserOrGroup::Group { id } => resp::UserOrGroupAccess::Group { id: id.0.clone() },
        })
        .collect();

    document_access::revoke_access_request(auth, id, revoke_request_list)
        .map(|resp| resp::document_access_api_resp_to_result(resp, vec![]))
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
    policy_result: &PolicyResult,
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
                    let err_msg =
                        format!("{} does not have associated public key", &uog).to_string();
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
    use crate::internal::test::contains;
    use base64::decode;
    use galvanic_assert::matchers::{collection::*, *};

    use super::*;
    use std::borrow::Borrow;

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
        println!("{:?}", doc_id);
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

        let policy = PolicyResult {
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
        assert_that!(errs.len() == 0);

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
        use recrypt::api::Hashable;
        use recrypt::prelude::*;
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

    //TODO test that shows edoc header is properly generated

    #[test]
    pub fn compare_grants_to_edek_encoded() -> Result<(), IronOxideErr> {
        use crate::proto::transform::UserOrGroup as UserOrGroupP;
        use crate::proto::transform::UserOrGroup_oneof_UserOrGroupId as UserOrGroupIdP;
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
        .into_edoc_unmanaged(DocumentHeader::new(doc_id.clone(), seg_id));

        // create an unmanged result, which does the proto serialization
        let doc_encrypt_unmanaged_result =
            DocumentEncryptUnmanagedResult::new(&doc_id, 1, encryption_result, vec![])?;

        // then deserialize and extract the user/groups from the edeks
        let proto_edeks: EncryptedDeksP =
            protobuf::parse_from_bytes(doc_encrypt_unmanaged_result.encrypted_deks())?;
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
                    Err(IronOxideErr::ProtobufValidationError(
                        format!(
                            "EncryptedDek does not have a valid user or group: {:?}",
                            &edek
                        )
                        .into(),
                    ))
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
}
