pub use crate::internal::document_api::{
    AssociationType, DocAccessEditErr, DocumentAccessResult, DocumentDecryptResult,
    DocumentEncryptResult, DocumentListMeta, DocumentListResult, DocumentMetadataResult,
    UserOrGroup, VisibleGroup, VisibleUser,
};
use crate::{
    internal::{
        add_optional_timeout,
        document_api::{self, DocumentId, DocumentName},
        group_api::GroupId,
        user_api::UserId,
        SdkOperation,
    },
    policy::*,
    Result,
};
use itertools::{Either, EitherOrBoth, Itertools};
use std::hash::{Hash, Hasher};

/// Advanced document operations
pub mod advanced;

/// Optional parameters that can be provided when encrypting a new document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentEncryptOpts {
    id: Option<DocumentId>,
    name: Option<DocumentName>,
    // at least one user/group must be included either explicitly or via a policy
    grants: EitherOrBoth<ExplicitGrant, PolicyGrant>,
}

impl Hash for DocumentEncryptOpts {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.name.hash(state);
        match &self.grants {
            EitherOrBoth::Left(explicit) => {
                0.hash(state);
                explicit.hash(state);
            }
            EitherOrBoth::Right(policy) => {
                1.hash(state);
                policy.hash(state);
            }
            EitherOrBoth::Both(explicit, policy) => {
                2.hash(state);
                explicit.hash(state);
                policy.hash(state);
            }
        }
    }
}

/// Explicit users/groups that should have access to decrypt a document.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExplicitGrant {
    grant_to_author: bool,
    grants: Vec<UserOrGroup>,
}

impl ExplicitGrant {
    /// `grant_to_author` - true if the calling user should have access to decrypt the document
    /// `grants` - other UserOrGroups that should have access to the document
    pub fn new(grant_to_author: bool, grants: &[UserOrGroup]) -> ExplicitGrant {
        ExplicitGrant {
            grant_to_author,
            grants: grants.to_vec(),
        }
    }
}

impl DocumentEncryptOpts {
    pub fn new(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        grants: EitherOrBoth<ExplicitGrant, PolicyGrant>,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts { grants, name, id }
    }
    pub fn with_explicit_grants(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        grant_to_author: bool,
        grants: Vec<UserOrGroup>,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts {
            id,
            name,
            grants: EitherOrBoth::Left(ExplicitGrant {
                grants,
                grant_to_author,
            }),
        }
    }

    pub fn with_policy_grants(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        policy: PolicyGrant,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts {
            id,
            name,
            grants: EitherOrBoth::Right(policy),
        }
    }
}

impl Default for DocumentEncryptOpts {
    /// default to only sharing with the creator of the document
    fn default() -> Self {
        DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![])
    }
}

#[async_trait]
pub trait DocumentOps {
    /// List all of the documents that the current user is able to decrypt.
    ///
    /// # Returns
    /// `DocumentListResult` struct with vec of metadata about each document the user can decrypt.
    async fn document_list(&self) -> Result<DocumentListResult>;

    /// Get the metadata for a specific document given its ID.
    ///
    /// # Arguments
    /// - `id` - Unique ID of the document to retrieve
    ///
    /// # Returns
    /// `DocumentMetadataResult` with details about the requested document.
    async fn document_get_metadata(&self, id: &DocumentId) -> Result<DocumentMetadataResult>;

    /// Attempt to parse the document ID out of an encrypted document.
    ///
    /// # Arguments
    /// - `encrypted_document` - Encrypted document bytes
    ///
    /// # Returns
    /// `Result<DocumentId>` Fails if provided encrypted document has no header, otherwise returns extracted ID.
    fn document_get_id_from_bytes(&self, encrypted_document: &[u8]) -> Result<DocumentId>;

    /// Encrypt the provided document bytes.
    ///
    /// # Arguments
    /// - `document_data` - Bytes of the document to encrypt
    /// - `encrypt_opts` - Optional document encrypt parameters. Includes
    ///       `id` - Unique ID to use for the document. Document ID will be stored unencrypted and must be unique per segment.
    ///       `name` - Non-unique name to use in the document. Document name will **not** be encrypted.
    ///       `grant_to_author` - Flag determining whether to encrypt to the calling user or not. If set to false at least one value must be present in the `grant` list.
    ///       `grants` - List of users/groups to grant access to this document once encrypted
    async fn document_encrypt(
        &self,
        document_data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptResult>;

    /// Update the encrypted content of an existing document. Persists any existing access to other users and groups.
    ///
    /// # Arguments
    /// - `id` - ID of document to update.
    /// - `new_document_data` - Updated document content to encrypt.
    async fn document_update_bytes(
        &self,
        id: &DocumentId,
        new_document_data: &[u8],
    ) -> Result<DocumentEncryptResult>;

    /// Decrypts the provided encrypted document and returns details about the document as well as its decrypted bytes.
    ///
    /// # Arguments
    /// - `encrypted_document` - Bytes of encrypted document. Should be the same bytes returned from `document_encrypt`.
    ///
    /// # Returns
    /// `Result<DocumentDecryptResult>` Includes metadata about the provided document as well as the decrypted document bytes.
    async fn document_decrypt(&self, encrypted_document: &[u8]) -> Result<DocumentDecryptResult>;

    /// Update a document name to a new value or clear its value.
    ///
    /// # Arguments
    /// - `id` - ID of the document to update
    /// - `name` - New name for the document. Provide a Some to update to a new name and a None to clear the name field.
    ///
    /// # Returns
    /// `Result<DocumentMetadataResult>` Metadata about the document that was updated.
    async fn document_update_name(
        &self,
        id: &DocumentId,
        name: Option<&DocumentName>,
    ) -> Result<DocumentMetadataResult>;

    /// Grant access to a document. Recipients of document access can be either users or groups.
    ///
    /// # Arguments
    /// `document_id` - id of the document whose access is is being modified
    /// `grant_list` - list of grants. Elements represent either a user or a group.
    ///
    /// # Returns
    /// Outer result indicates that the request failed either on the client or that the server rejected
    /// the whole request. If the outer result is `Ok` then each individual grant to a user/group
    /// either succeeded or failed.
    async fn document_grant_access(
        &self,
        document_id: &DocumentId,
        grant_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult>;

    /// Revoke access from a document. Revocation of document access can be either users or groups.
    ///
    /// # Arguments
    /// `document_id` - id of the document whose access is is being modified
    /// `revoke_list` - List of revokes. Elements represent either a user or a group.
    ///
    /// # Returns
    /// Outer result indicates that the request failed either on the client or that the server rejected
    /// the whole request. If the outer result is `Ok` then each individual revoke from a user/group
    /// either succeeded or failed.
    async fn document_revoke_access(
        &self,
        document_id: &DocumentId,
        revoke_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult>;
}

#[async_trait]
impl DocumentOps for crate::IronOxide {
    async fn document_list(&self) -> Result<DocumentListResult> {
        add_optional_timeout(
            document_api::document_list(self.device.auth()),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentList,
        )
        .await?
    }

    async fn document_get_metadata(&self, id: &DocumentId) -> Result<DocumentMetadataResult> {
        add_optional_timeout(
            document_api::document_get_metadata(self.device.auth(), id),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentGetMetadata,
        )
        .await?
    }

    fn document_get_id_from_bytes(&self, encrypted_document: &[u8]) -> Result<DocumentId> {
        document_api::get_id_from_bytes(encrypted_document)
    }

    async fn document_encrypt(
        &self,
        document_data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptResult> {
        let encrypt_opts = encrypt_opts.clone();

        let (explicit_users, explicit_groups, grant_to_author, policy_grants) =
            match encrypt_opts.grants {
                EitherOrBoth::Left(explicit_grants) => {
                    let (users, groups) = partition_user_or_group(&explicit_grants.grants);
                    (users, groups, explicit_grants.grant_to_author, None)
                }
                EitherOrBoth::Right(policy_grant) => (vec![], vec![], false, Some(policy_grant)),
                EitherOrBoth::Both(explicit_grants, policy_grant) => {
                    let (users, groups) = partition_user_or_group(&explicit_grants.grants);
                    (
                        users,
                        groups,
                        explicit_grants.grant_to_author,
                        Some(policy_grant),
                    )
                }
            };
        add_optional_timeout(
            document_api::encrypt_document(
                self.device.auth(),
                &self.config,
                &self.recrypt,
                &self.user_master_pub_key,
                &self.rng,
                document_data,
                encrypt_opts.id,
                encrypt_opts.name,
                grant_to_author,
                &explicit_users,
                &explicit_groups,
                policy_grants.as_ref(),
                &self.policy_eval_cache,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentEncrypt,
        )
        .await?
    }

    async fn document_update_bytes(
        &self,
        id: &DocumentId,
        new_document_data: &[u8],
    ) -> Result<DocumentEncryptResult> {
        add_optional_timeout(
            document_api::document_update_bytes(
                self.device.auth(),
                &self.recrypt,
                self.device.device_private_key(),
                &self.rng,
                id,
                new_document_data,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentUpdateBytes,
        )
        .await?
    }

    async fn document_decrypt(&self, encrypted_document: &[u8]) -> Result<DocumentDecryptResult> {
        add_optional_timeout(
            document_api::decrypt_document(
                self.device.auth(),
                &self.recrypt,
                self.device.device_private_key(),
                encrypted_document,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentDecrypt,
        )
        .await?
    }

    async fn document_update_name(
        &self,
        id: &DocumentId,
        name: Option<&DocumentName>,
    ) -> Result<DocumentMetadataResult> {
        add_optional_timeout(
            document_api::update_document_name(self.device.auth(), id, name),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentUpdateName,
        )
        .await?
    }

    async fn document_grant_access(
        &self,
        id: &DocumentId,
        grant_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        let (users, groups) = partition_user_or_group(grant_list);

        add_optional_timeout(
            document_api::document_grant_access(
                self.device.auth(),
                &self.recrypt,
                id,
                &self.user_master_pub_key,
                self.device.device_private_key(),
                &users,
                &groups,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentGrantAccess,
        )
        .await?
    }

    async fn document_revoke_access(
        &self,
        id: &DocumentId,
        revoke_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        add_optional_timeout(
            document_api::document_revoke_access(self.device.auth(), id, revoke_list),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentRevokeAccess,
        )
        .await?
    }
}

fn partition_user_or_group(uog_slice: &[UserOrGroup]) -> (Vec<UserId>, Vec<GroupId>) {
    uog_slice
        .iter()
        .partition_map(|access_grant| match access_grant {
            UserOrGroup::User { id } => Either::Left(id.clone()),
            UserOrGroup::Group { id } => Either::Right(id.clone()),
        })
}
