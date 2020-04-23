pub use crate::internal::document_api::{
    AssociationType, DocAccessEditErr, DocumentAccessResult, DocumentDecryptResult,
    DocumentEncryptResult, DocumentId, DocumentListMeta, DocumentListResult,
    DocumentMetadataResult, DocumentName, UserOrGroup, VisibleGroup, VisibleUser,
};
use crate::{
    common::SdkOperation,
    group::GroupId,
    internal::{add_optional_timeout, document_api},
    policy::PolicyGrant,
    user::UserId,
    Result,
};
use itertools::{Either, EitherOrBoth, Itertools};

/// Advanced document operations
pub mod advanced;

/// List of users and groups that should have access to decrypt a document.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExplicitGrant {
    grant_to_author: bool,
    grants: Vec<UserOrGroup>,
}

impl ExplicitGrant {
    /// Construct a new ExplicitGrant.
    ///
    /// # Arguments
    /// - `grant_to_author` - True if the calling user should have access to decrypt the document
    /// - `grants` - List of users and groups that should have access to decrypt the document
    pub fn new(grant_to_author: bool, grants: &[UserOrGroup]) -> ExplicitGrant {
        ExplicitGrant {
            grant_to_author,
            grants: grants.to_vec(),
        }
    }
}

/// Parameters that can be provided when encrypting a new document.
///
/// Document IDs must be unique to the segment. If no ID is provided, one will be generated for it.
/// If no document name is provided, the document's name will be left empty.
///
/// For default parameters, use `DocumentEncryptOpts::default()`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DocumentEncryptOpts {
    id: Option<DocumentId>,
    name: Option<DocumentName>,
    // at least one user/group must be included either explicitly or via a policy
    grants: EitherOrBoth<ExplicitGrant, PolicyGrant>,
}

impl DocumentEncryptOpts {
    /// Constructs a new `DocumentEncryptOpts`.
    ///
    /// Document encryption requires an `ExplicitGrant`, a `PolicyGrant`, or both. If only using one type
    /// of grant, consider using [with_explicit_grants](./struct.DocumentEncryptOpts.html#method.with_explicit_grants)
    /// or [with_policy_grants](./struct.DocumentEncryptOpts.html#method.with_policy_grants) instead.
    ///
    /// # Arguments
    /// - `id` - Unique ID to use for the document. Note: this ID will **not** be encrypted.
    /// - `name` - Non-unique name to use for the document. Note: this name will **not** be encrypted.
    /// - `grants` - Grants that control who will have access to read and decrypt this document.
    pub fn new(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        grants: EitherOrBoth<ExplicitGrant, PolicyGrant>,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts { grants, name, id }
    }

    /// Constructs a new `DocumentEncryptOpts` with access explicitly granted to certain users and groups.
    ///
    /// # Arguments
    /// - `id` - Unique ID to use for the document. Note: this ID will **not** be encrypted.
    /// - `name` - Non-unique name to use for the document. Note: this name will **not** be encrypted.
    /// - `grant_to_author` - True if the calling user should have access to decrypt the document
    /// - `grants` - List of users and groups that should have access to read and decrypt this document
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

    /// Constructs a new `DocumentEncryptOpts` with access granted by a policy.
    ///
    /// # Arguments
    /// - `id` - Unique ID to use for the document. Note: this ID will **not** be encrypted.
    /// - `name` - Non-unique name to use for the document. Note: this name will **not** be encrypted.
    /// - `policy` - Policy to determine which users and groups will have access to read and decrypt this document.
    ///              See the [policy](../policy/index.html) module for more information.
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
    /// Constructs a `DocumentEncryptOpts` with common values.
    ///
    /// The document will have a generated ID and no name. Only the document's author will be able to
    /// read and decrypt it.
    fn default() -> Self {
        DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![])
    }
}

#[async_trait]
pub trait DocumentOps {
    /// Encrypts the provided document bytes.
    ///
    /// Returns a `DocumentEncryptResult` which contains document metadata as well as the `encrypted_data`,
    /// which is the only thing that must be passed to [document_decrypt](trait.DocumentOps.html#tymethod.document_decrypt)
    /// in order to decrypt the document.
    ///
    /// Metadata about the document will be stored by IronCore, but the encrypted bytes of the document will not. To encrypt
    /// without any document information being stored by IronCore, consider using
    /// [document_encrypt_unmanaged](advanced/trait.DocumentAdvancedOps.html#tymethod.document_encrypt_unmanaged) instead.
    ///
    /// # Arguments
    /// - `document_data` - Bytes of the document to encrypt
    /// - `encrypt_opts` - Document encryption parameters. Default values are provided with `DocumentEncryptOpts::default()`.
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # use ironoxide::document::DocumentEncryptOpts;
    /// let data = "secret data".as_bytes();
    /// let encrypted = sdk.document_encrypt(data, &DocumentEncryptOpts::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn document_encrypt(
        &self,
        document_data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptResult>;

    /// Decrypts an IronCore encrypted document.
    ///
    /// Returns details about the document as well as its decrypted bytes.
    ///
    /// # Arguments
    /// - `encrypted_document` - Bytes of encrypted document. These should be the same bytes returned from
    /// [document_encrypt](trait.DocumentOps.html#tymethod.document_encrypt).
    ///
    /// # Errors
    /// Fails if passed malformed data or if the calling user does not have sufficient access to the document.
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # let encrypted_data: Vec<u8> = vec![];
    /// let decrypted_document = sdk.document_decrypt(&encrypted_data).await?;
    /// let decrypted_data = decrypted_document.decrypted_data();
    /// # Ok(())
    /// # }
    /// ```
    async fn document_decrypt(&self, encrypted_document: &[u8]) -> Result<DocumentDecryptResult>;

    /// Lists metadata for all of the encrypted documents that the calling user can read or decrypt.
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # use ironoxide::document::DocumentListMeta;
    /// # let sdk: IronOxide = unimplemented!();
    /// let document_data = sdk.document_list().await?;
    /// let documents: Vec<DocumentListMeta> = document_data.result().to_vec();
    /// # Ok(())
    /// # }
    async fn document_list(&self) -> Result<DocumentListResult>;

    /// Returns the metadata for an encrypted document.
    ///
    /// This will not return the encrypted document bytes, as they are not stored by IronCore.
    ///
    /// # Arguments
    /// - `id` - Unique ID of the document to retrieve
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// use std::convert::TryFrom;
    /// let document_id = DocumentId::try_from("test_document")?;
    /// let document_meta = sdk.document_get_metadata(&document_id).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn document_get_metadata(&self, id: &DocumentId) -> Result<DocumentMetadataResult>;

    /// Returns the document ID from the bytes of an encrypted document.
    ///
    /// This is the same ID returned by `DocumentEncryptResult.id()`.
    ///
    /// # Arguments
    /// - `encrypted_document` - Bytes of the encrypted document
    ///
    /// # Errors
    /// Fails if the provided bytes are not an encrypted document or have no header.
    ///
    /// # Examples
    /// ```
    /// # fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # let bytes: Vec<u8> = vec![];
    /// // with `bytes` returned from `document_encrypt`
    /// let document_id = sdk.document_get_id_from_bytes(&bytes)?;
    /// # Ok(())
    /// # }
    /// ```
    fn document_get_id_from_bytes(&self, encrypted_document: &[u8]) -> Result<DocumentId>;

    /// Updates the contents of an existing IronCore encrypted document.
    ///
    /// The new contents will be encrypted, and which users and groups are granted access
    /// will remain unchanged.
    ///
    /// # Arguments
    /// - `id` - Unique ID of the document to update
    /// - `new_document_data` - Updated bytes to encrypt
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # let document_id: DocumentId = unimplemented!();
    /// let new_data = "more secret data".as_bytes();
    /// let encrypted = sdk.document_update_bytes(&document_id, new_data).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn document_update_bytes(
        &self,
        id: &DocumentId,
        new_document_data: &[u8],
    ) -> Result<DocumentEncryptResult>;

    /// Modifies or removes a document's name.
    ///
    /// Returns the updated metadata of the document.
    ///
    /// # Arguments
    /// - `id` - Unique ID of the document to update
    /// - `name` - New name for the document. Provide a `Some` to update to a new name or a `None` to clear the name field.
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # let document_id: DocumentId = unimplemented!();
    /// use std::convert::TryFrom;
    /// let new_name = DocumentName::try_from("updated")?;
    /// let document_meta = sdk.document_update_name(&document_id, Some(&new_name)).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn document_update_name(
        &self,
        id: &DocumentId,
        name: Option<&DocumentName>,
    ) -> Result<DocumentMetadataResult>;

    /// Grants decryption access to a document for the provided users and/or groups.
    ///
    /// Returns lists of successful and failed grants.
    ///
    /// # Arguments
    /// - `document_id` - Unique ID of the document whose access is being modified.
    /// - `grant_list` - List of users and groups to grant access to.
    ///
    /// # Errors
    /// This operation supports partial success. If the request succeeds, then the resulting
    /// `DocumentAccessResult` will indicate which grants succeeded and which failed, and it
    /// will provide an explanation for each failure.
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # let document_id: DocumentId = unimplemented!();
    /// # let users: Vec<UserId> = vec![];
    /// use ironoxide::document::UserOrGroup;
    /// // from a list of UserIds, `users`
    /// let users_or_groups: Vec<UserOrGroup> = users.iter().map(|user| user.into()).collect();
    /// let access_result = sdk.document_grant_access(&document_id, &users_or_groups).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn document_grant_access(
        &self,
        document_id: &DocumentId,
        grant_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult>;

    /// Revokes decryption access to a document for the provided users and/or groups.
    ///
    /// Returns lists of successful and failed revocations.
    ///
    /// # Arguments
    /// - `document_id` - Unique ID of the document whose access is being modified.
    /// - `revoke_list` - List of users and groups to revoke access from.
    ///
    /// # Errors
    /// This operation supports partial success. If the request succeeds, then the resulting
    /// `DocumentAccessResult` will indicate which revocations succeeded and which failed, and it
    /// will provide an explanation for each failure.
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # let document_id: DocumentId = unimplemented!();
    /// # let users: Vec<UserId> = vec![];
    /// use ironoxide::document::UserOrGroup;
    /// // from a list of UserIds, `users`
    /// let users_or_groups: Vec<UserOrGroup> = users.iter().map(|user| user.into()).collect();
    /// let access_result = sdk.document_revoke_access(&document_id, &users_or_groups).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn document_revoke_access(
        &self,
        document_id: &DocumentId,
        revoke_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult>;
}

#[async_trait]
impl DocumentOps for crate::IronOxide {
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
