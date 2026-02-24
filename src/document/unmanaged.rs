//! Unmanaged document API
//!
//! See [DocumentUnmanagedOps](trait.DocumentUnmanagedOps.html) for unmanaged document functions and key terms.

pub use crate::internal::document_api::{
    DocumentAccessResult, DocumentDecryptUnmanagedResult, DocumentEncryptUnmanagedResult, DocumentId,
    DocumentMetadataUnmanagedResult, UserOrGroup
};
use crate::{
    Result, SdkOperation,
    document::{DocumentEncryptOpts, partition_user_or_group},
    internal,
    internal::add_optional_timeout,
};
use futures::Future;
use itertools::EitherOrBoth;


/// IronOxide Unmanaged Document Operations
///
/// These versions of the document operations allow the API consumer to manage the encrypted document encryption keys
/// (EDEKs) produced by document encryption and required for document decryption.
///
/// The managed version of encryption and stores the EDEKs for each document on the server, and
/// decryption determines which of the EDEKs for a document the caller can decrypt and returns that one to be
/// decrypted by the SDK.
///
/// These unmanaged functions allow the API consumer to store and managed the EDEKs, which in
/// particular allows for offline encryption operations (if you provide the public keys for the
/// users / groups to which you want to encrypt).
///
pub trait DocumentUnmanagedOps {
    /// Encrypts the provided document without storing the document metadata in the IronCore service.
    ///
    /// The webservice is still needed for looking up public keys and evaluating policies, but no
    /// document is created in the service and the EDEKs are not stored. Note that if you initialize
    /// the SDK with the public keys for the users and/or groups you are encrypting to and if you call
    /// encrypt with explicit grants instead of policy grants, you can do the encryption offline
    /// (without contacting the server).
    ///
    /// An additional burden is put on the caller to store both the encrypted data and the EDEKs
    /// together, so they can be provided for decryption.
    ///
    /// # Arguments
    /// - `data` - Bytes of the document to encrypt
    /// - `encrypt_opts` - Document encryption parameters. Default values are provided with
    ///   [DocumentEncryptOpts::default()](../struct.DocumentEncryptOpts.html#method.default).
    fn document_encrypt(
        &self,
        data: Vec<u8>,
        encrypt_opts: &DocumentEncryptOpts,
    ) -> impl Future<Output = Result<DocumentEncryptUnmanagedResult>> + Send;

    /// Decrypts a document whose metadata is not managed by the IronCore service.
    ///
    /// Requires the encrypted data and EDEKs returned from
    /// [document_encrypt_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_encrypt_unmanaged).
    ///
    /// The IronCore service is still needed to transform a chosen EDEK so it can be decrypted by the
    /// caller's private key, so offline decryption is not possible.
    ///
    /// # Arguments
    /// - `encrypted_data` - Bytes of the encrypted document
    /// - `encrypted_deks` - EDEKs associated with the encrypted document
    fn document_decrypt(
        &self,
        encrypted_data: &[u8],
        encrypted_deks: &[u8],
    ) -> impl Future<Output = Result<DocumentDecryptUnmanagedResult>> + Send;

    /// Returns the metadata associated with an encrypted document.
    ///
    /// This metadata is extracted from the EDEKs bytes that were produced when the
    /// document was encrypted.
    fn document_get_metadata(
        &self,
        encrypted_deks: &[u8],
    ) -> impl Future<Output = Result<DocumentMetadataUnmanagedResult>> + Send;
 
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
    fn document_get_id_from_bytes(&self, encrypted_document: &[u8]) -> impl Future<Output = Result<DocumentId>> + Send;

    /// Returns the document ID from the EDEKs of an encrypted document.
    ///
    /// This is the same ID returned by `DocumentEncryptResult.id()`.
    ///
    /// # Arguments
    /// - `edeks` - The EDEK bytes associated with the encrypted document
    ///
    /// # Errors
    /// Fails if the provided bytes are not EDEKs.
    ///
    /// # Examples
    /// ```
    /// # fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # let edeks: Vec<u8> = vec![];
    /// // with `bytes` returned from `document_encrypt`
    /// let document_id = sdk.document_get_id_from_edeks(&edeks)?;
    /// # Ok(())
    /// # }
    /// ```
    fn document_get_id_from_edeks(&self, edeks: &[u8]) -> impl Future<Output = Result<DocumentId>> + Send;

    /// Grants decryption access to a document to additional provided users and/or groups after
    /// the document was encrypted.
    ///
    /// This operation will communicate with the IronCore server if the public key for any user
    /// or group is not cached.
    ///
    /// Returns lists of successful and failed grants.
    ///
    /// # Arguments
    /// - `edeks` - the EDEKs of the document whose access is being modified
    /// - `grant_list` - List of users and groups to grant access to
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
    /// # let edeks: Vec<u8> = vec![];
    /// # let users: Vec<UserId> = vec![];
    /// use ironoxide::document::UserOrGroup;
    /// // from a list of UserIds, `users`
    /// let users_or_groups: Vec<UserOrGroup> = users.iter().map(|user| user.into()).collect();
    /// let access_result = sdk.document_grant_access(&edeks, &users_or_groups).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn document_grant_access(
        &self,
        edeks: &[u8],
        grant_list: &[UserOrGroup],
    ) -> impl Future<Output = Result<DocumentAccessResult>> + Send;

    /// Revokes decryption access to a document for the provided users and/or groups.
    ///
    /// This operation can be done offline (without access to the IronCore service).
    ///
    /// # Arguments
    /// - `edeks` - the EDEKs of the document whose access is being modified
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
    /// # let edeks: Vec<u8> = vec![];
    /// # let users: Vec<UserId> = vec![];
    /// use ironoxide::document::UserOrGroup;
    /// // from a list of UserIds, `users`
    /// let users_or_groups: Vec<UserOrGroup> = users.iter().map(|user| user.into()).collect();
    /// let access_result = sdk.document_revoke_access(&edeks, &users_or_groups).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn document_revoke_access(
        &self,
        edeks: &[u8],
        revoke_list: &[UserOrGroup],
    ) -> impl Future<Output = Result<DocumentAccessResult>> + Send;
}

impl DocumentUnmanagedOps for crate::IronOxide {
    async fn document_encrypt(
        &self,
        data: Vec<u8>,
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptUnmanagedResult> {
        let (explicit_users, explicit_groups, grant_to_author, policy_grants) =
            match &encrypt_opts.grants {
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
            internal::document_api::encrypt_document_unmanaged(
                self.device.auth(),
                &self.recrypt,
                &self.user_master_pub_key,
                &self.rng,
                data,
                encrypt_opts.id.clone(),
                grant_to_author,
                &explicit_users,
                &explicit_groups,
                policy_grants,
                &self.policy_eval_cache,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentEncryptUnmanaged,
        )
        .await?
    }

    async fn document_decrypt(
        &self,
        encrypted_data: &[u8],
        encrypted_deks: &[u8],
    ) -> Result<DocumentDecryptUnmanagedResult> {
        add_optional_timeout(
            internal::document_api::decrypt_document_unmanaged(
                self.device.auth(),
                &self.recrypt,
                self.device().device_private_key(),
                encrypted_data,
                encrypted_deks,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentDecryptUnmanaged,
        )
        .await?
    }

    async fn document_get_metadata(
        &self,
        encrypted_deks: &[u8],
    ) -> Result<DocumentMetadataUnmanagedResult> {
    }

    async fn document_get_id_from_bytes(
        &self,
        encrypted_document: &[u8]
    ) -> Result<DocumentId> {
    }

    async fn document_get_id_from_edeks(
        &self,
        edeks: &[u8]
    ) -> Result<DocumentId> {
    }

    async fn document_grant_access(
        &self,
        edeks: &[u8],
        grant_list: &[UserOrGroup],
    ) -> Result<DocumentAccessResult> {
    }

    async fn document_revoke_access(
        &self,
        edeks: &[u8],
        revoke_list: &[UserOrGroup],
    ) -> Result<DocumentAccessResult> {
    }
}

