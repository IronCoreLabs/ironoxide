//! Advanced document API
//!
//! See [DocumentAdvancedOps](trait.DocumentAdvancedOps.html) for advanced document functions and key terms.

pub use crate::internal::document_api::{
    DocumentDecryptUnmanagedResult, DocumentEncryptUnmanagedResult,
};
use crate::{
    document::{partition_user_or_group, DocumentEncryptOpts},
    internal,
    internal::add_optional_timeout,
    Result, SdkOperation,
};
use async_trait::async_trait;
use itertools::EitherOrBoth;

/// IronOxide Advanced Document Operations
///
/// # Key Terms
/// - EDEKs - Encrypted document encryption keys produced by unmanaged document encryption and required for unmanaged
///      document decryption.
#[async_trait]
pub trait DocumentAdvancedOps {
    /// Encrypts the provided document bytes without being managed by the IronCore service.
    ///
    /// The webservice is still needed for looking up public keys and evaluating policies, but no
    /// document is created and the EDEKs are not stored. An additional burden is put on the caller
    /// in that both the encrypted data and the EDEKs must be provided for decryption.
    ///
    /// # Arguments
    /// - `data` - Bytes of the document to encrypt
    /// - `encrypt_opts` - Document encryption parameters. Default values are provided with
    ///      [DocumentEncryptOpts::default()](../struct.DocumentEncryptOpts.html#method.default).
    async fn document_encrypt_unmanaged(
        &self,
        data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptUnmanagedResult>;

    /// Decrypts a document not managed by the IronCore service.
    ///
    /// Requires the encrypted data and EDEKs returned from
    /// [document_encrypt_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_encrypt_unmanaged).
    ///
    /// The webservice is still needed to transform a chosen EDEK so it can be decrypted by the caller's private key.
    ///
    /// # Arguments
    /// - `encrypted_data` - Bytes of the encrypted document
    /// - `encrypted_deks` - EDEKs associated with the encrypted document
    async fn document_decrypt_unmanaged(
        &self,
        encrypted_data: &[u8],
        encrypted_deks: &[u8],
    ) -> Result<DocumentDecryptUnmanagedResult>;
}

#[async_trait]
impl DocumentAdvancedOps for crate::IronOxide {
    async fn document_encrypt_unmanaged(
        &self,
        data: &[u8],
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
                &self.client,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentEncryptUnmanaged,
        )
        .await?
    }

    async fn document_decrypt_unmanaged(
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
                &self.client,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentDecryptUnmanaged,
        )
        .await?
    }
}
