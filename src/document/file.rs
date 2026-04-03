pub use crate::internal::document_api::file_ops::{
    DocumentFileDecryptResult, DocumentFileDecryptUnmanagedResult, DocumentFileEncryptResult,
    DocumentFileEncryptUnmanagedResult,
};
use crate::{
    Result, SdkOperation,
    document::{DocumentEncryptOpts, partition_user_or_group},
    internal::{add_optional_timeout, document_api::file_ops},
};
use futures::Future;
use itertools::EitherOrBoth;

/// IronOxide File-Based Document Operations
///
/// These operations use streaming I/O with constant memory usage, making them suitable
/// for large files. The encrypted format is identical to [DocumentOps](../trait.DocumentOps.html),
/// ensuring full interoperability between file and memory-based operations.
pub trait DocumentFileOps {
    /// Encrypts a file from source path to destination path.
    ///
    /// Uses streaming I/O with constant memory. Output format is identical to
    /// [document_encrypt](../trait.DocumentOps.html#tymethod.document_encrypt) and can be decrypted with
    /// [document_decrypt](../trait.DocumentOps.html#tymethod.document_decrypt) provided enough memory.
    ///
    /// # Arguments
    /// - `source_path` - Path to the plaintext file to encrypt
    /// - `destination_path` - Path where the encrypted file will be written
    /// - `opts` - Encryption options
    ///
    /// # Examples
    /// ```no_run
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # use ironoxide::document::file::DocumentFileOps;
    /// # let sdk: IronOxide = unimplemented!();
    /// let opts = DocumentEncryptOpts::default();
    /// let result = sdk.document_file_encrypt("/path/to/plaintext", "/path/to/encrypted.iron", &opts).await?;
    /// # Ok(())
    /// # }
    /// ```
    fn document_file_encrypt(
        &self,
        source_path: &str,
        destination_path: &str,
        opts: &DocumentEncryptOpts,
    ) -> impl Future<Output = Result<DocumentFileEncryptResult>> + Send;

    /// Decrypts an encrypted file to destination path.
    ///
    /// Uses streaming I/O with constant memory. Can decrypt files created by either
    /// [document_file_encrypt](trait.DocumentFileOps.html#tymethod.document_file_encrypt)
    /// or [document_encrypt](../trait.DocumentOps.html#tymethod.document_encrypt).
    ///
    /// # Arguments
    /// - `source_path` - Path to the encrypted file
    /// - `destination_path` - Path where the decrypted file will be written
    ///
    /// # Examples
    /// ```no_run
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # use ironoxide::document::file::DocumentFileOps;
    /// # let sdk: IronOxide = unimplemented!();
    /// let result = sdk.document_file_decrypt("/path/to/encrypted.iron", "/path/to/decrypted.dat").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security
    /// During decryption, plaintext is written to the destination file before authentication completes. The file is
    /// created with restrictive permissions (0600 on Unix), exclusive share mode on Windows, and is automatically
    /// deleted if authentication fails. Permissions are relaxed only after successful verification.
    fn document_file_decrypt(
        &self,
        source_path: &str,
        destination_path: &str,
    ) -> impl Future<Output = Result<DocumentFileDecryptResult>> + Send;
}

/// IronOxide Unmanaged File-Based Document Operations
///
/// These unmanaged versions allow the API consumer to manage the encrypted document encryption keys (EDEKs) themselves,
/// enabling offline encryption when public keys are pre-cached.
pub trait DocumentFileAdvancedOps {
    /// Encrypts a file without storing metadata in the IronCore service.
    ///
    /// Uses streaming I/O with constant memory. The caller must store the returned
    /// EDEKs alongside the encrypted file for later decryption.
    ///
    /// # Arguments
    /// - `source_path` - Path to the plaintext file to encrypt
    /// - `destination_path` - Path where the encrypted file will be written
    /// - `opts` - Encryption options
    ///
    /// # Examples
    /// ```no_run
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # use ironoxide::document::file::DocumentFileAdvancedOps;
    /// # let sdk: IronOxide = unimplemented!();
    /// let opts = DocumentEncryptOpts::default();
    /// let result = sdk.document_file_encrypt_unmanaged("/path/to/plaintext.dat", "/path/to/encrypted.iron", &opts).await?;
    /// // Store encrypted_deks alongside the encrypted file
    /// let edeks = result.encrypted_deks();
    /// # Ok(())
    /// # }
    /// ```
    fn document_file_encrypt_unmanaged(
        &self,
        source_path: &str,
        destination_path: &str,
        opts: &DocumentEncryptOpts,
    ) -> impl Future<Output = Result<DocumentFileEncryptUnmanagedResult>> + Send;

    /// Decrypts an unmanaged encrypted file to destination path.
    ///
    /// Uses streaming I/O with constant memory. Requires the EDEKs that were
    /// returned when the file was encrypted.
    ///
    /// # Arguments
    /// - `source_path` - Path to the encrypted file
    /// - `destination_path` - Path where the decrypted file will be written
    /// - `encrypted_deks` - EDEKs associated with the encrypted file
    ///
    /// # Examples
    /// ```no_run
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # use ironoxide::document::file::DocumentFileAdvancedOps;
    /// # let sdk: IronOxide = unimplemented!();
    /// # let edeks: Vec<u8> = vec![];
    /// let result = sdk.document_file_decrypt_unmanaged("/path/to/encrypted.iron", "/path/to/decrypted.dat", &edeks).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Security
    /// During decryption, plaintext is written to the destination file before
    /// authentication completes. The file is created with restrictive permissions
    /// (0600 on Unix) and is automatically deleted if authentication fails.
    /// Permissions are relaxed to 0644 only after successful verification.
    fn document_file_decrypt_unmanaged(
        &self,
        source_path: &str,
        destination_path: &str,
        encrypted_deks: &[u8],
    ) -> impl Future<Output = Result<DocumentFileDecryptUnmanagedResult>> + Send;
}

impl DocumentFileOps for crate::IronOxide {
    async fn document_file_encrypt(
        &self,
        source_path: &str,
        destination_path: &str,
        opts: &DocumentEncryptOpts,
    ) -> Result<DocumentFileEncryptResult> {
        let encrypt_opts = opts.clone();

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
            file_ops::encrypt_file_to_path(
                self.device.auth(),
                &self.config,
                &self.recrypt,
                &self.user_master_pub_key,
                &self.rng,
                source_path,
                destination_path,
                encrypt_opts.id,
                encrypt_opts.name,
                grant_to_author,
                &explicit_users,
                &explicit_groups,
                policy_grants.as_ref(),
                &self.policy_eval_cache,
                &self.public_key_cache,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentEncrypt,
        )
        .await?
    }

    async fn document_file_decrypt(
        &self,
        source_path: &str,
        destination_path: &str,
    ) -> Result<DocumentFileDecryptResult> {
        add_optional_timeout(
            file_ops::decrypt_file_to_path(
                self.device.auth(),
                self.recrypt.clone(),
                self.device.device_private_key_internal(),
                source_path,
                destination_path,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentDecrypt,
        )
        .await?
    }
}

impl DocumentFileAdvancedOps for crate::IronOxide {
    async fn document_file_encrypt_unmanaged(
        &self,
        source_path: &str,
        destination_path: &str,
        opts: &DocumentEncryptOpts,
    ) -> Result<DocumentFileEncryptUnmanagedResult> {
        let encrypt_opts = opts.clone();

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
            file_ops::encrypt_file_unmanaged(
                self.device.auth(),
                &self.config,
                &self.recrypt,
                &self.user_master_pub_key,
                &self.rng,
                source_path,
                destination_path,
                encrypt_opts.id,
                grant_to_author,
                &explicit_users,
                &explicit_groups,
                policy_grants.as_ref(),
                &self.policy_eval_cache,
                &self.public_key_cache,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentEncryptUnmanaged,
        )
        .await?
    }

    async fn document_file_decrypt_unmanaged(
        &self,
        source_path: &str,
        destination_path: &str,
        encrypted_deks: &[u8],
    ) -> Result<DocumentFileDecryptUnmanagedResult> {
        add_optional_timeout(
            file_ops::decrypt_file_unmanaged(
                self.device.auth(),
                &self.recrypt,
                self.device.device_private_key_internal(),
                source_path,
                destination_path,
                encrypted_deks,
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::DocumentDecryptUnmanaged,
        )
        .await?
    }
}
