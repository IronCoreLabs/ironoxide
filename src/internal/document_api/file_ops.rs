//! File-based document encryption and decryption operations.
//!
//! This module provides streaming file encryption/decryption with constant memory usage.
//! The encrypted format is identical to the in-memory document encryption, ensuring
//! full interoperability between file and memory operations.

use crate::{
    PolicyCache, Result,
    config::IronOxideConfig,
    crypto::{aes::AES_KEY_LEN, streaming, transform},
    group::GroupId,
    internal::{
        IronOxideErr, PrivateKey, PublicKey, PublicKeyCache, RequestAuth,
        document_api::{
            self, DocAccessEditErr, DocumentHeader, DocumentId, DocumentName, UserOrGroup,
            parse_header_length, recrypt_document,
            requests::{self, document_create},
        },
    },
    policy::PolicyGrant,
    proto::transform::EncryptedDeks as EncryptedDeksP,
    user::UserId,
};
use protobuf::Message;
use rand::{CryptoRng, RngCore};
use recrypt::prelude::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    sync::Mutex,
};
use time::OffsetDateTime;

/// On Unix: mode 0600 (owner read/write only).
/// On Windows: share_mode(0) prevents other processes from accessing while open.
/// On anything else (wasm?): we don't have a clean method of restricting access during decryption.
fn create_output_file(path: &str) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| IronOxideErr::FileIoError {
                path: Some(path.to_string()),
                operation: "create".into(),
                message: e.to_string(),
            })
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .share_mode(0)
            .open(path)
            .map_err(|e| IronOxideErr::FileIoError {
                path: Some(path.to_string()),
                operation: "create".into(),
                message: e.to_string(),
            })
    }

    #[cfg(not(any(unix, windows)))]
    {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| IronOxideErr::FileIoError {
                path: Some(path.to_string()),
                operation: "create".into(),
                message: e.to_string(),
            })
    }
}

/// On Unix: changes mode from 0600 to 0644 (owner read/write, group/other read).
/// On other platforms: no-op (Windows share_mode releases automatically on close, there was nothing to remove on wasm).
fn reset_file_permissions(path: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, Permissions::from_mode(0o644)).map_err(|e| {
            IronOxideErr::FileIoError {
                path: Some(path.to_string()),
                operation: "set_permissions".into(),
                message: e.to_string(),
            }
        })
    }

    #[cfg(not(unix))]
    {
        // suppress unused warning
        let _ = path;
        Ok(())
    }
}

/// Used during decryption to ensure unauthenticated plaintext is cleaned up if verification fails or an error/panic
/// occurs before completion.
struct CleanupOnDrop {
    path: String,
    committed: bool,
}

impl CleanupOnDrop {
    fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            committed: false,
        }
    }

    /// Commit the file, which prevents deletion on drop. Should be done after verification.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for CleanupOnDrop {
    fn drop(&mut self) {
        if !self.committed {
            // _ is to intentionally ignore failure here, there's nothing we or the caller can do if we can't remove the
            // file (already removed, moved, permissions failure, etc).
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Open a source file and read/parse the IronCore document header.
/// Returns the parsed header and the file positioned after the header.
fn read_document_header(source_path: &str) -> Result<(DocumentHeader, File)> {
    let mut source_file = File::open(source_path).map_err(|e| IronOxideErr::FileIoError {
        path: Some(source_path.to_string()),
        operation: "open".into(),
        message: e.to_string(),
    })?;

    // Read first few bytes to determine header length
    let mut header_prefix = [0u8; 3];
    source_file
        .read_exact(&mut header_prefix)
        .map_err(|e| IronOxideErr::FileIoError {
            path: Some(source_path.to_string()),
            operation: "read_header".into(),
            message: e.to_string(),
        })?;

    let header_len = parse_header_length(&header_prefix)?;

    // Read full header from beginning
    source_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| IronOxideErr::FileIoError {
            path: Some(source_path.to_string()),
            operation: "seek".into(),
            message: e.to_string(),
        })?;

    let mut header_bytes = vec![0u8; header_len];
    source_file
        .read_exact(&mut header_bytes)
        .map_err(|e| IronOxideErr::FileIoError {
            path: Some(source_path.to_string()),
            operation: "read_header".into(),
            message: e.to_string(),
        })?;

    // Parse header JSON (skip 3-byte prefix)
    let doc_header: DocumentHeader =
        serde_json::from_slice(&header_bytes[3..header_len]).map_err(|_| {
            IronOxideErr::DocumentHeaderParseFailure(
                "Unable to parse document header. Header value is corrupted.".to_string(),
            )
        })?;

    Ok((doc_header, source_file))
}

/// Stream decrypt from source file to destination, handling cleanup on failure.
/// Creates output with restrictive permissions, streams decryption, verifies tag,
/// and resets permissions on success.
fn stream_decrypt_to_file(
    key_bytes: &[u8; AES_KEY_LEN],
    source_file: &File,
    destination_path: &str,
) -> Result<()> {
    let mut output_file = create_output_file(destination_path)?;
    let cleanup_guard = CleanupOnDrop::new(destination_path);

    let mut reader = BufReader::new(source_file);
    let mut writer = BufWriter::new(&mut output_file);

    streaming::decrypt_stream(key_bytes, &mut reader, &mut writer)?;

    writer.flush().map_err(|e| IronOxideErr::FileIoError {
        path: Some(destination_path.to_string()),
        operation: "flush".into(),
        message: e.to_string(),
    })?;

    // Verification succeeded - commit the file (prevents deletion on drop)
    cleanup_guard.commit();
    reset_file_permissions(destination_path)?;

    Ok(())
}

/// Result of file encryption (managed).
///
/// Produced by [document_file_encrypt](trait.DocumentFileOps.html#tymethod.document_file_encrypt).
#[derive(Clone, Debug)]
pub struct DocumentFileEncryptResult {
    id: DocumentId,
    name: Option<DocumentName>,
    created: OffsetDateTime,
    updated: OffsetDateTime,
    grants: Vec<UserOrGroup>,
    access_errs: Vec<DocAccessEditErr>,
}

impl DocumentFileEncryptResult {
    /// ID of the encrypted document
    pub fn id(&self) -> &DocumentId {
        &self.id
    }

    /// Name of the document
    pub fn name(&self) -> Option<&DocumentName> {
        self.name.as_ref()
    }

    /// Date and time when the document was created
    pub fn created(&self) -> &OffsetDateTime {
        &self.created
    }

    /// Date and time when the document was last updated
    pub fn last_updated(&self) -> &OffsetDateTime {
        &self.updated
    }
    /// Users and groups the document was successfully encrypted to
    pub fn grants(&self) -> &[UserOrGroup] {
        &self.grants
    }

    /// Errors resulting from failure to encrypt to specific users/groups
    pub fn access_errs(&self) -> &[DocAccessEditErr] {
        &self.access_errs
    }
}

/// Result of file encryption (unmanaged).
///
/// Produced by [document_file_encrypt_unmanaged](trait.DocumentFileUnmanagedOps.html#tymethod.document_file_encrypt_unmanaged).
#[derive(Clone, Debug)]
pub struct DocumentFileEncryptUnmanagedResult {
    id: DocumentId,
    encrypted_deks: Vec<u8>,
    grants: Vec<UserOrGroup>,
    access_errs: Vec<DocAccessEditErr>,
}

impl DocumentFileEncryptUnmanagedResult {
    /// ID of the encrypted document
    pub fn id(&self) -> &DocumentId {
        &self.id
    }

    /// Bytes of EDEKs of users/groups that have been granted access
    pub fn encrypted_deks(&self) -> &[u8] {
        &self.encrypted_deks
    }

    /// Users and groups the document was successfully encrypted to
    pub fn grants(&self) -> &[UserOrGroup] {
        &self.grants
    }

    /// Errors resulting from failure to encrypt to specific users/groups
    pub fn access_errs(&self) -> &[DocAccessEditErr] {
        &self.access_errs
    }
}

/// Result of file decryption (managed).
///
/// Produced by [document_file_decrypt](trait.DocumentFileOps.html#tymethod.document_file_decrypt).
#[derive(Clone, Debug)]
pub struct DocumentFileDecryptResult {
    id: DocumentId,
    name: Option<DocumentName>,
}

impl DocumentFileDecryptResult {
    /// ID of the decrypted document
    pub fn id(&self) -> &DocumentId {
        &self.id
    }

    /// Name of the document
    pub fn name(&self) -> Option<&DocumentName> {
        self.name.as_ref()
    }
}

/// Result of file decryption (unmanaged).
///
/// Produced by [document_file_decrypt_unmanaged](trait.DocumentFileUnmanagedOps.html#tymethod.document_file_decrypt_unmanaged).
#[derive(Clone, Debug)]
pub struct DocumentFileDecryptUnmanagedResult {
    id: DocumentId,
    access_via: UserOrGroup,
}

impl DocumentFileDecryptUnmanagedResult {
    /// ID of the decrypted document
    pub fn id(&self) -> &DocumentId {
        &self.id
    }

    /// User or group that granted access to the encrypted data
    pub fn access_via(&self) -> &UserOrGroup {
        &self.access_via
    }
}

/// Encrypt a file from source path to destination path.
/// Uses streaming I/O with constant memory. Output format is identical to `document_encrypt`.
pub async fn encrypt_file_to_path<R1, R2>(
    auth: &RequestAuth,
    config: &IronOxideConfig,
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<R1>>,
    user_master_pub_key: &PublicKey,
    rng: &Mutex<R2>,
    source_path: &str,
    destination_path: &str,
    document_id: Option<DocumentId>,
    document_name: Option<DocumentName>,
    grant_to_author: bool,
    user_grants: &[UserId],
    group_grants: &[GroupId],
    policy_grant: Option<&PolicyGrant>,
    policy_cache: &PolicyCache,
    public_key_cache: &PublicKeyCache,
) -> Result<DocumentFileEncryptResult>
where
    R1: CryptoRng + RngCore,
    R2: CryptoRng + RngCore,
{
    let source_file = File::open(source_path).map_err(|e| IronOxideErr::FileIoError {
        path: Some(source_path.to_string()),
        operation: "open".into(),
        message: e.to_string(),
    })?;
    let (dek, doc_sym_key) = transform::generate_new_doc_key(recrypt);
    let doc_id = document_id.unwrap_or_else(|| DocumentId::goo_id(rng));
    let (grants, key_errs) = document_api::resolve_keys_for_grants(
        auth,
        config,
        user_grants,
        group_grants,
        policy_grant,
        if grant_to_author {
            Some(user_master_pub_key)
        } else {
            None
        },
        policy_cache,
        public_key_cache,
    )
    .await?;
    let mut output_file = create_output_file(destination_path)?;

    // Write document header
    let header = DocumentHeader::new(doc_id.clone(), auth.segment_id);
    let header_bytes = header.pack();
    output_file
        .write_all(&header_bytes.0)
        .map_err(|e| IronOxideErr::FileIoError {
            path: Some(destination_path.to_string()),
            operation: "write_header".into(),
            message: e.to_string(),
        })?;

    let mut reader = BufReader::new(source_file);
    let mut writer = BufWriter::new(&mut output_file);

    // Stream encrypt the file content (writes IV + ciphertext + auth tag)
    let key_bytes = *doc_sym_key.bytes();
    streaming::encrypt_stream(&key_bytes, rng, &mut reader, &mut writer)?;
    reset_file_permissions(destination_path)?;

    // Encrypt DEK to all grantees
    let recryption_result =
        recrypt_document(&auth.signing_private_key, recrypt, dek, &doc_id, grants)?;

    // Create document on server
    let create_result = document_create::document_create_request(
        auth,
        doc_id,
        document_name,
        recryption_result.edeks,
    )
    .await?;

    Ok(DocumentFileEncryptResult {
        id: create_result.id,
        name: create_result.name,
        created: create_result.created,
        updated: create_result.updated,
        grants: create_result
            .shared_with
            .into_iter()
            .map(|sw| sw.into())
            .collect(),
        access_errs: [key_errs, recryption_result.encryption_errs].concat(),
    })
}

/// Decrypt an encrypted file to destination path.
///
/// Uses streaming I/O with constant memory.
pub async fn decrypt_file_to_path<CR>(
    auth: &RequestAuth,
    recrypt: std::sync::Arc<Recrypt<Sha256, Ed25519, RandomBytes<CR>>>,
    device_private_key: &PrivateKey,
    source_path: &str,
    destination_path: &str,
) -> Result<DocumentFileDecryptResult>
where
    CR: CryptoRng + RngCore + Send + Sync + 'static,
{
    let (doc_header, source_file) = read_document_header(source_path)?;

    // Get document metadata from server
    let doc_meta = document_api::document_get_metadata(auth, &doc_header.document_id).await?;

    // Decrypt the symmetric key
    let device_private_key = device_private_key.clone();
    let encrypted_symmetric_key = doc_meta.to_encrypted_symmetric_key()?;

    let sym_key = tokio::task::spawn_blocking(move || {
        transform::decrypt_as_symmetric_key(
            &recrypt,
            encrypted_symmetric_key,
            device_private_key.recrypt_key(),
        )
    })
    .await??;

    let key_bytes: [u8; AES_KEY_LEN] = *sym_key.bytes();
    stream_decrypt_to_file(&key_bytes, &source_file, destination_path)?;

    Ok(DocumentFileDecryptResult {
        id: doc_meta.id().clone(),
        name: doc_meta.name().cloned(),
    })
}

/// Encrypt a file (unmanaged) - EDEKs are returned to caller instead of stored on server.
pub async fn encrypt_file_unmanaged<R1, R2>(
    auth: &RequestAuth,
    config: &IronOxideConfig,
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<R1>>,
    user_master_pub_key: &PublicKey,
    rng: &Mutex<R2>,
    source_path: &str,
    destination_path: &str,
    document_id: Option<DocumentId>,
    grant_to_author: bool,
    user_grants: &[UserId],
    group_grants: &[GroupId],
    policy_grant: Option<&PolicyGrant>,
    policy_cache: &PolicyCache,
    public_key_cache: &PublicKeyCache,
) -> Result<DocumentFileEncryptUnmanagedResult>
where
    R1: CryptoRng + RngCore,
    R2: CryptoRng + RngCore,
{
    // Open source file
    let source_file = File::open(source_path).map_err(|e| IronOxideErr::FileIoError {
        path: Some(source_path.to_string()),
        operation: "open".into(),
        message: e.to_string(),
    })?;

    // Generate keys
    let (dek, doc_sym_key) = transform::generate_new_doc_key(recrypt);
    let doc_id = document_id.unwrap_or_else(|| DocumentId::goo_id(rng));

    // Resolve grants
    let (grants, key_errs) = document_api::resolve_keys_for_grants(
        auth,
        config,
        user_grants,
        group_grants,
        policy_grant,
        if grant_to_author {
            Some(user_master_pub_key)
        } else {
            None
        },
        policy_cache,
        public_key_cache,
    )
    .await?;

    // Create output file
    let mut output_file = create_output_file(destination_path)?;

    // Write document header
    let header = DocumentHeader::new(doc_id.clone(), auth.segment_id);
    let header_bytes = header.pack();
    output_file
        .write_all(&header_bytes.0)
        .map_err(|e| IronOxideErr::FileIoError {
            path: Some(destination_path.to_string()),
            operation: "write_header".into(),
            message: e.to_string(),
        })?;

    // Stream encrypt the file content (writes IV + ciphertext + auth tag)
    let mut reader = BufReader::new(source_file);
    let mut writer = BufWriter::new(&mut output_file);

    let key_bytes: [u8; AES_KEY_LEN] = *doc_sym_key.bytes();
    streaming::encrypt_stream(&key_bytes, rng, &mut reader, &mut writer)?;

    // Encrypt DEK to all grantees
    let r = recrypt_document(&auth.signing_private_key, recrypt, dek, &doc_id, grants)?;

    // Convert EDEKs to bytes
    let edek_bytes = document_api::edeks_to_bytes(&r.edeks, &doc_id, auth.segment_id)?;

    let successful_grants: Vec<UserOrGroup> =
        r.edeks.iter().map(|edek| edek.grant_to().clone()).collect();
    let all_errs: Vec<DocAccessEditErr> = key_errs
        .into_iter()
        .chain(r.encryption_errs.clone())
        .collect();

    // Reset file permissions to normal (0644 on Unix)
    reset_file_permissions(destination_path)?;

    Ok(DocumentFileEncryptUnmanagedResult {
        id: doc_id,
        encrypted_deks: edek_bytes,
        grants: successful_grants,
        access_errs: all_errs,
    })
}

/// Decrypt an encrypted file (unmanaged) - caller provides EDEKs.
pub async fn decrypt_file_unmanaged<CR>(
    auth: &RequestAuth,
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    device_private_key: &PrivateKey,
    source_path: &str,
    destination_path: &str,
    encrypted_deks: &[u8],
) -> Result<DocumentFileDecryptUnmanagedResult>
where
    CR: CryptoRng + RngCore,
{
    let (doc_header, source_file) = read_document_header(source_path)?;

    // Parse and verify EDEKs match document
    let proto_edeks =
        EncryptedDeksP::parse_from_bytes(encrypted_deks).map_err(IronOxideErr::from)?;
    document_api::edeks_and_header_match_or_err(&proto_edeks, &doc_header)?;

    // Transform EDEK
    let transform_resp = requests::edek_transform::edek_transform(auth, encrypted_deks).await?;
    let requests::edek_transform::EdekTransformResponse {
        user_or_group,
        encrypted_symmetric_key,
    } = transform_resp;

    // Decrypt the symmetric key
    let sym_key = transform::decrypt_as_symmetric_key(
        recrypt,
        encrypted_symmetric_key.try_into()?,
        device_private_key.recrypt_key(),
    )?;

    let key_bytes: [u8; AES_KEY_LEN] = *sym_key.bytes();
    stream_decrypt_to_file(&key_bytes, &source_file, destination_path)?;

    Ok(DocumentFileDecryptUnmanagedResult {
        id: doc_header.document_id,
        access_via: user_or_group,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn cleanup_on_drop_deletes_uncommitted_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path().to_str().unwrap().to_string();

        // Write some content so the file definitely exists
        fs::write(&path, b"test content").expect("Failed to write");
        assert!(fs::metadata(&path).is_ok(), "File should exist before drop");

        // Create guard and drop it without committing
        let guard = CleanupOnDrop::new(&path);
        drop(guard);

        // File should be deleted
        assert!(
            fs::metadata(&path).is_err(),
            "File should be deleted after drop without commit"
        );
    }

    #[test]
    fn cleanup_on_drop_preserves_committed_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path().to_str().unwrap().to_string();

        // Write some content
        fs::write(&path, b"test content").expect("Failed to write");
        assert!(fs::metadata(&path).is_ok(), "File should exist before drop");

        // Create guard, commit it, then drop
        let guard = CleanupOnDrop::new(&path);
        guard.commit();

        // File should still exist
        assert!(
            fs::metadata(&path).is_ok(),
            "File should exist after committed drop"
        );

        // Clean up manually since we committed
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cleanup_on_drop_handles_already_deleted_file() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path().to_str().unwrap().to_string();

        // Delete the file before the guard tries to clean up
        let _ = fs::remove_file(&path);

        // This should not panic even though file doesn't exist
        let guard = CleanupOnDrop::new(&path);
        drop(guard); // Should silently handle the missing file
    }

    #[cfg(unix)]
    mod unix_permissions {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn create_output_file_sets_restrictive_permissions() {
            let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
            let path = temp_dir.path().join("test_output.txt");
            let path_str = path.to_str().unwrap();

            let file = create_output_file(path_str).expect("Failed to create file");
            drop(file);

            let metadata = fs::metadata(path_str).expect("Failed to get metadata");
            let mode = metadata.permissions().mode() & 0o777;

            assert_eq!(
                mode, 0o600,
                "File should have mode 0600 (owner read/write only)"
            );

            // Clean up
            let _ = fs::remove_file(path_str);
        }

        #[test]
        fn reset_file_permissions_sets_normal_permissions() {
            let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
            let path = temp_dir.path().join("test_reset.txt");
            let path_str = path.to_str().unwrap();

            // Create file with restrictive permissions
            let file = create_output_file(path_str).expect("Failed to create file");
            drop(file);

            // Verify it starts with 0600
            let metadata = fs::metadata(path_str).expect("Failed to get metadata");
            let mode_before = metadata.permissions().mode() & 0o777;
            assert_eq!(mode_before, 0o600);

            // Reset permissions
            reset_file_permissions(path_str).expect("Failed to reset permissions");

            // Verify it's now 0644
            let metadata = fs::metadata(path_str).expect("Failed to get metadata");
            let mode_after = metadata.permissions().mode() & 0o777;
            assert_eq!(mode_after, 0o644, "File should have mode 0644 after reset");

            // Clean up
            let _ = fs::remove_file(path_str);
        }
    }

    #[cfg(windows)]
    mod windows_permissions {
        use super::*;

        #[test]
        fn create_output_file_has_exclusive_access_on_windows() {
            use std::io::Write;

            let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
            let path = temp_dir.path().join("test_output.txt");
            let path_str = path.to_str().unwrap();

            // On Windows, create_output_file uses share_mode(0) which prevents
            // other processes/handles from accessing while open
            let mut file = create_output_file(path_str).expect("Failed to create file");

            // Write something to the file
            file.write_all(b"test").expect("Failed to write");

            // While the file is still open, attempting to open it again should fail
            // due to share_mode(0) denying all sharing
            let open_attempt = fs::File::open(path_str);
            assert!(
                open_attempt.is_err(),
                "Opening file should fail while held with exclusive share_mode(0)"
            );

            // Drop the original handle
            drop(file);

            // Now opening should succeed
            let content = fs::read(path_str).expect("Failed to read file after handle released");
            assert_eq!(content, b"test");

            // Clean up
            let _ = fs::remove_file(path_str);
        }

        #[test]
        fn reset_file_permissions_is_noop_on_windows() {
            let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
            let path = temp_dir.path().join("test_reset.txt");
            let path_str = path.to_str().unwrap();

            // Create a file
            fs::write(path_str, b"test content").expect("Failed to write file");

            // reset_file_permissions should succeed (it's a no-op on Windows)
            reset_file_permissions(path_str).expect("reset_file_permissions should succeed");

            // File should still be readable
            let content = fs::read(path_str).expect("Failed to read file");
            assert_eq!(content, b"test content");

            // Clean up
            let _ = fs::remove_file(path_str);
        }
    }
}
