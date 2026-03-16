mod common;

use crate::common::{create_id_all_classes, create_second_user, init_sdk_get_user, initialize_sdk};
use galvanic_assert::{matchers::collection::contains_in_any_order, *};
use ironoxide::document::file::{DocumentFileAdvancedOps, DocumentFileOps};
use ironoxide::{Result, prelude::*};
use std::convert::TryInto;
use std::io::Write;
use tempfile::NamedTempFile;

// Helper to create a temp file with given content
fn create_temp_file_with_content(content: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(content).expect("Failed to write test data");
    file
}

// Helper to create an empty temp file for output
fn create_output_temp_file() -> NamedTempFile {
    NamedTempFile::new().expect("Failed to create temp file")
}

#[tokio::test]
async fn file_encrypt_decrypt_roundtrip() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let plaintext = b"Hello, World! This is a test of file encryption.";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let encrypt_result = sdk
        .document_file_encrypt(source_path, encrypted_path, &Default::default())
        .await?;

    assert_eq!(encrypt_result.grants().len(), 1);
    assert_eq!(encrypt_result.access_errs().len(), 0);

    let decrypt_result = sdk
        .document_file_decrypt(encrypted_path, decrypted_path)
        .await?;

    assert_eq!(decrypt_result.id(), encrypt_result.id());

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    Ok(())
}

#[tokio::test]
async fn file_encrypt_decrypt_unmanaged_roundtrip() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let plaintext = b"Unmanaged file encryption test data";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let encrypt_result = sdk
        .document_file_encrypt_unmanaged(source_path, encrypted_path, &Default::default())
        .await?;

    assert_eq!(encrypt_result.grants().len(), 1);
    assert_eq!(encrypt_result.access_errs().len(), 0);
    assert!(!encrypt_result.encrypted_deks().is_empty());

    let decrypt_result = sdk
        .document_file_decrypt_unmanaged(
            encrypted_path,
            decrypted_path,
            encrypt_result.encrypted_deks(),
        )
        .await?;

    assert_eq!(decrypt_result.id(), encrypt_result.id());

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    Ok(())
}

#[tokio::test]
async fn file_roundtrip_empty_data() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let plaintext: &[u8] = &[];
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let encrypt_result = sdk
        .document_file_encrypt(source_path, encrypted_path, &Default::default())
        .await?;

    let decrypt_result = sdk
        .document_file_decrypt(encrypted_path, decrypted_path)
        .await?;

    assert_eq!(decrypt_result.id(), encrypt_result.id());

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    Ok(())
}

#[tokio::test]
async fn file_roundtrip_large_data() -> Result<()> {
    let sdk = initialize_sdk().await?;

    // Create 1MB of random-ish data
    let plaintext: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let source_file = create_temp_file_with_content(&plaintext);
    let encrypted_file = create_output_temp_file();
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let encrypt_result = sdk
        .document_file_encrypt(source_path, encrypted_path, &Default::default())
        .await?;

    assert_eq!(encrypt_result.grants().len(), 1);

    let decrypt_result = sdk
        .document_file_decrypt(encrypted_path, decrypted_path)
        .await?;

    assert_eq!(decrypt_result.id(), encrypt_result.id());

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    Ok(())
}

#[tokio::test]
async fn file_roundtrip_large_data_unmanaged() -> Result<()> {
    let sdk = initialize_sdk().await?;

    // Create 2MB of random-ish data
    let plaintext: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 256) as u8).collect();
    let source_file = create_temp_file_with_content(&plaintext);
    let encrypted_file = create_output_temp_file();
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let encrypt_result = sdk
        .document_file_encrypt_unmanaged(source_path, encrypted_path, &Default::default())
        .await?;

    assert_eq!(encrypt_result.grants().len(), 1);

    let decrypt_result = sdk
        .document_file_decrypt_unmanaged(
            encrypted_path,
            decrypted_path,
            encrypt_result.encrypted_deks(),
        )
        .await?;

    assert_eq!(decrypt_result.id(), encrypt_result.id());

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    Ok(())
}

#[tokio::test]
async fn file_encrypt_with_explicit_grants() -> Result<()> {
    let sdk = initialize_sdk().await?;
    let second_user = create_second_user().await;

    let plaintext = b"File with explicit grants";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();

    let bad_user: UserId = "bad_user".try_into()?;
    let bad_group: GroupId = "bad_group".try_into()?;

    let opts = DocumentEncryptOpts::with_explicit_grants(
        None,
        Some("file with grants".try_into()?),
        true,
        vec![
            UserOrGroup::User {
                id: second_user.account_id().clone(),
            },
            UserOrGroup::User { id: bad_user },
            UserOrGroup::Group { id: bad_group },
        ],
    );

    let encrypt_result = sdk
        .document_file_encrypt(source_path, encrypted_path, &opts)
        .await?;

    // Should have 2 successful grants (self + second_user)
    assert_eq!(encrypt_result.grants().len(), 2);
    assert_that!(
        &encrypt_result
            .grants()
            .iter()
            .cloned()
            .collect::<Vec<UserOrGroup>>(),
        contains_in_any_order(vec![
            UserOrGroup::User {
                id: sdk.device().account_id().clone()
            },
            UserOrGroup::User {
                id: second_user.account_id().clone()
            },
        ])
    );
    // Should have 2 errors (bad_user + bad_group)
    assert_eq!(encrypt_result.access_errs().len(), 2);

    Ok(())
}

#[tokio::test]
async fn file_encrypt_with_explicit_grants_unmanaged() -> Result<()> {
    let sdk = initialize_sdk().await?;
    let second_user = create_second_user().await;

    let plaintext = b"Unmanaged file with explicit grants";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();

    let bad_user: UserId = "bad_user".try_into()?;
    let bad_group: GroupId = "bad_group".try_into()?;

    let opts = DocumentEncryptOpts::with_explicit_grants(
        None,
        None,
        true,
        vec![
            UserOrGroup::User {
                id: second_user.account_id().clone(),
            },
            UserOrGroup::User { id: bad_user },
            UserOrGroup::Group { id: bad_group },
        ],
    );

    let encrypt_result = sdk
        .document_file_encrypt_unmanaged(source_path, encrypted_path, &opts)
        .await?;

    // Should have 2 successful grants (self + second_user)
    assert_eq!(encrypt_result.grants().len(), 2);
    // Should have 2 errors (bad_user + bad_group)
    assert_eq!(encrypt_result.access_errs().len(), 2);

    Ok(())
}

#[tokio::test]
async fn file_encrypt_decrypt_with_document_id_and_name() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let plaintext = b"File with explicit ID and name";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let doc_id: DocumentId = create_id_all_classes("file_doc_").try_into()?;
    let doc_name: DocumentName = "Test File Document".try_into()?;

    let opts = DocumentEncryptOpts::with_explicit_grants(
        Some(doc_id.clone()),
        Some(doc_name.clone()),
        true,
        vec![],
    );

    let encrypt_result = sdk
        .document_file_encrypt(source_path, encrypted_path, &opts)
        .await?;

    assert_eq!(encrypt_result.id(), &doc_id);
    assert_eq!(encrypt_result.name(), Some(&doc_name));

    let decrypt_result = sdk
        .document_file_decrypt(encrypted_path, decrypted_path)
        .await?;

    assert_eq!(decrypt_result.id(), &doc_id);
    assert_eq!(decrypt_result.name(), Some(&doc_name));

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    Ok(())
}

#[tokio::test]
async fn file_encrypt_without_self_grant() -> Result<()> {
    let sdk = initialize_sdk().await?;
    let second_user = create_second_user().await;

    let plaintext = b"File without self grant";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let opts = DocumentEncryptOpts::with_explicit_grants(
        None,
        None,
        false, // grant_to_author = false
        vec![UserOrGroup::User {
            id: second_user.account_id().clone(),
        }],
    );

    let encrypt_result = sdk
        .document_file_encrypt(source_path, encrypted_path, &opts)
        .await?;

    // Only second_user should have access
    assert_eq!(encrypt_result.grants().len(), 1);
    assert_eq!(
        encrypt_result.grants()[0],
        UserOrGroup::User {
            id: second_user.account_id().clone()
        }
    );

    // SDK user should NOT be able to decrypt
    let decrypt_result = sdk
        .document_file_decrypt(encrypted_path, decrypted_path)
        .await;

    assert!(decrypt_result.is_err());

    Ok(())
}

#[tokio::test]
async fn file_encrypt_source_not_found() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let encrypted_file = create_output_temp_file();
    let encrypted_path = encrypted_file.path().to_str().unwrap();

    let result = sdk
        .document_file_encrypt(
            "/nonexistent/path/to/file.txt",
            encrypted_path,
            &Default::default(),
        )
        .await;

    assert!(result.is_err());
    assert_that!(&result.unwrap_err(), is_variant!(IronOxideErr::FileIOError));

    Ok(())
}

#[tokio::test]
async fn file_decrypt_source_not_found() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let decrypted_file = create_output_temp_file();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let result = sdk
        .document_file_decrypt("/nonexistent/path/to/encrypted.iron", decrypted_path)
        .await;

    assert!(result.is_err());
    assert_that!(&result.unwrap_err(), is_variant!(IronOxideErr::FileIOError));

    Ok(())
}

#[tokio::test]
async fn file_decrypt_invalid_encrypted_data() -> Result<()> {
    let sdk = initialize_sdk().await?;

    // Create a file with garbage data (not a valid encrypted document)
    let garbage_data = b"This is not encrypted data";
    let source_file = create_temp_file_with_content(garbage_data);
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let result = sdk.document_file_decrypt(source_path, decrypted_path).await;

    assert!(result.is_err());
    // Should fail to parse the document header
    assert_that!(
        &result.unwrap_err(),
        is_variant!(IronOxideErr::DocumentHeaderParseFailure)
    );

    Ok(())
}

#[tokio::test]
async fn file_encrypt_invalid_destination_path() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let plaintext = b"Test data for invalid destination";
    let source_file = create_temp_file_with_content(plaintext);
    let source_path = source_file.path().to_str().unwrap();

    // Try to write to a non-existent directory
    let result = sdk
        .document_file_encrypt(
            source_path,
            "/nonexistent/directory/output.iron",
            &Default::default(),
        )
        .await;

    assert!(result.is_err());
    assert_that!(&result.unwrap_err(), is_variant!(IronOxideErr::FileIOError));

    Ok(())
}

#[tokio::test]
async fn file_decrypt_invalid_destination_path() -> Result<()> {
    let sdk = initialize_sdk().await?;

    // First create a valid encrypted file
    let plaintext = b"Test data";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();

    sdk.document_file_encrypt(source_path, encrypted_path, &Default::default())
        .await?;

    // Try to decrypt to a non-existent directory
    let result = sdk
        .document_file_decrypt(encrypted_path, "/nonexistent/directory/output.txt")
        .await;

    assert!(result.is_err());
    assert_that!(&result.unwrap_err(), is_variant!(IronOxideErr::FileIOError));

    Ok(())
}

// Interoperability tests: file operations should produce output compatible with memory operations

#[tokio::test]
async fn interop_file_encrypt_memory_decrypt() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let plaintext = b"Test interoperability: file encrypt, memory decrypt";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();

    // Encrypt with file API
    let _encrypt_result = sdk
        .document_file_encrypt(source_path, encrypted_path, &Default::default())
        .await?;

    // Read encrypted file into memory
    let encrypted_bytes = std::fs::read(encrypted_path).expect("Failed to read encrypted file");

    // Decrypt with memory API
    let decrypt_result = sdk.document_decrypt(&encrypted_bytes).await?;

    assert_eq!(decrypt_result.decrypted_data(), plaintext);

    Ok(())
}

#[tokio::test]
async fn interop_memory_encrypt_file_decrypt() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let plaintext = b"Test interoperability: memory encrypt, file decrypt";

    // Encrypt with memory API
    let encrypt_result = sdk
        .document_encrypt(plaintext.to_vec(), &Default::default())
        .await?;

    // Write encrypted data to file
    let encrypted_file = create_output_temp_file();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    std::fs::write(encrypted_path, encrypt_result.encrypted_data())
        .expect("Failed to write encrypted file");

    let decrypted_file = create_output_temp_file();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    // Decrypt with file API
    let decrypt_result = sdk
        .document_file_decrypt(encrypted_path, decrypted_path)
        .await?;

    assert_eq!(decrypt_result.id(), encrypt_result.id());

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    Ok(())
}

#[tokio::test]
async fn interop_file_encrypt_unmanaged_memory_decrypt_unmanaged() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let plaintext = b"Unmanaged interop test: file encrypt, memory decrypt";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();

    // Encrypt with file API (unmanaged)
    let encrypt_result = sdk
        .document_file_encrypt_unmanaged(source_path, encrypted_path, &Default::default())
        .await?;

    // Read encrypted file into memory
    let encrypted_bytes = std::fs::read(encrypted_path).expect("Failed to read encrypted file");

    // Decrypt with memory API (unmanaged)
    let decrypt_result = sdk
        .document_decrypt_unmanaged(&encrypted_bytes, encrypt_result.encrypted_deks())
        .await?;

    assert_eq!(decrypt_result.decrypted_data(), plaintext);

    Ok(())
}

#[tokio::test]
async fn interop_memory_encrypt_unmanaged_file_decrypt_unmanaged() -> Result<()> {
    let sdk = initialize_sdk().await?;

    let plaintext = b"Unmanaged interop test: memory encrypt, file decrypt";

    // Encrypt with memory API (unmanaged)
    let encrypt_result = sdk
        .document_encrypt_unmanaged(plaintext.to_vec(), &Default::default())
        .await?;

    // Write encrypted data to file
    let encrypted_file = create_output_temp_file();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    std::fs::write(encrypted_path, encrypt_result.encrypted_data())
        .expect("Failed to write encrypted file");

    let decrypted_file = create_output_temp_file();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    // Decrypt with file API (unmanaged)
    let decrypt_result = sdk
        .document_file_decrypt_unmanaged(
            encrypted_path,
            decrypted_path,
            encrypt_result.encrypted_deks(),
        )
        .await?;

    assert_eq!(decrypt_result.id(), encrypt_result.id());

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    Ok(())
}

// Cross-user decryption tests

#[tokio::test]
async fn file_encrypt_decrypt_by_different_user() -> Result<()> {
    let (_user1, sdk1) = init_sdk_get_user().await;
    let (user2, sdk2) = init_sdk_get_user().await;

    let plaintext = b"File shared between users";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    // User1 encrypts to User2
    let opts = DocumentEncryptOpts::with_explicit_grants(
        None,
        None,
        false, // Don't grant to self
        vec![UserOrGroup::User { id: user2.clone() }],
    );

    let encrypt_result = sdk1
        .document_file_encrypt(source_path, encrypted_path, &opts)
        .await?;

    assert_eq!(encrypt_result.grants().len(), 1);
    assert_eq!(
        encrypt_result.grants()[0],
        UserOrGroup::User { id: user2.clone() }
    );

    // User2 decrypts
    let decrypt_result = sdk2
        .document_file_decrypt(encrypted_path, decrypted_path)
        .await?;

    assert_eq!(decrypt_result.id(), encrypt_result.id());

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    // User1 should NOT be able to decrypt (they didn't grant to self)
    let decrypted_file2 = create_output_temp_file();
    let decrypted_path2 = decrypted_file2.path().to_str().unwrap();

    let result = sdk1
        .document_file_decrypt(encrypted_path, decrypted_path2)
        .await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn file_encrypt_to_group() -> Result<()> {
    let (_, sdk) = init_sdk_get_user().await;

    // Create a group
    let group = sdk.group_create(&Default::default()).await?;

    let plaintext = b"File encrypted to group";
    let source_file = create_temp_file_with_content(plaintext);
    let encrypted_file = create_output_temp_file();
    let decrypted_file = create_output_temp_file();

    let source_path = source_file.path().to_str().unwrap();
    let encrypted_path = encrypted_file.path().to_str().unwrap();
    let decrypted_path = decrypted_file.path().to_str().unwrap();

    let opts = DocumentEncryptOpts::with_explicit_grants(
        None,
        None,
        false, // Don't grant to self directly
        vec![UserOrGroup::Group {
            id: group.id().clone(),
        }],
    );

    let encrypt_result = sdk
        .document_file_encrypt(source_path, encrypted_path, &opts)
        .await?;

    assert_eq!(encrypt_result.grants().len(), 1);
    assert_eq!(
        encrypt_result.grants()[0],
        UserOrGroup::Group {
            id: group.id().clone()
        }
    );

    // Should be able to decrypt via group membership
    let _decrypt_result = sdk
        .document_file_decrypt(encrypted_path, decrypted_path)
        .await?;

    let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, plaintext);

    Ok(())
}
