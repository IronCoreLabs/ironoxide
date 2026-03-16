mod common;

// Note: The blocking functions need minimal testing as they primarily just call their async counterparts

#[cfg(feature = "blocking")]
mod blocking_integration_tests {
    use crate::common::{USER_PASSWORD, create_id_all_classes, gen_jwt};
    use galvanic_assert::{matchers::*, *};
    use ironoxide::{Result, prelude::*};
    use std::{convert::TryInto, time::Duration};
    // Tests a UserOp (user_create/generate_new_device), a GroupOp (group_create),
    // and ironoxide::blocking functions (initialize/initialize_check_rotation)
    #[test]
    fn rotate_all() -> Result<()> {
        let account_id: UserId = create_id_all_classes("").try_into()?;
        let jwt = gen_jwt(Some(account_id.id())).0;
        BlockingIronOxide::user_create(&jwt, USER_PASSWORD, &UserCreateOpts::new(true), None)?;
        let device = BlockingIronOxide::generate_new_device(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &Default::default(),
            None,
        )?
        .into();
        let creator_sdk = ironoxide::blocking::initialize(&device, &Default::default())?;
        // making non-default groups so I can specify needs_rotation of true
        let group_create = creator_sdk.group_create(&GroupCreateOpts::new(
            None,
            None,
            true,
            true,
            None,
            vec![],
            vec![],
            true,
        ))?;
        assert_eq!(group_create.needs_rotation(), Some(true));

        let init_and_rotation_check =
            ironoxide::blocking::initialize_check_rotation(&device, &Default::default())?;
        let (user_result, group_result) = match init_and_rotation_check {
            InitAndRotationCheck::NoRotationNeeded(_) => {
                panic!("both user and groups should need rotation!");
            }
            InitAndRotationCheck::RotationNeeded(io, rot) => {
                io.rotate_all(&rot, USER_PASSWORD, None)?
            }
        };
        assert!(user_result.is_some());
        assert!(group_result.is_some());
        assert_eq!(group_result.unwrap().len(), 1);

        let user_result = BlockingIronOxide::user_verify(&jwt, None)?;
        assert!(!user_result.unwrap().needs_rotation());
        let group_get_result = creator_sdk.group_get_metadata(group_create.id())?;
        assert!(!group_get_result.needs_rotation().unwrap());

        Ok(())
    }

    // Tests a DocumentOp (document_encrypt) and a DocumentAdvancedOp (document_encrypt_unmanaged)
    #[test]
    fn document_encrypt() -> Result<()> {
        let account_id: UserId = create_id_all_classes("").try_into()?;
        BlockingIronOxide::user_create(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &UserCreateOpts::new(false),
            None,
        )?;
        let device = BlockingIronOxide::generate_new_device(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &Default::default(),
            None,
        )?
        .into();
        let sdk = ironoxide::blocking::initialize(&device, &Default::default())?;
        let doc = [0u8; 64];
        let doc_result = sdk.document_encrypt(doc.into(), &Default::default())?;
        assert_eq!(doc_result.grants().len(), 1);
        assert_eq!(doc_result.access_errs().len(), 0);

        let doc_unmanaged_result =
            sdk.document_encrypt_unmanaged(doc.into(), &Default::default())?;
        assert_eq!(doc_unmanaged_result.grants().len(), 1);
        assert_eq!(doc_unmanaged_result.access_errs().len(), 0);

        Ok(())
    }

    // Show that SDK operations timeout correctly using BlockingIronOxide
    #[test]
    fn initialize_with_timeout() -> Result<()> {
        let account_id: UserId = create_id_all_classes("").try_into()?;
        BlockingIronOxide::user_create(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &UserCreateOpts::new(false),
            None,
        )?;
        let device = BlockingIronOxide::generate_new_device(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &Default::default(),
            None,
        )?
        .into();

        // set an initialize timeout that is unreasonably small
        let duration = Duration::from_millis(5);
        let config = IronOxideConfig {
            sdk_operation_timeout: Some(duration),
            ..Default::default()
        };

        let result = ironoxide::blocking::initialize(&device, &config);
        let err_result = result.unwrap_err();

        assert_that!(&err_result, is_variant!(IronOxideErr::OperationTimedOut));
        assert_that!(
            &err_result,
            has_structure!(IronOxideErr::OperationTimedOut {
                operation: eq(SdkOperation::InitializeSdk),
                duration: eq(*duration)
            })
        );

        Ok(())
    }

    #[test]
    fn rotate_all_with_timeout() -> Result<()> {
        let account_id: UserId = create_id_all_classes("").try_into()?;
        BlockingIronOxide::user_create(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &UserCreateOpts::new(true),
            None,
        )?;
        let device = BlockingIronOxide::generate_new_device(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &Default::default(),
            None,
        )?
        .into();

        if let InitAndRotationCheck::RotationNeeded(bio, to_rotate) =
            ironoxide::blocking::initialize_check_rotation(&device, &Default::default())?
        {
            // set a rotate_all timeout that is unreasonably small
            let duration = Some(Duration::from_millis(5));
            let result = bio.rotate_all(&to_rotate, USER_PASSWORD, duration);

            let err_result = result.unwrap_err();

            assert_that!(&err_result, is_variant!(IronOxideErr::OperationTimedOut));
            assert_that!(
                &err_result,
                has_structure!(IronOxideErr::OperationTimedOut {
                    operation: eq(SdkOperation::RotateAll),
                    duration: eq(*duration)
                })
            );
            Ok(())
        } else {
            panic!("rotation should be required")
        }
    }

    // Tests DocumentFileOps (managed file encrypt/decrypt roundtrip)
    #[test]
    fn document_file_encrypt_decrypt_roundtrip() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let account_id: UserId = create_id_all_classes("").try_into()?;
        BlockingIronOxide::user_create(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &UserCreateOpts::new(false),
            None,
        )?;
        let device = BlockingIronOxide::generate_new_device(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &Default::default(),
            None,
        )?
        .into();
        let sdk = ironoxide::blocking::initialize(&device, &Default::default())?;

        // Create source file with test data
        let plaintext = b"Hello from blocking file operations test!";
        let mut source_file = NamedTempFile::new().expect("Failed to create temp file");
        source_file
            .write_all(plaintext)
            .expect("Failed to write test data");
        let source_path = source_file.path().to_str().unwrap();

        // Create destination paths
        let encrypted_file = NamedTempFile::new().expect("Failed to create temp file");
        let encrypted_path = encrypted_file.path().to_str().unwrap();
        let decrypted_file = NamedTempFile::new().expect("Failed to create temp file");
        let decrypted_path = decrypted_file.path().to_str().unwrap();

        // Encrypt file
        let encrypt_result =
            sdk.document_file_encrypt(source_path, encrypted_path, &Default::default())?;
        assert_eq!(encrypt_result.grants().len(), 1);
        assert_eq!(encrypt_result.access_errs().len(), 0);

        // Decrypt file
        let decrypt_result = sdk.document_file_decrypt(encrypted_path, decrypted_path)?;
        assert_eq!(decrypt_result.id(), encrypt_result.id());

        // Verify decrypted content matches original
        let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted");
        assert_eq!(decrypted_content, plaintext);

        Ok(())
    }

    // Tests DocumentFileAdvancedOps (unmanaged file encrypt/decrypt roundtrip)
    #[test]
    fn document_file_encrypt_decrypt_unmanaged_roundtrip() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let account_id: UserId = create_id_all_classes("").try_into()?;
        BlockingIronOxide::user_create(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &UserCreateOpts::new(false),
            None,
        )?;
        let device = BlockingIronOxide::generate_new_device(
            &gen_jwt(Some(account_id.id())).0,
            USER_PASSWORD,
            &Default::default(),
            None,
        )?
        .into();
        let sdk = ironoxide::blocking::initialize(&device, &Default::default())?;

        // Create source file with test data
        let plaintext = b"Hello from blocking unmanaged file operations test!";
        let mut source_file = NamedTempFile::new().expect("Failed to create temp file");
        source_file
            .write_all(plaintext)
            .expect("Failed to write test data");
        let source_path = source_file.path().to_str().unwrap();

        // Create destination paths
        let encrypted_file = NamedTempFile::new().expect("Failed to create temp file");
        let encrypted_path = encrypted_file.path().to_str().unwrap();
        let decrypted_file = NamedTempFile::new().expect("Failed to create temp file");
        let decrypted_path = decrypted_file.path().to_str().unwrap();

        // Encrypt file (unmanaged)
        let encrypt_result =
            sdk.document_file_encrypt_unmanaged(source_path, encrypted_path, &Default::default())?;
        assert_eq!(encrypt_result.grants().len(), 1);
        assert_eq!(encrypt_result.access_errs().len(), 0);
        assert!(!encrypt_result.encrypted_deks().is_empty());

        // Decrypt file (unmanaged)
        let decrypt_result = sdk.document_file_decrypt_unmanaged(
            encrypted_path,
            decrypted_path,
            encrypt_result.encrypted_deks(),
        )?;
        assert_eq!(decrypt_result.id(), encrypt_result.id());

        // Verify decrypted content matches original
        let decrypted_content = std::fs::read(decrypted_path).expect("Failed to read decrypted");
        assert_eq!(decrypted_content, plaintext);

        Ok(())
    }
}
