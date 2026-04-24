mod common;

use common::{USER_PASSWORD, create_id_all_classes, gen_jwt, initialize_sdk};
use galvanic_assert::{matchers::*, *};
use ironoxide::Result;
use ironoxide::prelude::*;
use std::{convert::TryInto, default::Default};
use uuid::Uuid;

#[tokio::test]
async fn initialize_adds_current_user_public_key_to_cache() -> Result<()> {
    let account_id: UserId = create_id_all_classes("").try_into()?;
    IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &UserCreateOpts::new(false),
        None,
    )
    .await?;
    let device: DeviceContext = IronOxide::generate_new_device(
        &gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?
    .into();

    let sdk = ironoxide::initialize(&device, &Default::default()).await?;
    let exported_cache = sdk.export_public_key_cache()?;

    // re-initialize with the exported cache. This will fail if the current user's
    // public key is not in the cache (per create_with_public_key_cache validation).
    ironoxide::initialize_with_public_keys(&device, &Default::default(), exported_cache).await?;

    Ok(())
}
#[tokio::test]
async fn user_verify_non_existing_user() -> Result<()> {
    let option_result = IronOxide::user_verify(&gen_jwt(None).0, None).await?;
    assert!(option_result.is_none());
    Ok(())
}

#[tokio::test]
async fn user_verify_existing_user() -> Result<()> {
    let account_id: UserId = create_id_all_classes("").try_into()?;
    IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        "foo",
        &Default::default(),
        None,
    )
    .await?;

    let result = IronOxide::user_verify(&gen_jwt(Some(account_id.id())).0, None).await?;
    assert!(result.is_some());
    let verify_resp = result.unwrap();

    assert_eq!(&account_id, verify_resp.account_id());
    Ok(())
}

#[tokio::test]
async fn user_verify_after_create_with_needs_rotation() -> Result<()> {
    let account_id: UserId = Uuid::new_v4().to_string().try_into()?;
    IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        "foo",
        &UserCreateOpts::new(true),
        None,
    )
    .await?;

    let result = IronOxide::user_verify(&gen_jwt(Some(account_id.id())).0, None).await?;
    assert!(result.is_some());
    let verify_resp = result.unwrap();
    assert!(verify_resp.needs_rotation());
    Ok(())
}
#[tokio::test]
async fn user_create_good_with_devices() -> Result<()> {
    let account_id: UserId = Uuid::new_v4().to_string().try_into()?;
    IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        "foo",
        &Default::default(),
        None,
    )
    .await?;
    let device: DeviceContext = IronOxide::generate_new_device(
        &gen_jwt(Some(account_id.id())).0,
        "foo",
        &DeviceCreateOpts::new(Some("myDevice".try_into()?)),
        None,
    )
    .await?
    .into();
    let sdk = ironoxide::initialize(&device, &Default::default()).await?;
    let device_list = sdk.user_list_devices().await?;

    assert_eq!(1, device_list.result().len());
    assert_eq!(
        &"myDevice".to_string(),
        device_list.result()[0].name().unwrap().name()
    );
    Ok(())
}

#[tokio::test]
async fn user_private_key_rotation() -> Result<()> {
    let io = initialize_sdk().await?;

    let result1 = io.user_rotate_private_key(common::USER_PASSWORD).await?;
    assert!(!result1.needs_rotation());

    let result2 = io.user_rotate_private_key(common::USER_PASSWORD).await?;
    assert_ne!(
        &result1.user_master_private_key(),
        &result2.user_master_private_key()
    );

    Ok(())
}

#[tokio::test]
async fn user_change_password() -> Result<()> {
    let account_id: UserId = Uuid::new_v4().to_string().try_into()?;
    let first_password = "foo";
    let new_password = "bar";
    let initial_result = IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        first_password,
        &Default::default(),
        None,
    )
    .await?;
    let device: DeviceContext = IronOxide::generate_new_device(
        &gen_jwt(Some(account_id.id())).0,
        first_password,
        &Default::default(),
        None,
    )
    .await?
    .into();
    let sdk = ironoxide::initialize(&device, &Default::default()).await?;
    let change_passcode_result = sdk
        .user_change_password(first_password, new_password)
        .await?;

    assert_eq!(
        initial_result.user_public_key(),
        change_passcode_result.user_public_key()
    );

    //Make sure we can't add a device with the old password.
    assert!(
        IronOxide::generate_new_device(
            &gen_jwt(Some(account_id.id())).0,
            first_password,
            &Default::default(),
            None,
        )
        .await
        .is_err()
    );

    //Make sure we can add a new device with the new password
    IronOxide::generate_new_device(
        &gen_jwt(Some(account_id.id())).0,
        new_password,
        &Default::default(),
        None,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn sdk_init_with_private_key_rotation() -> Result<()> {
    use ironoxide::InitAndRotationCheck;

    let (user_id, init_result) = common::init_sdk_get_init_result(true).await;
    let _: IronOxide = match init_result {
        InitAndRotationCheck::NoRotationNeeded(_ironoxide) => panic!("user should need rotation"),
        InitAndRotationCheck::RotationNeeded(io, rotation_check) => {
            assert_eq!(rotation_check.user_rotation_needed(), Some(&user_id));
            let rotation_result = io.user_rotate_private_key(common::USER_PASSWORD).await?;
            assert!(!rotation_result.needs_rotation());
            io
        }
    };
    Ok(())
}

#[tokio::test]
async fn user_add_device_after_rotation() -> Result<()> {
    //create a user
    let (user, sdk) = common::init_sdk_get_user().await;
    let bytes = vec![42u8, 43u8];

    let encrypt_result = sdk
        .document_encrypt(
            bytes.clone(),
            &DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![]),
        )
        .await?;
    let encrypted_data = encrypt_result.encrypted_data();

    //rotate the private key
    let _rotation_result = sdk.user_rotate_private_key(common::USER_PASSWORD).await?;

    //add a new device
    let new_device = IronOxide::generate_new_device(
        &common::gen_jwt(Some(user.id())).0,
        common::USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?;

    assert_eq!(new_device.created(), new_device.last_updated());
    assert_eq!(new_device.name(), None);

    //reinitialize the sdk with the new device and decrypt some data
    let new_sdk = ironoxide::initialize(&new_device.into(), &Default::default()).await?;
    let decrypt_result = new_sdk.document_decrypt(encrypted_data).await?;
    let decrypted_data = decrypt_result.decrypted_data();

    assert_eq!(bytes, decrypted_data.to_vec());

    Ok(())
}

#[tokio::test]
async fn user_create_with_needs_rotation() -> Result<()> {
    let account_id: UserId = Uuid::new_v4().to_string().try_into()?;
    let result = IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        common::USER_PASSWORD,
        &UserCreateOpts::new(true),
        None,
    )
    .await;
    assert!(result?.needs_rotation());
    Ok(())
}
#[tokio::test]
async fn user_update_status_disable_then_enable() -> Result<()> {
    let account_id: UserId = create_id_all_classes("").try_into()?;
    IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?;
    // Disable the user using a JWT
    IronOxide::user_update_status(
        &gen_jwt(Some(account_id.id())).0,
        UserStatus::Disabled,
        None,
    )
    .await?;
    // Re-enable the user using a JWT
    IronOxide::user_update_status(&gen_jwt(Some(account_id.id())).0, UserStatus::Enabled, None)
        .await?;
    Ok(())
}

#[tokio::test]
async fn user_inoperable_after_disable() -> Result<()> {
    let account_id: UserId = create_id_all_classes("").try_into()?;
    IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?;
    let device = IronOxide::generate_new_device(
        &common::gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?
    .into();
    let sdk = ironoxide::initialize(&device, &Default::default()).await?;
    // Disable the user using a JWT
    IronOxide::user_update_status(
        &gen_jwt(Some(account_id.id())).0,
        UserStatus::Disabled,
        None,
    )
    .await?;

    // JWT operation still work after disabling
    IronOxide::user_verify(&common::gen_jwt(Some(account_id.id())).0, None).await?;

    // SDK operations don't work after disabling
    assert!(sdk.document_list().await.is_err());
    assert!(
        ironoxide::initialize(&device, &Default::default())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn user_disable_self_works() -> Result<()> {
    let account_id: UserId = create_id_all_classes("").try_into()?;
    IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?;

    let device: DeviceContext = IronOxide::generate_new_device(
        &gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?
    .into();

    let sdk = ironoxide::initialize(&device, &Default::default()).await?;

    let disable_result = sdk.user_disable_self().await?;
    assert_eq!(disable_result.id(), account_id.id());
    assert_eq!(disable_result.status(), UserStatus::Disabled);

    // SDK operations don't work after disabling
    assert!(sdk.document_list().await.is_err());
    assert!(
        ironoxide::initialize(&device, &Default::default())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn generate_device_with_timeout() -> Result<()> {
    let result = IronOxide::generate_new_device(
        &common::gen_jwt(None).0,
        "pass",
        &Default::default(),
        Some(std::time::Duration::from_millis(1)),
    )
    .await;

    assert!(result.is_err());
    let err_result = result.unwrap_err();
    dbg!(&err_result);
    assert_that!(&err_result, is_variant!(IronOxideErr::OperationTimedOut));
    assert_that!(
        &err_result,
        has_structure!(IronOxideErr::OperationTimedOut {
            operation: eq(SdkOperation::GenerateNewDevice),
            duration: eq(std::time::Duration::from_millis(1))
        })
    );
    Ok(())
}
