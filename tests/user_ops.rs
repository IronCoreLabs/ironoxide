mod common;
use common::{create_id_all_classes, gen_jwt};
use ironoxide::{
    prelude::*,
    user::{DeviceCreateOpts, UserCreateOpts},
};
use std::{convert::TryInto, default::Default};
use uuid::Uuid;

#[macro_use]
extern crate serde_json;

#[test]
fn user_verify_non_existing_user() {
    let result = IronOxide::user_verify(&gen_jwt(1012, "test-segment", 551, None).0);
    assert_eq!(true, result.is_ok(), "User verify call failed unexpectedly");
    let option_result = result.unwrap();
    assert_eq!(true, option_result.is_none());
}

#[test]
fn user_verify_existing_user() {
    let account_id: UserId = create_id_all_classes("").try_into().unwrap();
    IronOxide::user_create(
        &gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0,
        "foo",
        &Default::default(),
    )
    .unwrap();

    let result =
        IronOxide::user_verify(&gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0)
            .unwrap();
    assert_eq!(true, result.is_some());
    let verify_resp = result.unwrap();

    assert_eq!(&account_id, verify_resp.account_id());
    assert_eq!(2012, verify_resp.segment_id());
}

#[test]
fn user_verify_after_create_with_needs_rotation() -> Result<(), IronOxideErr> {
    let account_id: UserId = Uuid::new_v4().to_string().try_into().unwrap();
    IronOxide::user_create(
        &gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0,
        "foo",
        &UserCreateOpts::new(true),
    )?;

    let result =
        IronOxide::user_verify(&gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0)?;
    assert_eq!(true, result.is_some());
    let verify_resp = result.unwrap();

    Ok(assert!(verify_resp.needs_rotation()))
}
#[test]
fn user_create_good_with_devices() {
    let account_id: UserId = Uuid::new_v4().to_string().try_into().unwrap();
    let result = IronOxide::user_create(
        &gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0,
        "foo",
        &Default::default(),
    );
    assert!(result.is_ok());

    let device = IronOxide::generate_new_device(
        &gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0,
        "foo",
        &DeviceCreateOpts::new(Some("myDevice".try_into().unwrap())),
    );

    assert!(device.is_ok());

    let sdk = ironoxide::initialize(&device.unwrap()).unwrap();

    let device_list = sdk.user_list_devices().unwrap();

    assert_eq!(1, device_list.result().len());
    assert_eq!(
        &"myDevice".to_string(),
        device_list.result()[0].name().unwrap().name()
    );
}

#[test]
fn user_private_key_rotation() -> Result<(), IronOxideErr> {
    let io = common::init_sdk();

    let result1 = io.user_rotate_private_key(common::USER_PASSWORD)?;
    assert_eq!(result1.needs_rotation(), false);

    let result2 = io.user_rotate_private_key(common::USER_PASSWORD)?;
    assert_eq!(&result1.user_key_id(), &result2.user_key_id());
    assert_ne!(
        &result1.user_master_private_key(),
        &result2.user_master_private_key()
    );

    Ok(())
}

#[test]
fn sdk_init_with_private_key_rotation() -> Result<(), IronOxideErr> {
    use ironoxide::InitAndRotationCheck;

    let (_, init_result) = common::init_sdk_get_init_result(true);

    //    // case 1: don't handle RotationNeeded
    let sdk: IronOxide = init_result.unwrap();

    let (user_id, init_result) = common::init_sdk_get_init_result(true);
    // case 2: handle with a standard pattern match
    let sdk: IronOxide = match init_result {
        InitAndRotationCheck::NoRotationNeeded(io) => panic!("user should need rotation"),
        InitAndRotationCheck::RotationNeeded(io, rotation_check) => {
            // TODO should we have a rotate_all() function?
            assert_eq!(rotation_check.user_rotation_needed(), Some(user_id));
            let rotation_result = io.user_rotate_private_key(common::USER_PASSWORD)?;
            assert_eq!(rotation_result.needs_rotation(), false);
            io
        }
    };
    Ok(())
}

#[test]
fn user_create_with_needs_rotation() -> Result<(), IronOxideErr> {
    let account_id: UserId = Uuid::new_v4().to_string().try_into().unwrap();
    let result = IronOxide::user_create(
        &gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0,
        common::USER_PASSWORD,
        &UserCreateOpts::new(true),
    );
    assert!(result?.needs_rotation());
    Ok(())
}
