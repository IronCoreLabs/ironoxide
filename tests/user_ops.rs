mod common;
use common::gen_jwt;
use ironoxide::user::UserCreateOpts;
use ironoxide::{prelude::*, user::DeviceCreateOpts};
use std::convert::TryInto;
use std::default::Default;
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
    let account_id: UserId = Uuid::new_v4().to_string().try_into().unwrap();
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
fn user_private_key_rotation() -> Result<(), IronOxideErr>{_
    let (_, init_result) = common::init_sdk_get_init_result();

    //    // case 1: don't handle RotationNeeded
    //    let sdk: IronOxide = init_result.unwrap();
    //
    //    let (_, init_result) = common::init_sdk_get_init_result();
    //    // case 2: handle with a standard pattern match
    //    let sdk: IronOxide = match init_result {
    //        IronOxideInitResult::Ok(io) => io,
    //        IronOxideInitResult::RotationNeeded(with_rotation) => {
    //            let rotation_result = with_rotation.soft_rotate_curr_user("users_master_password")?;
    //            with_rotation.into_ironoxide()
    //        }
    //    };
    //
    //    let (_, init_result) = common::init_sdk_get_init_result();
    //    // case 3: use a convenience function for handling rotation
    //    let sdk: IronOxide = init_result.unwrap_or_handle_rotation(|with_rotation| {
    //        let rotation_result = with_rotation.soft_rotate_curr_user("users_master_password")?;
    //        Ok(with_rotation.into_ironoxide())
    //    })?;

    Ok(())
}

#[test]
fn user_create_with_needs_rotation() -> Result<(), IronOxideErr> {
    let account_id: UserId = Uuid::new_v4().to_string().try_into().unwrap();
    let result = IronOxide::user_create(
        &gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0,
        "foo",
        &UserCreateOpts::new(true),
    );
    assert!(result?.needs_rotation());
    Ok(())
}
