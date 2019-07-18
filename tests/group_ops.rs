use common::init_sdk;
use ironoxide::{group::*, prelude::*};
use std::convert::TryInto;
use uuid::Uuid;

mod common;

#[macro_use]
extern crate serde_json;

#[test]
fn group_create_no_member() {
    let sdk = init_sdk();

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(Uuid::new_v4().to_string().try_into().unwrap()),
        Some("test group name".try_into().unwrap()),
        false,
    ));

    assert!(group_result.is_ok())
}

#[test]
fn group_create_also_member() {
    let sdk = init_sdk();

    let group_result = sdk.group_create(&Default::default());

    assert!(group_result.is_ok())
}

#[test]
fn group_delete() {
    let sdk = init_sdk();

    let group_result = sdk.group_create(&Default::default());
    assert!(group_result.is_ok());

    let group_id = group_result.unwrap().id().clone();

    let group_delete_result = sdk.group_delete(&group_id);
    assert!(group_delete_result.is_ok());
    assert_eq!(group_id, group_delete_result.unwrap().clone());
}

#[test]
fn group_update_name() {
    let sdk = init_sdk();

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(Uuid::new_v4().to_string().try_into().unwrap()),
            Some("first name".try_into().unwrap()),
            false,
        ))
        .unwrap();

    assert_eq!(
        group_result.name().unwrap().name(),
        &"first name".to_string()
    );

    let updated_group = sdk
        .group_update_name(group_result.id(), Some(&"new name".try_into().unwrap()))
        .unwrap();

    assert_eq!(
        updated_group.name(),
        Some(&"new name".try_into().expect("this name is valid"))
    );

    let cleared_name = sdk.group_update_name(updated_group.id(), None).unwrap();

    assert!(cleared_name.name().is_none());
}

#[test]
fn group_add_member() {
    let sdk = init_sdk();
    let account_id = sdk.device().account_id().clone();

    let group_result = sdk.group_create(&GroupCreateOpts::new(None, None, false));
    assert!(group_result.is_ok());

    let group_id = group_result.unwrap().id().clone();
    //Call to add ourselves to the group, since we didn't add on create, this should succeed.
    let add_member_res = sdk.group_add_members(&group_id, &[account_id.clone()]);
    assert!(add_member_res.is_ok());
    let add_member_res_unwrap = add_member_res.unwrap();
    assert_eq!(add_member_res_unwrap.succeeded().len(), 1);
    assert_eq!(add_member_res_unwrap.failed().len(), 0);
    //The 2nd should have a failure for an account id that doesn't exist and for the one that was already added
    let fake_account_id = Uuid::new_v4().to_string().try_into().unwrap();
    let add_member_res_second =
        sdk.group_add_members(&group_id, &[account_id.clone(), fake_account_id]);
    let add_member_res_second_unwrap = add_member_res_second.unwrap();
    assert_eq!(add_member_res_second_unwrap.succeeded().len(), 0);
    assert_eq!(add_member_res_second_unwrap.failed().len(), 2);
}

#[test]
fn group_list() {
    let sdk = init_sdk();

    //create two groups
    let group_result = sdk.group_create(&Default::default());
    assert!(group_result.is_ok());
    let group_result2 = sdk.group_create(&Default::default());
    assert!(group_result2.is_ok());

    let list_result = sdk.group_list();
    assert!(list_result.is_ok());
    assert_eq!(2, list_result.unwrap().result().len())
}

#[test]
fn group_remove_member() {
    let sdk = init_sdk();
    let account_id = sdk.device().account_id().clone();

    let group_result = sdk.group_create(&Default::default());
    assert!(group_result.is_ok());
    let group_id = group_result.unwrap().id().clone();

    //Remove ourselves and another missing user from the group. Should result in one success and one failure
    let fake_account_id: UserId = Uuid::new_v4().to_string().try_into().unwrap();
    let remove_members_res = sdk
        .group_remove_members(&group_id, &[account_id.clone(), fake_account_id.clone()])
        .unwrap();

    assert_eq!(remove_members_res.succeeded().len(), 1);
    assert_eq!(&remove_members_res.succeeded()[0], &account_id);
    assert_eq!(remove_members_res.failed().len(), 1);
    assert_eq!(remove_members_res.failed()[0].user(), &fake_account_id);
}

#[test]
fn group_add_admin() {
    let sdk = init_sdk();

    let account_id = sdk.device().account_id().clone();
    let second_account_id = init_sdk().device().account_id().clone();

    let group_result = sdk.group_create(&GroupCreateOpts::default());
    assert!(group_result.is_ok());

    let group_id = group_result.unwrap().id().clone();
    //Call to add ourselves and a second id as admins. Adding ourselves should fail and the other should succeed.
    let add_member_res =
        sdk.group_add_admins(&group_id, &[account_id.clone(), second_account_id.clone()]);
    assert!(add_member_res.is_ok());
    let add_member_res_unwrap = add_member_res.unwrap();
    assert_eq!(add_member_res_unwrap.succeeded().len(), 1);
    assert_eq!(add_member_res_unwrap.succeeded()[0], second_account_id);
    assert_eq!(add_member_res_unwrap.failed().len(), 1);
    assert_eq!(add_member_res_unwrap.failed()[0].user(), &account_id);
}

#[test]
fn group_remove_admin() {
    let sdk = init_sdk();

    let second_account_id = init_sdk().device().account_id().clone();

    let group_result = sdk.group_create(&GroupCreateOpts::default());
    assert!(group_result.is_ok());

    let group_id = group_result.unwrap().id().clone();
    //Call to add the second id as an admin.
    let add_member_res = sdk.group_add_admins(&group_id, &[second_account_id.clone()]);
    assert!(add_member_res.is_ok());
    let add_member_res_unwrap = add_member_res.unwrap();
    assert_eq!(add_member_res_unwrap.succeeded().len(), 1);
    //Then remove them, which should succeed.
    let remove_member_res = sdk
        .group_remove_admins(&group_id, &[second_account_id.clone()])
        .unwrap();
    assert_eq!(remove_member_res.succeeded().len(), 1);
    assert_eq!(remove_member_res.succeeded()[0], second_account_id);
    assert_eq!(remove_member_res.failed().len(), 0);
}

#[test]
fn group_get_not_url_safe_id() {
    let sdk = init_sdk();

    let not_url_safe_id: GroupId = format!("{}{}", Uuid::new_v4(), "'=#.other|/$non@;safe'-:;id_")
        .try_into()
        .unwrap();
    let group_create_result = sdk.group_create(&GroupCreateOpts::new(
        Some(not_url_safe_id.clone()),
        None,
        false,
    ));

    assert!(group_create_result.is_ok());

    let get_result = sdk.group_get_metadata(&not_url_safe_id);
    assert!(get_result.is_ok());
    assert_eq!(&not_url_safe_id, group_create_result.unwrap().id())
}
