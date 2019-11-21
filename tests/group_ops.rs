use crate::common::create_second_user;
use common::{create_id_all_classes, init_sdk_get_user, initialize_sdk};
use ironoxide::{group::*, prelude::*};
use std::convert::TryInto;
use uuid::Uuid;

mod common;

#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate galvanic_assert;

#[test]
fn group_create_no_member() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        Some("test group name".try_into()?),
        true,
        false,
        None,
        vec![],
        vec![],
        true,
    ))?;

    assert_eq!(group_result.owner(), sdk.device().account_id());
    assert_eq!(group_result.needs_rotation(), Some(true));
    Ok(())
}

#[test]
fn group_create_with_defaults() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    let result = sdk.group_create(&Default::default());
    let group_result = result?;
    assert_eq!(group_result.needs_rotation(), Some(false));
    assert!(group_result.is_member());
    assert!(group_result.is_admin());
    assert_eq!(group_result.owner(), sdk.device().account_id());
    Ok(())
}

#[test]
fn group_get_metadata() -> Result<(), IronOxideErr> {
    let admin_sdk = initialize_sdk()?;
    let member_sdk = initialize_sdk()?;
    let nonmember_sdk = initialize_sdk()?;

    let member_id = member_sdk.device().account_id().clone();
    let group = admin_sdk.group_create(&Default::default());
    let group_id = &group?.id().clone();

    admin_sdk.group_add_members(&group_id, &[member_id])?;

    let admin_group_get = admin_sdk.group_get_metadata(group_id)?;
    let member_group_get = member_sdk.group_get_metadata(group_id)?;
    let nonmember_group_get = nonmember_sdk.group_get_metadata(group_id)?;

    assert_eq!(admin_group_get.needs_rotation(), Some(false));
    assert_eq!(member_group_get.needs_rotation(), None);
    assert_eq!(nonmember_group_get.needs_rotation(), None);

    assert_eq!(
        admin_group_get.owner(),
        Some(admin_sdk.device().account_id())
    );
    assert_eq!(
        member_group_get.owner(),
        Some(admin_sdk.device().account_id())
    );
    assert_eq!(nonmember_group_get.owner(), None);
    Ok(())
}

#[test]
fn group_delete() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        None,
        true,
        true,
        None,
        vec![],
        vec![],
        false,
    ))?;

    let group_id = group_result.id().clone();

    let group_delete_result = sdk.group_delete(&group_id)?;
    assert_eq!(group_id, group_delete_result.clone());
    Ok(())
}

#[test]
fn group_update_name() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        Some("first name".try_into()?),
        true,
        false,
        None,
        vec![],
        vec![],
        false,
    ))?;

    assert_eq!(
        group_result.name().unwrap().name(),
        &"first name".to_string()
    );

    let updated_group = sdk.group_update_name(group_result.id(), Some(&"new name".try_into()?))?;

    assert_eq!(
        updated_group.name(),
        Some(&"new name".try_into().expect("this name is valid"))
    );

    let cleared_name = sdk.group_update_name(updated_group.id(), None)?;

    assert!(cleared_name.name().is_none());
    Ok(())
}

#[test]
fn group_add_member() -> Result<(), IronOxideErr> {
    let (account_id, sdk) = init_sdk_get_user();

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        None,
        true,
        false,
        None,
        vec![],
        vec![],
        false,
    ))?;

    let group_id = group_result.id().clone();
    //Call to add ourselves to the group, since we didn't add on create, this should succeed.
    let add_member_res = sdk.group_add_members(&group_id, &[account_id.clone()])?;
    assert_eq!(add_member_res.succeeded().len(), 1);
    assert_eq!(add_member_res.failed().len(), 0);
    //The 2nd should have a failure for an account id that doesn't exist and for the one that was already added
    let fake_account_id = Uuid::new_v4().to_string().try_into()?;
    let add_member_res_second =
        sdk.group_add_members(&group_id, &[account_id.clone(), fake_account_id])?;
    assert_eq!(add_member_res_second.succeeded().len(), 0);
    assert_eq!(add_member_res_second.failed().len(), 2);
    Ok(())
}

#[test]
fn group_add_member_on_create() -> Result<(), IronOxideErr> {
    use std::{collections::HashSet, iter::FromIterator};
    let (account_id, sdk) = init_sdk_get_user();
    let second_account_id = initialize_sdk()?.device().account_id().clone();

    // Even though `add_as_member` is false, the UserId is in the `members` list,
    // so the caller becomes a member regardless
    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        None,
        true,
        false,
        None,
        vec![],
        vec![account_id.clone(), second_account_id.clone()],
        false,
    ))?;

    assert_eq!(group_result.owner(), sdk.device().account_id());

    // the order of the vector can be confusing with the add_as_member, so comparing the
    // sets can avoid issues with it
    let result_set: HashSet<&UserId> = HashSet::from_iter(group_result.members());
    let expected_vec = &vec![account_id, second_account_id];
    let expected_set: HashSet<&UserId> = HashSet::from_iter(expected_vec);
    assert_eq!(result_set, expected_set);
    Ok(())
}

#[test]
fn group_add_specific_owner() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;
    let second_account_id = initialize_sdk()?.device().account_id().clone();

    // because the owner is specified, GroupCreateOpts.standardize() adds them
    // to the admins list
    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        None,
        false,
        false,
        Some(second_account_id.clone()),
        vec![],
        vec![second_account_id.clone()],
        false,
    ))?;

    assert_eq!(group_result.owner(), &second_account_id);
    assert_eq!(group_result.members(), &vec![second_account_id.clone()]);
    assert_eq!(group_result.admins(), &vec![second_account_id]);

    Ok(())
}

#[test]
fn group_add_admin_on_create() -> Result<(), IronOxideErr> {
    use std::{collections::HashSet, iter::FromIterator};
    let (account_id, sdk) = init_sdk_get_user();
    let (second_account_id, _) = init_sdk_get_user();

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        None,
        true,
        false,
        None,
        vec![second_account_id.clone()],
        vec![],
        false,
    ))?;

    assert_eq!(group_result.owner(), &account_id);

    // the order of the vector can be confusing with the add_as_admin, so comparing the
    // sets can avoid issues with it
    let result_set: HashSet<&UserId> = HashSet::from_iter(group_result.admins());
    let expected_vec = &vec![account_id, second_account_id];
    let expected_set: HashSet<&UserId> = HashSet::from_iter(expected_vec);
    assert_eq!(result_set, expected_set);
    Ok(())
}

#[test]
fn group_add_admin_invalid_ids() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        None,
        true,
        false,
        Some(UserId::unsafe_from_string("likeafox".to_string())),
        vec![UserId::unsafe_from_string("whatsthenextwhat".to_string())],
        vec![UserId::unsafe_from_string("aretheseuserids".to_string())],
        false,
    ));

    assert_that!(
        &group_result.unwrap_err(),
        is_variant!(IronOxideErr::UserDoesNotExist)
    );

    Ok(())
}

#[test]
fn group_owner_not_an_admin() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        None,
        false,
        false,
        None,
        vec![UserId::unsafe_from_string("antelope".to_string())],
        vec![],
        false,
    ));

    assert_that!(
        &group_result.unwrap_err(),
        is_variant!(IronOxideErr::ValidationError)
    );

    Ok(())
}

#[test]
fn group_list() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    //create two groups
    sdk.group_create(&Default::default())?;
    sdk.group_create(&Default::default())?;

    let list_result = sdk.group_list()?;
    assert_eq!(2, list_result.result().len());
    Ok(())
}

#[test]
fn group_remove_member() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;
    let account_id = sdk.device().account_id().clone();

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        None,
        true,
        true,
        None,
        vec![],
        vec![],
        false,
    ))?;
    let group_id = group_result.id().clone();

    //Remove ourselves and another missing user from the group. Should result in one success and one failure
    let fake_account_id: UserId = Uuid::new_v4().to_string().try_into()?;
    let remove_members_res =
        sdk.group_remove_members(&group_id, &[account_id.clone(), fake_account_id.clone()])?;

    assert_eq!(remove_members_res.succeeded().len(), 1);
    assert_eq!(&remove_members_res.succeeded()[0], &account_id);
    assert_eq!(remove_members_res.failed().len(), 1);
    assert_eq!(remove_members_res.failed()[0].user(), &fake_account_id);
    Ok(())
}

#[test]
fn group_add_admin() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    let account_id = sdk.device().account_id().clone();
    let second_account_id = initialize_sdk()?.device().account_id().clone();

    let group_result = sdk.group_create(&GroupCreateOpts::new(
        Some(create_id_all_classes("").try_into()?),
        None,
        true,
        false,
        None,
        vec![],
        vec![],
        false,
    ))?;

    let group_id = group_result.id().clone();
    //Call to add ourselves and a second id as admins. Adding ourselves should fail and the other should succeed.
    let add_member_res =
        sdk.group_add_admins(&group_id, &[account_id.clone(), second_account_id.clone()])?;

    assert_eq!(add_member_res.succeeded().len(), 1);
    assert_eq!(add_member_res.succeeded()[0], second_account_id);
    assert_eq!(add_member_res.failed().len(), 1);
    assert_eq!(add_member_res.failed()[0].user(), &account_id);
    Ok(())
}

#[test]
fn group_remove_admin() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    let second_account_id = create_second_user().account_id().clone();

    let group_result = sdk.group_create(&GroupCreateOpts::default())?;

    let group_id = group_result.id().clone();
    //Call to add the second id as an admin.
    let add_member_res = sdk.group_add_admins(&group_id, &[second_account_id.clone()])?;
    assert_eq!(add_member_res.succeeded().len(), 1);
    //Then remove them, which should succeed.
    let remove_member_res = sdk.group_remove_admins(&group_id, &[second_account_id.clone()])?;
    assert_eq!(remove_member_res.succeeded().len(), 1);
    assert_eq!(remove_member_res.succeeded()[0], second_account_id);
    assert_eq!(remove_member_res.failed().len(), 0);
    Ok(())
}

#[test]
fn group_get_not_url_safe_id() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk()?;

    let not_url_safe_id: GroupId =
        format!("{}{}", Uuid::new_v4(), "'=#.other|/$non@;safe'-:;id_").try_into()?;
    let group_create_result = sdk.group_create(&GroupCreateOpts::new(
        Some(not_url_safe_id.clone()),
        None,
        true,
        false,
        None,
        vec![],
        vec![],
        false,
    ))?;

    let get_result = sdk.group_get_metadata(&not_url_safe_id)?;
    assert_eq!(&not_url_safe_id, group_create_result.id());
    assert_eq!(&not_url_safe_id, get_result.id());
    Ok(())
}
