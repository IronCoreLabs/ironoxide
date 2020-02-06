mod common;

use common::{
    create_id_all_classes, create_second_user, gen_jwt, init_sdk_get_user, initialize_sdk,
    USER_PASSWORD,
};
use galvanic_assert::{assert_that, is_variant};
use ironoxide::{
    document::DocumentEncryptOpts,
    group::{GroupCreateOpts, GroupId, GroupOps},
    prelude::*,
};
use std::convert::TryInto;
use uuid::Uuid;

#[tokio::test]
async fn group_create_no_member() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            Some("test group name".try_into()?),
            true,
            false,
            None,
            vec![],
            vec![],
            true,
        ))
        .await?;

    assert_eq!(group_result.owner(), sdk.device().account_id());
    assert_eq!(group_result.needs_rotation(), Some(true));
    Ok(())
}

#[tokio::test]
async fn group_create_with_defaults() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let result = sdk.group_create(&Default::default()).await;
    let group_result = result?;
    assert_eq!(group_result.needs_rotation(), Some(false));
    assert!(group_result.is_member());
    assert!(group_result.is_admin());
    assert_eq!(group_result.owner(), sdk.device().account_id());
    Ok(())
}

#[tokio::test]
async fn group_init_and_rotation_check() -> Result<(), IronOxideErr> {
    use ironoxide::InitAndRotationCheck;
    let user: UserId = create_id_all_classes("").try_into()?;
    IronOxide::user_create(
        &gen_jwt(Some(user.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?;
    let device: DeviceContext = IronOxide::generate_new_device(
        &gen_jwt(Some(user.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?
    .into();
    let sdk = ironoxide::initialize(&device, &Default::default()).await?;
    sdk.group_create(&GroupCreateOpts::new(
        None,
        None,
        true,
        true,
        None,
        vec![],
        vec![],
        true,
    ))
    .await?;
    let init_and_rotation_check =
        ironoxide::initialize_check_rotation(&device, &Default::default()).await?;
    match init_and_rotation_check {
        InitAndRotationCheck::RotationNeeded(_, rotations_needed) => {
            assert!(rotations_needed.group_rotation_needed().is_some());
            assert!(rotations_needed.user_rotation_needed().is_none());
        }
        InitAndRotationCheck::NoRotationNeeded(_) => panic!("User group should need rotation"),
    };
    Ok(())
}

#[tokio::test]
async fn group_rotate_private_key() -> Result<(), IronOxideErr> {
    let creator_sdk = initialize_sdk().await?;
    let (member, member_sdk) = init_sdk_get_user().await;

    // making non-default group so I can specify needs_rotation of true
    let group_create = creator_sdk
        .group_create(&GroupCreateOpts::new(
            None,
            None,
            true,
            true,
            None,
            vec![],
            vec![],
            true,
        ))
        .await?;
    assert_eq!(group_create.needs_rotation(), Some(true));

    let bytes = vec![42u8, 43u8];

    let encrypt_result = creator_sdk
        .document_encrypt(
            &bytes,
            &DocumentEncryptOpts::with_explicit_grants(
                None,
                None,
                false,
                vec![group_create.id().into()],
            ),
        )
        .await?;
    let encrypted_data = encrypt_result.encrypted_data();

    let group_rotate = creator_sdk
        .group_rotate_private_key(group_create.id())
        .await?;
    assert_eq!(group_rotate.needs_rotation(), false);

    creator_sdk
        .group_add_members(group_create.id(), &vec![member])
        .await?;

    let creator_decrypt_result = creator_sdk.document_decrypt(encrypted_data).await?;
    let creator_decrypted_data = creator_decrypt_result.decrypted_data().to_vec();
    assert_eq!(creator_decrypted_data, bytes);

    let member_decrypt_result = member_sdk.document_decrypt(encrypted_data).await?;
    let member_decrypted_data = member_decrypt_result.decrypted_data().to_vec();
    assert_eq!(member_decrypted_data, bytes);

    Ok(())
}

#[tokio::test]
async fn group_rotate_private_key_non_admin() -> Result<(), IronOxideErr> {
    let creator_sdk = initialize_sdk().await?;
    let member_sdk = initialize_sdk().await?;

    // making non-default group so I can specify needs_rotation of true
    let group_create = creator_sdk
        .group_create(&GroupCreateOpts::new(
            None,
            None,
            true,
            true,
            None,
            vec![],
            vec![],
            true,
        ))
        .await?;

    let group_rotate = member_sdk.group_rotate_private_key(group_create.id()).await;
    assert_that!(
        &group_rotate.unwrap_err(),
        is_variant!(IronOxideErr::NotGroupAdmin)
    );

    Ok(())
}

#[tokio::test]
async fn rotate_all() -> Result<(), IronOxideErr> {
    use ironoxide::{user::UserCreateOpts, InitAndRotationCheck};
    let account_id: UserId = create_id_all_classes("").try_into()?;
    let jwt = gen_jwt(Some(account_id.id())).0;
    IronOxide::user_create(&jwt, USER_PASSWORD, &UserCreateOpts::new(true), None).await?;
    let device: DeviceContext = IronOxide::generate_new_device(
        &gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?
    .into();
    let creator_sdk = ironoxide::initialize(&device, &Default::default()).await?;
    // making non-default groups so I can specify needs_rotation of true
    let group_create1 = creator_sdk
        .group_create(&GroupCreateOpts::new(
            None,
            None,
            true,
            true,
            None,
            vec![],
            vec![],
            true,
        ))
        .await?;
    assert_eq!(group_create1.needs_rotation(), Some(true));
    let group_create2 = creator_sdk
        .group_create(&GroupCreateOpts::new(
            None,
            None,
            true,
            true,
            None,
            vec![],
            vec![],
            true,
        ))
        .await?;
    assert_eq!(group_create2.needs_rotation(), Some(true));

    let init_and_rotation_check =
        ironoxide::initialize_check_rotation(&device, &Default::default()).await?;
    let (user_result, group_result) = match init_and_rotation_check {
        InitAndRotationCheck::NoRotationNeeded(_) => {
            panic!("both user and groups should need rotation!");
        }
        InitAndRotationCheck::RotationNeeded(io, rot) => io.rotate_all(&rot, USER_PASSWORD).await?,
    };
    assert!(user_result.is_some());
    assert!(group_result.is_some());

    assert_eq!(group_result.unwrap().len(), 2);

    let user_result = IronOxide::user_verify(&jwt, None).await?;
    assert!(!user_result.unwrap().needs_rotation());

    let group1_result = creator_sdk.group_get_metadata(group_create1.id()).await?;
    let group2_result = creator_sdk.group_get_metadata(group_create2.id()).await?;

    assert!(!group1_result.needs_rotation().unwrap());
    assert!(!group2_result.needs_rotation().unwrap());

    Ok(())
}

#[tokio::test]
async fn group_get_metadata() -> Result<(), IronOxideErr> {
    let admin_sdk = initialize_sdk().await?;
    let member_sdk = initialize_sdk().await?;
    let nonmember_sdk = initialize_sdk().await?;

    let member_id = member_sdk.device().account_id().clone();
    let group = admin_sdk.group_create(&Default::default()).await;
    let group_id = &group?.id().clone();

    admin_sdk.group_add_members(&group_id, &[member_id]).await?;

    let admin_group_get = admin_sdk.group_get_metadata(group_id).await?;
    let member_group_get = member_sdk.group_get_metadata(group_id).await?;
    let nonmember_group_get = nonmember_sdk.group_get_metadata(group_id).await?;

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

#[tokio::test]
async fn group_delete() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            None,
            true,
            true,
            None,
            vec![],
            vec![],
            false,
        ))
        .await?;

    let group_id = group_result.id().clone();

    let group_delete_result = sdk.group_delete(&group_id).await?;
    assert_eq!(group_id, group_delete_result.clone());
    Ok(())
}

#[tokio::test]
async fn group_update_name() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            Some("first name".try_into()?),
            true,
            false,
            None,
            vec![],
            vec![],
            false,
        ))
        .await?;

    assert_eq!(
        group_result.name().unwrap().name(),
        &"first name".to_string()
    );

    let updated_group = sdk
        .group_update_name(group_result.id(), Some(&"new name".try_into()?))
        .await?;

    assert_eq!(
        updated_group.name(),
        Some(&"new name".try_into().expect("this name is valid"))
    );
    assert!(updated_group.last_updated() > updated_group.created());

    let cleared_name = sdk.group_update_name(updated_group.id(), None).await?;

    assert!(cleared_name.name().is_none());
    Ok(())
}

#[tokio::test]
async fn group_add_member() -> Result<(), IronOxideErr> {
    let (account_id, sdk) = init_sdk_get_user().await;

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            None,
            true,
            false,
            None,
            vec![],
            vec![],
            false,
        ))
        .await?;

    let group_id = group_result.id().clone();
    //Call to add ourselves to the group, since we didn't add on create, this should succeed.
    let add_member_res = sdk
        .group_add_members(&group_id, &[account_id.clone()])
        .await?;
    assert_eq!(add_member_res.succeeded().len(), 1);
    assert_eq!(add_member_res.failed().len(), 0);
    //The 2nd should have a failure for an account id that doesn't exist and for the one that was already added
    let fake_account_id = Uuid::new_v4().to_string().try_into()?;
    let add_member_res_second = sdk
        .group_add_members(&group_id, &[account_id.clone(), fake_account_id])
        .await?;
    assert_eq!(add_member_res_second.succeeded().len(), 0);
    assert_eq!(add_member_res_second.failed().len(), 2);
    Ok(())
}

#[tokio::test]
async fn group_add_member_on_create() -> Result<(), IronOxideErr> {
    use std::{collections::HashSet, iter::FromIterator};
    let (account_id, sdk) = init_sdk_get_user().await;
    let second_account_id = initialize_sdk().await?.device().account_id().clone();

    // Even though `add_as_member` is false, the UserId is in the `members` list,
    // so the caller becomes a member regardless
    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            None,
            true,
            false,
            None,
            vec![],
            vec![account_id.clone(), second_account_id.clone()],
            false,
        ))
        .await?;

    assert_eq!(group_result.owner(), sdk.device().account_id());

    // the order of the vector can be confusing with the add_as_member, so comparing the
    // sets can avoid issues with it
    let result_set: HashSet<&UserId> = HashSet::from_iter(group_result.members());
    let expected_vec = &vec![account_id, second_account_id];
    let expected_set: HashSet<&UserId> = HashSet::from_iter(expected_vec);
    assert_eq!(result_set, expected_set);
    Ok(())
}

#[tokio::test]
async fn group_add_specific_owner() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;
    let second_account_id = initialize_sdk().await?.device().account_id().clone();

    // because the owner is specified, GroupCreateOpts.standardize() adds them
    // to the admins list
    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            None,
            false,
            false,
            Some(second_account_id.clone()),
            vec![],
            vec![second_account_id.clone()],
            false,
        ))
        .await?;

    assert_eq!(group_result.owner(), &second_account_id);
    assert_eq!(group_result.members(), &vec![second_account_id.clone()]);
    assert_eq!(group_result.admins(), &vec![second_account_id]);

    Ok(())
}

#[tokio::test]
async fn group_add_admin_on_create() -> Result<(), IronOxideErr> {
    use std::{collections::HashSet, iter::FromIterator};
    let (account_id, sdk) = init_sdk_get_user().await;
    let (second_account_id, _) = init_sdk_get_user().await;

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            None,
            true,
            false,
            Some(account_id.clone()),
            vec![second_account_id.clone()],
            vec![],
            false,
        ))
        .await?;

    assert_eq!(group_result.owner(), &account_id);

    // the order of the vector can be confusing with the add_as_admin, so comparing the
    // sets can avoid issues with it
    let result_set: HashSet<&UserId> = HashSet::from_iter(group_result.admins());
    let expected_vec = &vec![account_id, second_account_id];
    let expected_set: HashSet<&UserId> = HashSet::from_iter(expected_vec);
    assert_eq!(result_set, expected_set);
    Ok(())
}

#[tokio::test]
async fn group_add_admin_invalid_ids() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            None,
            true,
            false,
            Some(UserId::unsafe_from_string("likeafox".to_string())),
            vec![UserId::unsafe_from_string("whatsthenextwhat".to_string())],
            vec![UserId::unsafe_from_string("aretheseuserids".to_string())],
            false,
        ))
        .await;

    assert_that!(
        &group_result.unwrap_err(),
        is_variant!(IronOxideErr::UserDoesNotExist)
    );

    Ok(())
}

#[tokio::test]
async fn group_owner_not_an_admin() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            None,
            false,
            false,
            None,
            vec![UserId::unsafe_from_string("antelope".to_string())],
            vec![],
            false,
        ))
        .await;

    assert_that!(
        &group_result.unwrap_err(),
        is_variant!(IronOxideErr::ValidationError)
    );

    Ok(())
}

#[tokio::test]
async fn group_list() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    //create two groups
    sdk.group_create(&Default::default()).await?;
    sdk.group_create(&Default::default()).await?;

    let list_result = sdk.group_list().await?;
    assert_eq!(2, list_result.result().len());
    Ok(())
}

#[tokio::test]
async fn group_remove_member() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;
    let account_id = sdk.device().account_id().clone();

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            None,
            true,
            true,
            None,
            vec![],
            vec![],
            false,
        ))
        .await?;
    let group_id = group_result.id().clone();

    //Remove ourselves and another missing user from the group. Should result in one success and one failure
    let fake_account_id: UserId = Uuid::new_v4().to_string().try_into()?;
    let remove_members_res = sdk
        .group_remove_members(&group_id, &[account_id.clone(), fake_account_id.clone()])
        .await?;

    assert_eq!(remove_members_res.succeeded().len(), 1);
    assert_eq!(&remove_members_res.succeeded()[0], &account_id);
    assert_eq!(remove_members_res.failed().len(), 1);
    assert_eq!(remove_members_res.failed()[0].user(), &fake_account_id);
    Ok(())
}

#[tokio::test]
async fn group_add_admin() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let account_id = sdk.device().account_id().clone();
    let second_account_id = initialize_sdk().await?.device().account_id().clone();

    let group_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(create_id_all_classes("").try_into()?),
            None,
            true,
            false,
            None,
            vec![],
            vec![],
            false,
        ))
        .await?;

    let group_id = group_result.id().clone();
    //Call to add ourselves and a second id as admins. Adding ourselves should fail and the other should succeed.
    let add_member_res = sdk
        .group_add_admins(&group_id, &[account_id.clone(), second_account_id.clone()])
        .await?;

    assert_eq!(add_member_res.succeeded().len(), 1);
    assert_eq!(add_member_res.succeeded()[0], second_account_id);
    assert_eq!(add_member_res.failed().len(), 1);
    assert_eq!(add_member_res.failed()[0].user(), &account_id);
    Ok(())
}

#[tokio::test]
async fn group_remove_admin() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let second_account_id = create_second_user().await.account_id().clone();

    let group_result = sdk.group_create(&GroupCreateOpts::default()).await?;

    let group_id = group_result.id().clone();
    //Call to add the second id as an admin.
    let add_member_res = sdk
        .group_add_admins(&group_id, &[second_account_id.clone()])
        .await?;
    assert_eq!(add_member_res.succeeded().len(), 1);
    //Then remove them, which should succeed.
    let remove_member_res = sdk
        .group_remove_admins(&group_id, &[second_account_id.clone()])
        .await?;
    assert_eq!(remove_member_res.succeeded().len(), 1);
    assert_eq!(remove_member_res.succeeded()[0], second_account_id);
    assert_eq!(remove_member_res.failed().len(), 0);
    Ok(())
}

#[tokio::test]
async fn group_get_not_url_safe_id() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let not_url_safe_id: GroupId =
        format!("{}{}", Uuid::new_v4(), "'=#.other|/$non@;safe'-:;id_").try_into()?;
    let group_create_result = sdk
        .group_create(&GroupCreateOpts::new(
            Some(not_url_safe_id.clone()),
            None,
            true,
            false,
            None,
            vec![],
            vec![],
            false,
        ))
        .await?;

    let get_result = sdk.group_get_metadata(&not_url_safe_id).await?;
    assert_eq!(&not_url_safe_id, group_create_result.id());
    assert_eq!(&not_url_safe_id, get_result.id());
    Ok(())
}
