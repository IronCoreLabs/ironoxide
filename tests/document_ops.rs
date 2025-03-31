mod common;

use crate::common::init_sdk_with_config;
use common::{create_id_all_classes, create_second_user, init_sdk_get_user, initialize_sdk};
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use galvanic_assert::{
    matchers::{collection::contains_in_any_order, eq},
    *,
};
use ironoxide::prelude::*;
use itertools::{EitherOrBoth, Itertools};
use std::{
    convert::{TryFrom, TryInto},
    thread::sleep,
    time::{Duration, Instant},
};

#[tokio::test]
async fn doc_list() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;
    let (other_user, _) = init_sdk_get_user().await;
    let doc = "secret".to_string().into_bytes();
    // grant_to_author is false, so doc should not come back in document list
    let opts =
        DocumentEncryptOpts::with_explicit_grants(None, None, false, vec![(&other_user).into()]);
    sdk.document_encrypt(doc.clone(), &opts).await?;
    let document_list_one = sdk.document_list().await?;
    assert_eq!(document_list_one.result().len(), 0);
    //Create another doc, grant to author true.
    let opts2 =
        DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![(&other_user).into()]);
    sdk.document_encrypt(doc, &opts2).await?;
    let document_list_two = sdk.document_list().await?;
    assert_eq!(document_list_two.result().len(), 1);
    Ok(())
}

#[tokio::test]
async fn doc_roundtrip_empty_data() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;
    let doc = [0u8; 0];

    let doc_result = sdk
        .document_encrypt(doc.into(), &Default::default())
        .await?;
    let decrypted_result = sdk.document_decrypt(doc_result.encrypted_data()).await?;

    Ok(assert_eq!(&doc, decrypted_result.decrypted_data()))
}

#[tokio::test]
async fn doc_create_without_id() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let doc = [0u8; 64];

    let doc_result = sdk
        .document_encrypt(doc.into(), &Default::default())
        .await?;

    assert_eq!(doc_result.grants().len(), 1); // access always granted to creator
    assert_eq!(doc_result.access_errs().len(), 0);
    Ok(())
}

#[tokio::test]
async fn doc_create_with_policy_grants() -> Result<(), IronOxideErr> {
    // policy assumed for this test
    /*
    {
      "dataSubjects": [
        "PATIENT"
      ],
      "sensitivities": [
        "RESTRICTED",
        "INTERNAL"
      ],
      "categories": [
        "HEALTH",
        "PII"
      ],
      "rules": [
        {
          "sensitivity": "RESTRICTED",
          "users": [
            "%USER%"
          ],
          "dataSubject": "PATIENT",
          "groups": [
            "group_other_%USER%",
            "group_id_doctors",
            "data_recovery_%LOGGED_IN_USER%"
          ],
          "category": "HEALTH"
        },
        {
          "sensitivity": "INTERNAL",
          "users": [
            "baduserid_frompolicy",
            "%LOGGED_IN_USER%"
          ],
          "groups": [
            "badgroupid_frompolicy",
            "data_recovery_%LOGGED_IN_USER%"
          ],
          "category": "PII"
        },
        {
          "users": [],
          "groups": [
            "data_recovery_%LOGGED_IN_USER%"
          ]
        }
      ]
    }
        */
    let (curr_user, sdk) = init_sdk_get_user().await;

    //create the data_recovery group used in the policy
    let data_rec_group_id: GroupId = format!("data_recovery_{}", curr_user.id()).try_into()?;
    sdk.group_create(&GroupCreateOpts::new(
        data_rec_group_id.clone().into(),
        None,
        true,
        true,
        None,
        vec![],
        vec![],
        false,
    ))
    .await?;

    let doc = [0u8; 64];

    // all of the policy grant fields are optional
    let doc_result = sdk
        .document_encrypt(
            doc.into(),
            &DocumentEncryptOpts::with_policy_grants(
                None,
                Some("doc name".try_into()?),
                PolicyGrant::new(
                    Some("PII".try_into()?),
                    Some("INTERNAL".try_into()?),
                    None,
                    None,
                ),
            ),
        )
        .await?;

    assert_eq!(doc_result.grants().len(), 2);
    assert_that!(
        &doc_result
            .grants()
            .iter()
            .map(Clone::clone)
            .collect::<Vec<UserOrGroup>>(),
        contains_in_any_order(vec![
            UserOrGroup::User {
                id: sdk.device().account_id().clone()
            },
            UserOrGroup::Group {
                id: data_rec_group_id.clone()
            }
        ])
    );
    assert_eq!(doc_result.access_errs().len(), 2);
    assert_that!(
        &doc_result
            .access_errs()
            .iter()
            .map(|err| err.user_or_group.clone())
            .collect::<Vec<_>>(),
        contains_in_any_order(vec![
            UserOrGroup::Group {
                id: "badgroupid_frompolicy".try_into()?
            },
            UserOrGroup::User {
                id: "baduserid_frompolicy".try_into()?
            }
        ])
    );

    // now use category, sensitivity, data_subject and substitution_user_id
    let user2_result = create_second_user().await;
    let user2 = user2_result.account_id();
    let group2_id: GroupId = format!("group_other_{}", user2.id()).try_into()?;
    sdk.group_create(&GroupCreateOpts::new(
        group2_id.clone().into(),
        None,
        true,
        false,
        None,
        vec![],
        vec![],
        false,
    ))
    .await?;

    let doc_result2 = sdk
        .document_encrypt(
            doc.into(),
            &DocumentEncryptOpts::with_policy_grants(
                None,
                Some("doc name2".try_into()?),
                PolicyGrant::new(
                    Some("HEALTH".try_into()?),
                    Some("RESTRICTED".try_into()?),
                    Some("PATIENT".try_into()?),
                    Some(user2.clone()),
                ),
            ),
        )
        .await?;

    assert_eq!(doc_result2.grants().len(), 3);
    assert_that!(
        &doc_result2
            .grants()
            .iter()
            .map(Clone::clone)
            .collect::<Vec<UserOrGroup>>(),
        contains_in_any_order(vec![
            UserOrGroup::User { id: user2.clone() },
            UserOrGroup::Group { id: group2_id },
            UserOrGroup::Group {
                id: data_rec_group_id.clone()
            }
        ])
    );
    assert_eq!(doc_result2.access_errs().len(), 1);
    assert_that!(
        &doc_result2
            .access_errs()
            .iter()
            .map(|err| err.user_or_group.clone())
            .collect::<Vec<_>>(),
        contains_in_any_order(vec![UserOrGroup::Group {
            id: "group_id_doctors".try_into()?
        },])
    );

    //finally send an empty policy. This will evaluate cleanly and will thus be cached.
    let doc_result3 = sdk
        .document_encrypt(
            doc.into(),
            &DocumentEncryptOpts::with_policy_grants(
                None,
                Some("doc name2".try_into()?),
                PolicyGrant::default(),
            ),
        )
        .await?;
    assert_eq!(doc_result3.grants().len(), 1);
    assert_eq!(sdk.clear_policy_cache(), 1);

    Ok(())
}

fn setup_encrypt_with_explicit_self_grant() -> DocumentEncryptOpts {
    let bad_user: UserId = "bad_user".try_into().unwrap();
    let bad_group: GroupId = "bad_group".try_into().unwrap();

    DocumentEncryptOpts::with_explicit_grants(
        None,
        Some("first name".try_into().unwrap()),
        true,
        vec![
            UserOrGroup::User { id: bad_user },
            UserOrGroup::Group { id: bad_group },
        ],
    )
}

fn check_encrypt_with_explicit_self_grant(sdk: &IronOxide, doc_result: Box<dyn WithGrantsAndErrs>) {
    let bad_user: UserId = "bad_user".try_into().unwrap();
    let bad_group: GroupId = "bad_group".try_into().unwrap();

    assert_eq!(doc_result.grants().len(), 1);
    assert_eq!(
        doc_result.grants()[0],
        UserOrGroup::User {
            id: sdk.device().account_id().clone()
        }
    );
    assert_eq!(doc_result.access_errs().len(), 2);
    assert_that!(
        &doc_result
            .access_errs()
            .iter()
            .map(|err| err.user_or_group.clone())
            .collect::<Vec<_>>(),
        contains_in_any_order(vec![
            UserOrGroup::User { id: bad_user },
            UserOrGroup::Group { id: bad_group }
        ])
    )
}

#[tokio::test]
async fn doc_create_with_explicit_self_grant() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;
    let encrypt_opts = setup_encrypt_with_explicit_self_grant();
    let doc = [0u8; 64];
    let doc_result = sdk.document_encrypt(doc.into(), &encrypt_opts).await?;

    check_encrypt_with_explicit_self_grant(&sdk, Box::new(doc_result));
    Ok(())
}

#[tokio::test]
async fn doc_encrypt_unmanaged_with_explicit_self_grant() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;
    let encrypt_opts = setup_encrypt_with_explicit_self_grant();
    let doc = [0u8; 64];
    let doc_result = sdk
        .document_encrypt_unmanaged(doc.into(), &encrypt_opts)
        .await?;

    check_encrypt_with_explicit_self_grant(&sdk, Box::new(doc_result));
    Ok(())
}

fn check_encrypt_with_explicit_and_policy_grants(
    curr_user: &UserId,
    ex_group_id: &GroupId,
    data_rec_group_id: &GroupId,
    bad_group_id: &GroupId,
    doc_result: Box<dyn WithGrantsAndErrs>,
) {
    assert_eq!(doc_result.grants().len(), 3);
    assert_that!(
        &doc_result
            .grants()
            .iter()
            .map(Clone::clone)
            .collect::<Vec<UserOrGroup>>(),
        contains_in_any_order(vec![
            UserOrGroup::User {
                id: curr_user.clone()
            },
            UserOrGroup::Group {
                id: data_rec_group_id.clone()
            },
            UserOrGroup::Group {
                id: ex_group_id.clone()
            }
        ])
    );
    assert_eq!(doc_result.access_errs().len(), 3);
    assert_that!(
        &doc_result
            .access_errs()
            .iter()
            .map(|err| err.user_or_group.clone())
            .collect::<Vec<_>>(),
        contains_in_any_order(vec![
            UserOrGroup::Group {
                id: "badgroupid_frompolicy".try_into().unwrap()
            },
            UserOrGroup::User {
                id: "baduserid_frompolicy".try_into().unwrap()
            },
            UserOrGroup::Group {
                id: bad_group_id.clone()
            } // bad explicit group
        ])
    );
}

async fn setup_encrypt_with_explicit_and_policy_grants(
    sdk: &IronOxide,
    curr_user: &UserId,
    bad_group: &GroupId,
) -> Result<(DocumentEncryptOpts, GroupId, GroupId), IronOxideErr> {
    //create the data_recovery group used in the policy
    let data_rec_group_id: GroupId = format!("data_recovery_{}", curr_user.id()).try_into()?;
    sdk.group_create(&GroupCreateOpts::new(
        data_rec_group_id.clone().into(),
        None,
        true,
        true,
        None,
        vec![],
        vec![],
        false,
    ))
    .await?;

    // create an explicit group as well
    let group2 = sdk.group_create(&Default::default()).await?;
    let ex_group_id = group2.id();

    Ok((
        DocumentEncryptOpts::new(
            None,
            None,
            // encrypt using the results of the policy and to ex_group_id
            // note that both the policy and the `grant_to_author` will encrypt to the
            // logged in user. This gets deduplicated internally.
            EitherOrBoth::Both(
                ExplicitGrant::new(true, &[ex_group_id.into(), bad_group.into()]),
                PolicyGrant::new(
                    Some("PII".try_into()?),
                    Some("INTERNAL".try_into()?),
                    None,
                    None,
                ),
            ),
        ),
        ex_group_id.clone(),
        data_rec_group_id.clone(),
    ))
}
// show how policy and explicit grants interact
#[tokio::test]
async fn doc_create_with_explicit_and_policy_grants() -> Result<(), IronOxideErr> {
    let (curr_user, sdk) = init_sdk_get_user().await;
    // this group doesn't exist, so it should show up in the errors
    let bad_group: GroupId = create_id_all_classes("bad_group").try_into()?;

    let doc = [0u8; 64];
    let (opts, ex_group_id, data_rec_group_id) =
        setup_encrypt_with_explicit_and_policy_grants(&sdk, &curr_user, &bad_group).await?;

    let doc_result = sdk.document_encrypt(doc.into(), &opts).await?;
    check_encrypt_with_explicit_and_policy_grants(
        &curr_user,
        &ex_group_id,
        &data_rec_group_id,
        &bad_group,
        Box::new(doc_result),
    );
    Ok(())
}

#[tokio::test]
async fn doc_encrypt_unmanaged_with_explicit_and_policy_grants() -> Result<(), IronOxideErr> {
    let (curr_user, sdk) = init_sdk_get_user().await;
    // this group doesn't exist, so it should show up in the errors
    let bad_group: GroupId = create_id_all_classes("bad_group").try_into()?;

    let doc = [0u8; 64];
    let (opts, ex_group_id, data_rec_group_id) =
        setup_encrypt_with_explicit_and_policy_grants(&sdk, &curr_user, &bad_group).await?;

    let doc_result = sdk.document_encrypt_unmanaged(doc.into(), &opts).await?;
    check_encrypt_with_explicit_and_policy_grants(
        &curr_user,
        &ex_group_id,
        &data_rec_group_id,
        &bad_group,
        Box::new(doc_result),
    );
    Ok(())
}
#[tokio::test]
async fn doc_create_duplicate_grants() -> Result<(), IronOxideErr> {
    let (user, sdk) = init_sdk_get_user().await;

    let doc = [0u8; 64];

    let doc_result = sdk
        .document_encrypt(
            doc.into(),
            &DocumentEncryptOpts::with_explicit_grants(
                None,
                Some("first name".try_into()?),
                true,
                vec![UserOrGroup::User { id: user }],
            ),
        )
        .await?;

    assert_that!(&doc_result.grants().len(), eq(1));
    Ok(())
}

#[tokio::test]
async fn doc_create_without_self_grant() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let doc = [0u8; 64];

    // create a second user to grant access to the document
    let second_user = create_second_user().await;

    let doc_result = sdk
        .document_encrypt(
            doc.into(),
            &DocumentEncryptOpts::with_explicit_grants(
                Some(create_id_all_classes("").try_into()?),
                Some("first name".try_into()?),
                false,
                vec![UserOrGroup::User {
                    id: second_user.account_id().clone(),
                }],
            ),
        )
        .await?;

    // should be a user with access, but not the currently initd user
    assert_eq!(doc_result.grants().len(), 1);
    assert_ne!(
        doc_result.grants()[0],
        UserOrGroup::User {
            id: sdk.device().account_id().clone()
        }
    );
    assert_eq!(
        doc_result.grants()[0],
        UserOrGroup::User {
            id: second_user.account_id().clone()
        }
    );
    assert_eq!(doc_result.access_errs().len(), 0);
    Ok(())
}

#[tokio::test]
async fn doc_create_shared_user_can_revoke() -> Result<(), IronOxideErr> {
    let (user1, user1_sdk) = init_sdk_get_user().await;
    let (user2, user2_sdk) = init_sdk_get_user().await;

    let doc = [0u8; 64];

    let doc_result = user1_sdk
        .document_encrypt(
            doc.into(),
            &DocumentEncryptOpts::with_explicit_grants(
                Some(create_id_all_classes("").try_into()?),
                Some("first name".try_into()?),
                true,
                vec![UserOrGroup::User { id: user2.clone() }],
            ),
        )
        .await?;

    // should be the author and the user2.
    assert_eq!(doc_result.grants().len(), 2);
    //Revoke the creator, which should now be allowed.
    let revoke_result = user2_sdk
        .document_revoke_access(doc_result.id(), &[UserOrGroup::User { id: user1.clone() }])
        .await?;
    assert_eq!(revoke_result.failed().len(), 0);
    assert_eq!(revoke_result.succeeded().len(), 1);
    let decrypt_result_or_error = user1_sdk
        .document_decrypt(doc_result.encrypted_data())
        .await;
    assert!(decrypt_result_or_error.err().is_some());
    Ok(())
}

#[tokio::test]
async fn doc_create_must_grant() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let doc = [0u8; 64];

    // should fail because encrypting a document with no grants is nonsense
    let doc_result = sdk
        .document_encrypt(
            doc.into(),
            &DocumentEncryptOpts::with_explicit_grants(
                None,
                Some("first name".try_into()?),
                false,
                vec![],
            ),
        )
        .await;

    // make sure there was a validation error, and that the problem was with the grant
    assert_eq!(
        match doc_result.err().unwrap() {
            IronOxideErr::ValidationError(field_name, _) => field_name,
            _ => "failed test".to_string(),
        },
        "grants".to_string()
    );
    Ok(())
}

#[tokio::test]
async fn doc_create_and_adjust_name() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let doc = [0u8; 64];

    let doc_result = sdk
        .document_encrypt(
            doc.into(),
            &DocumentEncryptOpts::with_explicit_grants(
                Some(create_id_all_classes("").try_into()?),
                Some("first name".try_into()?),
                true,
                vec![UserOrGroup::User {
                    id: UserId::try_from("bad-user").expect("should be good id"),
                }],
            ),
        )
        .await?;

    assert_eq!(doc_result.name().unwrap().name(), &"first name".to_string());

    let first_update = sdk
        .document_update_name(doc_result.id(), Some(&"second name".try_into()?))
        .await?;

    assert_eq!(
        first_update.name().unwrap().name(),
        &"second name".to_string()
    );

    let last_update = sdk.document_update_name(doc_result.id(), None).await?;

    assert!(last_update.name().is_none());
    Ok(())
}

#[tokio::test]
async fn doc_encrypt_decrypt_roundtrip_colt() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let doc = [43u8; 64];
    let encrypted_doc = sdk
        .document_encrypt(doc.into(), &Default::default())
        .await?;

    sdk.document_get_metadata(encrypted_doc.id()).await?;

    let decrypted = sdk.document_decrypt(encrypted_doc.encrypted_data()).await?;

    for i in 0..100_000_000 {
        let mut futures = futures::stream::iter(0..1000)
            .map(|_| time_future(sdk.document_decrypt(encrypted_doc.encrypted_data()))) // Creates a Vec of futures
            .buffer_unordered(20);

        while let Some((_, duration)) = futures.next().await {
            println!("Duration: {:?} in batch {}", duration, i);
        }
    }

    // assert_eq!(doc.to_vec(), decrypted.decrypted_data());
    Ok(())
}

#[tokio::test]
async fn doc_decrypt_unmanaged_no_access() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let user2 = create_second_user().await;

    let doc = [43u8; 64];
    let encrypted_doc = sdk
        .document_encrypt_unmanaged(
            doc.into(),
            &DocumentEncryptOpts::with_explicit_grants(
                Some(create_id_all_classes("").try_into()?),
                None,
                false,
                vec![user2.account_id().into()],
            ),
        )
        .await?;

    let decrypt_err = sdk
        .document_decrypt_unmanaged(
            encrypted_doc.encrypted_data(),
            encrypted_doc.encrypted_deks(),
        )
        .await
        .unwrap_err();

    assert_that!(&decrypt_err, is_variant!(IronOxideErr::RequestServerErrors));
    Ok(())
}

#[tokio::test]
async fn decrypt_with_rotated_user_private_key() -> Result<(), IronOxideErr> {
    let (_, init_result) = common::init_sdk_get_init_result(true).await;

    let sdk = init_result.discard_check();

    let encrypted_doc = sdk
        .document_encrypt(
            [42u8, 43u8].into(),
            &DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![]),
        )
        .await?;
    let decrypt_result1 = sdk.document_decrypt(encrypted_doc.encrypted_data()).await?;
    sdk.user_rotate_private_key(common::USER_PASSWORD).await?;
    let decrypt_result2 = sdk.document_decrypt(encrypted_doc.encrypted_data()).await?;

    assert_eq!(&decrypt_result1, &decrypt_result2);
    Ok(())
}

#[tokio::test]
async fn doc_encrypt_decrypt_unmanaged_roundtrip_many() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;
    let encrypt_opts = Default::default();
    let doc = [0u8; 42];

    for i in 0..100_000_000 {
        let encrypt_result = sdk
            .document_encrypt_unmanaged(doc.into(), &encrypt_opts)
            .await?;
        let (_, time) = time_future(sdk.document_decrypt_unmanaged(
            encrypt_result.encrypted_data(),
            encrypt_result.encrypted_deks(),
        ))
        .await;
        println!("decrypt time was: {:?} for iteration: {}", time, i);
    }

    Ok(())
}

#[tokio::test]
async fn doc_encrypt_decrypt_unmanaged_roundtrip_one() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;
    let encrypt_opts = Default::default();
    let doc = [0u8; 42];

    let encrypt_result = sdk
        .document_encrypt_unmanaged(doc.into(), &encrypt_opts)
        .await?;
    let (_, time) = time_future(sdk.document_decrypt_unmanaged(
        encrypt_result.encrypted_data(),
        encrypt_result.encrypted_deks(),
    ))
    .await;

    for i in 0..100_000_000 {
        let futures_vec: Vec<_> = (0..40)
            .map(|_| {
                time_future(sdk.document_decrypt_unmanaged(
                    encrypt_result.encrypted_data(),
                    encrypt_result.encrypted_deks(),
                ))
            }) // Creates a Vec of futures
            .collect();
        let mut futures = futures_vec.into_iter().collect::<FuturesUnordered<_>>(); // Convert Vec -> FuturesUnordered

        while let Some((_, duration)) = futures.next().await {
            println!("Duration: {:?} in batch {}", duration, i);
        }
    }

    Ok(())
}
async fn time_future<F, T>(future: F) -> (T, std::time::Duration)
where
    F: Future<Output = T>,
{
    async move { Instant::now() } // Start time is captured **only when polled**
        .then(|start| future.map(move |result| (result, start.elapsed())))
        .await
}

#[tokio::test]
async fn doc_encrypt_update_and_decrypt() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;
    let doc1 = [20u8; 72];

    let encrypted_doc = sdk
        .document_encrypt(doc1.into(), &Default::default())
        .await?;

    let doc_id = &encrypted_doc.id();

    let doc2 = [10u8; 11];

    let updated_encrypted_doc = sdk.document_update_bytes(doc_id, doc2.into()).await?;

    let decrypted = sdk
        .document_decrypt(updated_encrypted_doc.encrypted_data())
        .await?;

    assert_eq!(doc2.to_vec(), decrypted.decrypted_data());
    Ok(())
}

#[tokio::test]
async fn doc_grant_access() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let doc = [0u8; 64];
    let doc_result = sdk
        .document_encrypt(doc.into(), &Default::default())
        .await?;
    let doc_id = doc_result.id().clone();

    // create a second user to grant access to the document
    let user = create_second_user().await;

    // group user is a member of
    let group_result = sdk.group_create(&Default::default()).await?;
    let group_id = group_result.id().clone();

    // group user is not a member of
    let group2_result = sdk
        .group_create(&GroupCreateOpts::new(
            None,
            None,
            true,
            false,
            None,
            vec![],
            vec![],
            false,
        ))
        .await?;
    let group2_id = group2_result.id().clone();

    let grants = sdk
        .document_grant_access(
            &doc_id,
            &[
                UserOrGroup::User {
                    id: user.account_id().clone(),
                },
                UserOrGroup::Group { id: group_id },
                UserOrGroup::Group { id: group2_id },
                UserOrGroup::User {
                    id: create_id_all_classes("bad-user-id").try_into()?,
                },
                UserOrGroup::Group {
                    id: create_id_all_classes("bad-group-id").try_into()?,
                },
            ],
        )
        .await?;
    assert_eq!(3, grants.succeeded().len());
    assert_eq!(2, grants.failed().len());
    Ok(())
}

#[tokio::test]
async fn doc_add_remove_access() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let doc = [0u8; 64];
    let doc_result = sdk
        .document_encrypt(doc.into(), &Default::default())
        .await?;
    let doc_id = doc_result.id().clone();
    assert_eq!(doc_result.grants().len(), 1);

    // create a second user to grant access to the document
    let user = create_second_user().await;

    let grants = sdk
        .document_grant_access(
            &doc_id,
            &[UserOrGroup::User {
                id: user.account_id().clone(),
            }],
        )
        .await?;
    assert_eq!(1, grants.succeeded().len());
    assert_eq!(0, grants.failed().len());
    let doc_get = sdk.document_get_metadata(&doc_id).await?;
    assert_eq!(doc_get.visible_to_users().len(), 2);
    let removals = sdk
        .document_revoke_access(
            &doc_id,
            &[UserOrGroup::User {
                id: user.account_id().clone(),
            }],
        )
        .await?;
    assert_eq!(1, removals.succeeded().len());
    assert_eq!(0, removals.failed().len());
    let doc_get = sdk.document_get_metadata(&doc_id).await?;
    assert_eq!(doc_get.visible_to_users().len(), 1);
    Ok(())
}

#[tokio::test]
async fn doc_revoke_access() -> Result<(), IronOxideErr> {
    let sdk = initialize_sdk().await?;

    let doc = [0u8; 64];
    let doc_result = sdk
        .document_encrypt(
            doc.into(),
            &DocumentEncryptOpts::with_explicit_grants(
                Some(create_id_all_classes("").try_into()?),
                None,
                true,
                vec![],
            ),
        )
        .await?;
    let doc_id = doc_result.id().clone();

    // create a second user to grant/revoke access to the document
    let user = create_second_user().await;

    let group_result = sdk.group_create(&Default::default()).await?;
    let group_id = group_result.id().clone();

    let grants = sdk
        .document_grant_access(
            &doc_id,
            &[
                UserOrGroup::User {
                    id: user.account_id().clone(),
                },
                UserOrGroup::Group {
                    id: group_id.clone(),
                },
            ],
        )
        .await?;
    assert_eq!(grants.succeeded().len(), 2);

    let revokes = sdk
        .document_revoke_access(
            &doc_id,
            &[
                UserOrGroup::User {
                    id: user.account_id().clone(),
                },
                UserOrGroup::Group {
                    id: group_id.clone(),
                },
                UserOrGroup::User {
                    id: "bad-user-id".try_into()?,
                },
                UserOrGroup::Group {
                    id: "bad-group-id".try_into()?,
                },
            ],
        )
        .await?;

    assert_eq!(revokes.succeeded().len(), 2);
    assert_eq!(revokes.failed().len(), 2);
    Ok(())
}

#[tokio::test]
async fn sdk_init_with_timeout() -> Result<(), IronOxideErr> {
    let result = init_sdk_with_config(&IronOxideConfig {
        sdk_operation_timeout: Some(std::time::Duration::from_millis(10)),
        ..Default::default()
    })
    .await;

    assert!(result.is_err());
    let err_result = result.unwrap_err();
    assert_that!(&err_result, is_variant!(IronOxideErr::OperationTimedOut));
    assert_that!(
        &err_result,
        has_structure!(IronOxideErr::OperationTimedOut {
            operation: eq(SdkOperation::InitializeSdk),
            duration: eq(std::time::Duration::from_millis(10))
        })
    );
    Ok(())
}

//#[tokio::test]
//async fn doc_encrypt_concurrent() -> Result<(), IronOxideErr> {
//    let sdk = Arc::new(initialize_sdk()?);
//    let doc = [43u8; 64];
//    let _encrypted_doc = sdk.document_encrypt(&doc, &Default::default()).await?;
//
//    let mut threads = vec![];
//    for _i in 0..10 {
//        let sdk_ref = sdk.clone();
//        threads.push(std::thread::spawn(move || {
//            let _result = sdk_ref.document_encrypt(&doc, &Default::default()).unwrap();
//        }));
//    }
//
//    let mut joined_count = 0;
//    for t in threads {
//        t.join().expect("couldn't join");
//        joined_count += 1;
//    }
//
//    assert_eq!(joined_count, 10);
//    Ok(())
//}

trait WithGrantsAndErrs {
    fn grants(&self) -> Vec<UserOrGroup>;
    fn access_errs(&self) -> &[DocAccessEditErr];
}

impl WithGrantsAndErrs for DocumentEncryptResult {
    fn grants(&self) -> Vec<UserOrGroup> {
        self.grants().to_vec()
    }

    fn access_errs(&self) -> &[DocAccessEditErr] {
        self.access_errs()
    }
}

impl WithGrantsAndErrs for DocumentEncryptUnmanagedResult {
    fn grants(&self) -> Vec<UserOrGroup> {
        self.grants().to_vec()
    }

    fn access_errs(&self) -> &[DocAccessEditErr] {
        self.access_errs()
    }
}
