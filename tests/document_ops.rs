mod common;
use crate::common::init_sdk_get_user;
use common::{create_second_user, init_sdk};
use galvanic_assert::matchers::{collection::*, *};
use ironoxide::{document::*, group::GroupCreateOpts, prelude::*, IronOxide};
use itertools::EitherOrBoth;
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

#[cfg(test)]
#[macro_use]
extern crate galvanic_assert;

#[macro_use]
extern crate serde_json;

#[test]
fn doc_create_without_id() {
    let sdk = init_sdk();

    let doc = [0u8; 64];

    let doc_result = sdk.document_encrypt(&doc, &Default::default());

    assert!(doc_result.is_ok());
    let doc_result = doc_result.unwrap();
    assert_eq!(doc_result.grants().len(), 1); // access always granted to creator
    assert_eq!(doc_result.access_errs().len(), 0);
}

#[test]
fn doc_create_with_policy_grants() -> Result<(), IronOxideErr> {
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
    let (curr_user, sdk) = init_sdk_get_user();

    //create the data_recovery group used in the policy
    let data_rec_group_id: GroupId = format!("data_recovery_{}", curr_user.id())
        .try_into()
        .unwrap();
    let group_result = sdk.group_create(&GroupCreateOpts::new(
        data_rec_group_id.clone().into(),
        None,
        true,
    ));
    assert!(group_result.is_ok());

    let doc = [0u8; 64];

    // all of the policy grant fields are optional
    let doc_result = sdk
        .document_encrypt(
            &doc,
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
        .unwrap();

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
                id: "badgroupid_frompolicy".try_into().unwrap()
            },
            UserOrGroup::User {
                id: "baduserid_frompolicy".try_into().unwrap()
            }
        ])
    );

    // now use category, sensitivity, data_subject and substitution_user_id
    let user2_result = create_second_user();
    let user2 = user2_result.account_id();
    let group2_id: GroupId = format!("group_other_{}", user2.id()).try_into().unwrap();
    let group2_result =
        sdk.group_create(&GroupCreateOpts::new(group2_id.clone().into(), None, false));
    assert!(group2_result.is_ok());

    let doc_result2 = sdk
        .document_encrypt(
            &doc,
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
        .unwrap();

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
            id: "group_id_doctors".try_into().unwrap()
        },])
    );

    //finally send an empty policy
    let doc_result3 = sdk
        .document_encrypt(
            &doc,
            &DocumentEncryptOpts::with_policy_grants(
                None,
                Some("doc name2".try_into()?),
                PolicyGrant::default(),
            ),
        )
        .unwrap();
    assert_eq!(doc_result3.grants().len(), 1);
    Ok(())
}

#[test]
fn doc_edek_encrypt_with_policy_grants() -> Result<(), IronOxideErr> {
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
    let (curr_user, sdk) = init_sdk_get_user();

    //create the data_recovery group used in the policy
    let data_rec_group_id: GroupId = format!("data_recovery_{}", curr_user.id())
        .try_into()
        .unwrap();
    let group_result = sdk.group_create(&GroupCreateOpts::new(
        data_rec_group_id.clone().into(),
        None,
        true,
    ));
    assert!(group_result.is_ok());

    let doc = [0u8; 64];

    // all of the policy grant fields are optional
    let doc_result = sdk
        .document_edek_encrypt(
            &doc,
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
        .unwrap();

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
                id: "badgroupid_frompolicy".try_into().unwrap()
            },
            UserOrGroup::User {
                id: "baduserid_frompolicy".try_into().unwrap()
            }
        ])
    );

    // now use category, sensitivity, data_subject and substitution_user_id
    let user2_result = create_second_user();
    let user2 = user2_result.account_id();
    let group2_id: GroupId = format!("group_other_{}", user2.id()).try_into().unwrap();
    let group2_result =
        sdk.group_create(&GroupCreateOpts::new(group2_id.clone().into(), None, false));
    assert!(group2_result.is_ok());

    let doc_result2 = sdk
        .document_edek_encrypt(
            &doc,
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
        .unwrap();

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
            id: "group_id_doctors".try_into().unwrap()
        },])
    );

    //finally send an empty policy
    let doc_result3 = sdk
        .document_edek_encrypt(
            &doc,
            &DocumentEncryptOpts::with_policy_grants(
                None,
                Some("doc name2".try_into()?),
                PolicyGrant::default(),
            ),
        )
        .unwrap();
    assert_eq!(doc_result3.grants().len(), 1);
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
            UserOrGroup::User {
                id: bad_user.clone(),
            },
            UserOrGroup::Group {
                id: bad_group.clone(),
            },
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

#[test]
fn doc_create_with_explicit_self_grant() {
    let sdk = init_sdk();
    let encrypt_opts = setup_encrypt_with_explicit_self_grant();
    let doc = [0u8; 64];

    let doc_result = sdk.document_encrypt(&doc, &encrypt_opts).unwrap();

    check_encrypt_with_explicit_self_grant(&sdk, Box::new(doc_result));
}

#[test]
fn doc_edek_encrypt_with_explicit_self_grant() {
    let sdk = init_sdk();
    let encrypt_opts = setup_encrypt_with_explicit_self_grant();
    let doc = [0u8; 64];

    let doc_result = sdk.document_edek_encrypt(&doc, &encrypt_opts).unwrap();

    check_encrypt_with_explicit_self_grant(&sdk, Box::new(doc_result));
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

fn setup_encrypt_with_explicit_and_policy_grants(
    sdk: &IronOxide,
    curr_user: &UserId,
    bad_group: &GroupId,
) -> Result<(DocumentEncryptOpts, GroupId, GroupId), IronOxideErr> {
    //create the data_recovery group used in the policy
    let data_rec_group_id: GroupId = format!("data_recovery_{}", curr_user.id())
        .try_into()
        .unwrap();
    let group_result = sdk.group_create(&GroupCreateOpts::new(
        data_rec_group_id.clone().into(),
        None,
        true,
    ));
    assert!(group_result.is_ok());

    // create an explicit group as well
    let group2_result = sdk.group_create(&Default::default());
    assert!(group2_result.is_ok());
    let group2 = group2_result?;
    let ex_group_id = group2.id();

    Ok((
        DocumentEncryptOpts::new(
            None,
            None,
            // encrypt using the results of the policy and to ex_group_id
            // note that both the policy and the `grant_to_author` will encrypt to the
            // logged in user. This gets deduplicated internally.
            EitherOrBoth::Both(
                ExplicitGrant::new(true, &vec![ex_group_id.into(), bad_group.into()]),
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
#[test]
fn doc_create_with_explicit_and_policy_grants() -> Result<(), IronOxideErr> {
    let (curr_user, sdk) = init_sdk_get_user();
    // this group doesn't exist, so it should show up in the errors
    let bad_group: GroupId = "bad_group".try_into().unwrap();

    let doc = [0u8; 64];
    let (opts, ex_group_id, data_rec_group_id) =
        setup_encrypt_with_explicit_and_policy_grants(&sdk, &curr_user, &bad_group)?;

    let doc_result = sdk.document_encrypt(&doc, &opts).unwrap();
    check_encrypt_with_explicit_and_policy_grants(
        &curr_user,
        &ex_group_id,
        &data_rec_group_id,
        &bad_group,
        Box::new(doc_result),
    );
    Ok(())
}

#[test]
fn doc_edek_encrypt_with_explicit_and_policy_grants() -> Result<(), IronOxideErr> {
    let (curr_user, sdk) = init_sdk_get_user();
    // this group doesn't exist, so it should show up in the errors
    let bad_group: GroupId = "bad_group".try_into().unwrap();

    let doc = [0u8; 64];
    let (opts, ex_group_id, data_rec_group_id) =
        setup_encrypt_with_explicit_and_policy_grants(&sdk, &curr_user, &bad_group)?;

    let doc_result = sdk.document_edek_encrypt(&doc, &opts).unwrap();
    check_encrypt_with_explicit_and_policy_grants(
        &curr_user,
        &ex_group_id,
        &data_rec_group_id,
        &bad_group,
        Box::new(doc_result),
    );
    Ok(())
}
#[test]
fn doc_create_duplicate_grants() {
    let (user, sdk) = init_sdk_get_user();

    let doc = [0u8; 64];

    let doc_result = sdk
        .document_encrypt(
            &doc,
            &DocumentEncryptOpts::with_explicit_grants(
                None,
                Some("first name".try_into().unwrap()),
                true,
                vec![UserOrGroup::User { id: user }],
            ),
        )
        .unwrap();

    assert_that!(&doc_result.grants().len(), eq(1))
}

#[test]
fn doc_create_without_self_grant() {
    let sdk = init_sdk();

    let doc = [0u8; 64];

    // create a second user to grant access to the document
    let second_user = create_second_user();

    let doc_result = sdk
        .document_encrypt(
            &doc,
            &DocumentEncryptOpts::with_explicit_grants(
                None,
                Some("first name".try_into().unwrap()),
                false,
                vec![UserOrGroup::User {
                    id: second_user.account_id().clone(),
                }],
            ),
        )
        .unwrap();

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
}

#[test]
fn doc_create_must_grant() {
    let sdk = init_sdk();

    let doc = [0u8; 64];

    // should fail because encrypting a document with no grants is nonsense
    let doc_result = sdk.document_encrypt(
        &doc,
        &DocumentEncryptOpts::with_explicit_grants(
            None,
            Some("first name".try_into().unwrap()),
            false,
            vec![],
        ),
    );

    // make sure there was a validation error, and that the problem was with the grant
    assert_eq!(
        match doc_result.err().unwrap() {
            IronOxideErr::ValidationError(field_name, _) => field_name,
            _ => "failed test".to_string(),
        },
        "grants".to_string()
    )
}

#[test]
fn doc_create_and_adjust_name() {
    let sdk = init_sdk();

    let doc = [0u8; 64];

    let doc_result = sdk
        .document_encrypt(
            &doc,
            &DocumentEncryptOpts::with_explicit_grants(
                None,
                Some("first name".try_into().unwrap()),
                true,
                vec![UserOrGroup::User {
                    id: UserId::try_from("bad-user").expect("should be good id"),
                }],
            ),
        )
        .unwrap();

    assert_eq!(doc_result.name().unwrap().name(), &"first name".to_string());

    let first_update = sdk
        .document_update_name(&doc_result.id(), Some(&"second name".try_into().unwrap()))
        .unwrap();

    assert_eq!(
        first_update.name().unwrap().name(),
        &"second name".to_string()
    );

    let last_update = sdk.document_update_name(&doc_result.id(), None).unwrap();

    assert!(last_update.name().is_none());
}

#[test]
fn doc_decrypt_roundtrip() {
    let sdk = init_sdk();
    let doc = [43u8; 64];
    let encrypted_doc = sdk.document_encrypt(&doc, &Default::default()).unwrap();

    sdk.document_get_metadata(&encrypted_doc.id()).unwrap();

    let decrypted = sdk
        .document_decrypt(&encrypted_doc.encrypted_data())
        .unwrap();

    assert_eq!(doc.to_vec(), decrypted.decrypted_data());
}

#[test]
fn doc_encrypt_update_and_decrypt() {
    let sdk = init_sdk();
    let doc1 = [20u8; 72];

    let encrypted_doc = sdk.document_encrypt(&doc1, &Default::default()).unwrap();

    let doc_id = &encrypted_doc.id();

    let doc2 = [10u8; 11];

    let updated_encrypted_doc = sdk.document_update_bytes(doc_id, &doc2).unwrap();

    let decrypted = sdk
        .document_decrypt(&updated_encrypted_doc.encrypted_data())
        .unwrap();

    assert_eq!(doc2.to_vec(), decrypted.decrypted_data());
}

#[test]
fn doc_grant_access() {
    let sdk = init_sdk();

    let doc = [0u8; 64];
    let doc_result = sdk.document_encrypt(&doc, &Default::default());
    assert!(doc_result.is_ok());
    let doc_id = doc_result.unwrap().id().clone();

    // create a second user to grant access to the document
    let user = create_second_user();

    // group user is a memeber of
    let group_result = sdk.group_create(&Default::default());
    assert!(group_result.is_ok());
    let group_id = group_result.unwrap().id().clone();

    // group user is not a member of
    let group2_result = sdk.group_create(&GroupCreateOpts::new(None, None, false));
    assert!(group2_result.is_ok());
    let group2_id = group2_result.unwrap().id().clone();

    let grant_result = sdk.document_grant_access(
        &doc_id,
        &vec![
            UserOrGroup::User {
                id: user.account_id().clone(),
            },
            UserOrGroup::Group { id: group_id },
            UserOrGroup::Group { id: group2_id },
            UserOrGroup::User {
                id: "bad-user-id".try_into().unwrap(),
            },
            UserOrGroup::Group {
                id: "bad-group-id".try_into().unwrap(),
            },
        ],
    );
    dbg!(&grant_result);
    assert!(grant_result.is_ok());
    let grants = grant_result.unwrap();
    assert_eq!(3, grants.succeeded().len());
    assert_eq!(2, grants.failed().len());
}

#[test]
fn doc_revoke_access() {
    let sdk = init_sdk();

    let doc = [0u8; 64];
    let doc_result = sdk.document_encrypt(&doc, &Default::default());
    assert!(doc_result.is_ok());
    let doc_id = doc_result.unwrap().id().clone();

    // create a second user to grant/revoke access to the document
    let user = create_second_user();

    let group_result = sdk.group_create(&Default::default());
    assert!(group_result.is_ok());
    let group_id = group_result.unwrap().id().clone();

    let grant_result = sdk.document_grant_access(
        &doc_id,
        &vec![
            UserOrGroup::User {
                id: user.account_id().clone(),
            },
            UserOrGroup::Group {
                id: group_id.clone(),
            },
        ],
    );

    assert!(grant_result.is_ok());
    let grants = grant_result.unwrap();
    assert_eq!(grants.succeeded().len(), 2);

    let revoke_result = sdk.document_revoke_access(
        &doc_id,
        &vec![
            UserOrGroup::User {
                id: user.account_id().clone(),
            },
            UserOrGroup::Group {
                id: group_id.clone(),
            },
            UserOrGroup::User {
                id: "bad-user-id".try_into().unwrap(),
            },
            UserOrGroup::Group {
                id: "bad-group-id".try_into().unwrap(),
            },
        ],
    );

    assert!(revoke_result.is_ok());
    let revokes = revoke_result.unwrap();
    assert_eq!(revokes.succeeded().len(), 2);
    assert_eq!(revokes.failed().len(), 2)
}

#[test]
fn doc_encrypt_concurrent() {
    let sdk = Arc::new(init_sdk());
    let doc = [43u8; 64];
    let _encrypted_doc = sdk.document_encrypt(&doc, &Default::default()).unwrap();

    let mut threads = vec![];
    for _i in 0..10 {
        let sdk_ref = sdk.clone();
        threads.push(std::thread::spawn(move || {
            let _result = sdk_ref.document_encrypt(&doc, &Default::default()).unwrap();
        }));
    }

    let mut joined_count = 0;
    for t in threads {
        t.join().expect("couldn't join");
        joined_count += 1;
    }

    assert_eq!(joined_count, 10)
}

trait WithGrantsAndErrs {
    fn grants(&self) -> Vec<UserOrGroup>;
    fn access_errs(&self) -> &[DocAccessEditErr];
}

impl WithGrantsAndErrs for DocumentCreateResult {
    fn grants(&self) -> Vec<UserOrGroup> {
        self.grants().to_vec()
    }

    fn access_errs(&self) -> &[DocAccessEditErr] {
        self.access_errs()
    }
}

impl WithGrantsAndErrs for DocumentDetachedEncryptResult {
    fn grants(&self) -> Vec<UserOrGroup> {
        self.grants()
    }

    fn access_errs(&self) -> &[DocAccessEditErr] {
        self.access_errs()
    }
}
