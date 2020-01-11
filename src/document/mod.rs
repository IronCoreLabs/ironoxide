pub use crate::internal::document_api::{
    AssociationType, DocAccessEditErr, DocumentAccessResult, DocumentDecryptResult,
    DocumentEncryptResult, DocumentListMeta, DocumentListResult, DocumentMetadataResult,
    UserOrGroup, VisibleGroup, VisibleUser,
};
use crate::{
    internal::{
        document_api::{self, DocumentId, DocumentName},
        group_api::GroupId,
        user_api::UserId,
    },
    policy::*,
    Result,
};
use ironoxide_macros::add_async;
use itertools::{Either, EitherOrBoth, Itertools};

/// Advanced document operations
pub mod advanced;

/// Optional parameters that can be provided when encrypting a new document.
#[derive(Debug, PartialEq, Clone)]
pub struct DocumentEncryptOpts {
    id: Option<DocumentId>,
    name: Option<DocumentName>,
    // at least one user/group must be included either explicitly or via a policy
    grants: EitherOrBoth<ExplicitGrant, PolicyGrant>,
}
#[derive(Debug, PartialEq, Clone)]

/// Explicit users/groups that should have access to decrypt a document.
pub struct ExplicitGrant {
    grant_to_author: bool,
    grants: Vec<UserOrGroup>,
}

impl ExplicitGrant {
    /// `grant_to_author` - true if the calling user should have access to decrypt the document
    /// `grants` - other UserOrGroups that should have access to the document
    pub fn new(grant_to_author: bool, grants: &[UserOrGroup]) -> ExplicitGrant {
        ExplicitGrant {
            grant_to_author,
            grants: grants.to_vec(),
        }
    }
}

impl DocumentEncryptOpts {
    pub fn new(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        grants: EitherOrBoth<ExplicitGrant, PolicyGrant>,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts { grants, name, id }
    }
    pub fn with_explicit_grants(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        grant_to_author: bool,
        grants: Vec<UserOrGroup>,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts {
            id,
            name,
            grants: EitherOrBoth::Left(ExplicitGrant {
                grants,
                grant_to_author,
            }),
        }
    }

    pub fn with_policy_grants(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        policy: PolicyGrant,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts {
            id,
            name,
            grants: EitherOrBoth::Right(policy),
        }
    }
}

impl Default for DocumentEncryptOpts {
    /// default to only sharing with the creator of the document
    fn default() -> Self {
        DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![])
    }
}

crate::document_ops!(add_async(async));

#[async_trait]
impl DocumentOps for crate::IronOxide {
    async fn document_list(&self) -> Result<DocumentListResult> {
        document_api::document_list(self.device.auth()).await
    }

    async fn document_get_metadata(&self, id: &DocumentId) -> Result<DocumentMetadataResult> {
        document_api::document_get_metadata(self.device.auth(), id).await
    }

    async fn document_get_id_from_bytes(&self, encrypted_document: &[u8]) -> Result<DocumentId> {
        document_api::get_id_from_bytes(encrypted_document)
    }

    async fn document_encrypt(
        &self,
        document_data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptResult> {
        let encrypt_opts = encrypt_opts.clone();

        let (explicit_users, explicit_groups, grant_to_author, policy_grants) =
            match encrypt_opts.grants {
                EitherOrBoth::Left(explicit_grants) => {
                    let (users, groups) = partition_user_or_group(&explicit_grants.grants);
                    (users, groups, explicit_grants.grant_to_author, None)
                }
                EitherOrBoth::Right(policy_grant) => (vec![], vec![], false, Some(policy_grant)),
                EitherOrBoth::Both(explicit_grants, policy_grant) => {
                    let (users, groups) = partition_user_or_group(&explicit_grants.grants);
                    (
                        users,
                        groups,
                        explicit_grants.grant_to_author,
                        Some(policy_grant),
                    )
                }
            };

        document_api::encrypt_document(
            self.device.auth(),
            &self.recrypt,
            &self.user_master_pub_key,
            &self.rng,
            document_data,
            encrypt_opts.id,
            encrypt_opts.name,
            grant_to_author,
            &explicit_users,
            &explicit_groups,
            policy_grants.as_ref(),
        )
        .await
    }

    async fn document_update_bytes(
        &self,
        id: &DocumentId,
        new_document_data: &[u8],
    ) -> Result<DocumentEncryptResult> {
        document_api::document_update_bytes(
            self.device.auth(),
            &self.recrypt,
            self.device.device_private_key(),
            &self.rng,
            id,
            &new_document_data,
        )
        .await
    }

    async fn document_decrypt(&self, encrypted_document: &[u8]) -> Result<DocumentDecryptResult> {
        document_api::decrypt_document(
            self.device.auth(),
            &self.recrypt,
            self.device.device_private_key(),
            encrypted_document,
        )
        .await
    }

    async fn document_update_name(
        &self,
        id: &DocumentId,
        name: Option<&DocumentName>,
    ) -> Result<DocumentMetadataResult> {
        document_api::update_document_name(self.device.auth(), id, name).await
    }

    async fn document_grant_access(
        &self,
        id: &DocumentId,
        grant_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        let (users, groups) = partition_user_or_group(grant_list);

        document_api::document_grant_access(
            self.device.auth(),
            &self.recrypt,
            id,
            &self.user_master_pub_key,
            &self.device.device_private_key(),
            &users,
            &groups,
        )
        .await
    }

    async fn document_revoke_access(
        &self,
        id: &DocumentId,
        revoke_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        document_api::document_revoke_access(self.device.auth(), id, revoke_list).await
    }
}

fn partition_user_or_group(uog_slice: &[UserOrGroup]) -> (Vec<UserId>, Vec<GroupId>) {
    uog_slice
        .into_iter()
        .partition_map(|access_grant| match access_grant {
            UserOrGroup::User { id } => Either::Left(id.clone()),
            UserOrGroup::Group { id } => Either::Right(id.clone()),
        })
}
