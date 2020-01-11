pub use crate::internal::document_api::{
    DocumentDecryptUnmanagedResult, DocumentEncryptUnmanagedResult,
};
use crate::{
    document::{partition_user_or_group, DocumentEncryptOpts},
    internal, Result,
};
use ironoxide_macros::add_async;
use itertools::EitherOrBoth;

crate::document_advanced_ops!(add_async(async));

#[async_trait]
impl DocumentAdvancedOps for crate::IronOxide {
    async fn document_encrypt_unmanaged(
        &self,
        data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptUnmanagedResult> {
        let (explicit_users, explicit_groups, grant_to_author, policy_grants) =
            match &encrypt_opts.grants {
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

        internal::document_api::encrypted_document_unmanaged(
            self.device.auth(),
            &self.recrypt,
            &self.user_master_pub_key,
            &self.rng,
            data,
            encrypt_opts.id.clone(),
            grant_to_author,
            &explicit_users,
            &explicit_groups,
            policy_grants,
        )
        .await
    }

    async fn document_decrypt_unmanaged(
        &self,
        encrypted_data: &[u8],
        encrypted_deks: &[u8],
    ) -> Result<DocumentDecryptUnmanagedResult> {
        internal::document_api::decrypt_document_unmanaged(
            self.device.auth(),
            &self.recrypt,
            self.device().device_private_key(),
            encrypted_data,
            encrypted_deks,
        )
        .await
    }
}
