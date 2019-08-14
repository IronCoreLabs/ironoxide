use crate::document::{partition_user_or_group, DocumentEncryptOpts};
use crate::internal;
pub use crate::internal::document_api::{
    DocumentDecryptUnmanagedResult, DocumentEncryptUnmanagedResult,
};
use crate::Result;
use itertools::EitherOrBoth;
use tokio::runtime::current_thread::Runtime;

pub trait DocumentAdvancedOps {
    /// (Advanced) Encrypt the provided document bytes. Return the encrypted document encryption keys (EDEKs)
    /// instead of creating a document entry in the IronCore webservice.
    ///
    /// The webservice is still needed for looking up public keys and evaluating policies, but no
    /// document is created and the edeks are not stored. An additional burden is put on the caller
    /// in that the encrypted data AND the edeks need to be provided for decryption.
    ///
    /// # Arguments
    /// - `document_data` - Bytes of the document to encrypt
    /// - `encrypt_opts` - Optional document encrypt parameters. Includes
    ///       `id` - Unique ID to use for the document. Document ID will be stored unencrypted and must be unique per segment.
    ///       `name` - (Ignored) - Any name provided will be ignored
    ///       `grant_to_author` - Flag determining whether to encrypt to the calling user or not. If set to false at least one value must be present in the `grants` list.
    ///       `grants` - List of users/groups to grant access to this document once encrypted
    fn document_encrypt_unmanaged(
        &self,
        data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptUnmanagedResult>;

    fn document_decrypt_unmanaged(
        &self,
        encrypted_data: &[u8],
        encrypted_deks: &[u8],
    ) -> Result<DocumentDecryptUnmanagedResult>;
}

impl DocumentAdvancedOps for crate::IronOxide {
    fn document_encrypt_unmanaged(
        &self,
        data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptUnmanagedResult> {
        let mut rt = Runtime::new().unwrap();

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

        rt.block_on(internal::document_api::edek_encrypt_document(
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
        ))
    }

    fn document_decrypt_unmanaged(
        &self,
        encrypted_data: &[u8],
        encrypted_deks: &[u8],
    ) -> Result<DocumentDecryptUnmanagedResult> {
        let deks: crate::proto::transform::EncryptedDeks =
            protobuf::parse_from_bytes(&encrypted_deks)?;
        dbg!(&deks);

        let mut rt = Runtime::new().unwrap();

        rt.block_on(internal::document_api::decrypt_document_unmanaged(
            self.device.auth(),
            &self.recrypt,
            self.device().private_device_key(),
            encrypted_data,
            encrypted_deks,
        ))
    }
}
