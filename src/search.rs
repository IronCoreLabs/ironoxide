use crate::document::advanced::DocumentEncryptUnmanagedResult;
use crate::document::advanced::*;
use crate::document::DocumentEncryptOpts;
use crate::internal::{take_lock, IronOxideErr};
use crate::{GroupId, IronOxide};
use async_trait::async_trait;
use rand::{self, RngCore};
use std::convert::{TryFrom, TryInto};
use std::ops::DerefMut;

use ironcore_search_helpers::generate_hashes_for_string;

type Result<A> = std::result::Result<A, IronOxideErr>;
///The required length of the salt.
const REQUIRED_LEN: usize = 32;

///The result of creating a new index as well as initializing an IronSimpleSdk.
///If you only want to create the index, see create_index.
pub struct CreatedIndexResult {
    pub encrypted_salt: DocumentEncryptUnmanagedResult,
    pub sdk: IronSimpleSearch,
}

///Trait which gives the ability to create an index.
#[async_trait]
pub trait SimpleSeachInitialize {
    ///Given the encrypted salt and the edeks, decrypt them and give back the IronSimpleSearch object.
    async fn initialize_search_sdk(
        &self,
        encrypted_data: &[u8],
        encrypted_deks: &[u8],
    ) -> Result<IronSimpleSearch>;
    ///Create an index and encrypt it to the provided group_id.
    ///If you need to index data immediately, see `create_index_and_initialize_search_sdk` which will return
    ///the IronSimpleSearch for reuse.
    async fn create_index(&self, group_id: &GroupId) -> Result<DocumentEncryptUnmanagedResult>;
    ///Create an index, encrypt it and initialize a IronSimpleSearch for immediate use.
    async fn create_index_and_initialize_search_sdk(
        &self,
        group_id: &GroupId,
    ) -> Result<CreatedIndexResult>;
}

#[async_trait]
impl SimpleSeachInitialize for IronOxide {
    async fn initialize_search_sdk(
        &self,
        encrypted_salt: &[u8],
        encrypted_salt_deks: &[u8],
    ) -> Result<IronSimpleSearch> {
        let decrypted_value = self
            .document_decrypt_unmanaged(encrypted_salt, encrypted_salt_deks)
            .await?;
        decrypted_value.decrypted_data().try_into()
    }
    async fn create_index(&self, group_id: &GroupId) -> Result<DocumentEncryptUnmanagedResult> {
        let CreatedIndexResult { encrypted_salt, .. } = self
            .create_index_and_initialize_search_sdk(group_id)
            .await?;
        Ok(encrypted_salt)
    }
    async fn create_index_and_initialize_search_sdk(
        &self,
        group_id: &GroupId,
    ) -> Result<CreatedIndexResult> {
        let salt = {
            let mut mut_salt = [0u8; 32];
            take_lock(&self.rng).deref_mut().fill_bytes(&mut mut_salt);
            mut_salt
        };

        let encrypted_salt = self
            .document_encrypt_unmanaged(
                &salt,
                &DocumentEncryptOpts::with_explicit_grants(
                    None,
                    None,
                    false,
                    vec![group_id.into()],
                ),
            )
            .await?;
        let search_sdk = IronSimpleSearch::new(salt);

        Ok(CreatedIndexResult {
            encrypted_salt,
            sdk: search_sdk,
        })
    }
}
#[derive(Debug, PartialEq, Clone)]
pub struct IronSimpleSearch {
    decrypted_salt: [u8; 32],
}

impl TryFrom<&[u8]> for IronSimpleSearch {
    type Error = IronOxideErr;
    fn try_from(bytes: &[u8]) -> Result<IronSimpleSearch> {
        let decrypted_len = bytes.len();
        if decrypted_len != REQUIRED_LEN {
            std::result::Result::Err(IronOxideErr::WrongSizeError(
                Some(decrypted_len),
                Some(REQUIRED_LEN),
            ))
        } else {
            let mut a = [0u8; 32];
            a.copy_from_slice(&bytes[0..32]);
            Ok(IronSimpleSearch::new(a))
        }
    }
}

impl IronSimpleSearch {
    fn new(decrypted_salt: [u8; 32]) -> IronSimpleSearch {
        IronSimpleSearch { decrypted_salt }
    }

    ///Generate the list of tokens to use to find entries that match the search query, given the specified partition_id.
    pub fn tokenize_query(&self, query: &str, partition_id: Option<&str>) -> Vec<u32> {
        generate_hashes_for_string(query, partition_id, &self.decrypted_salt[..])
    }

    ///Generate the list of search tokens that represent the supplied string.
    pub fn tokenize_data(&self, data: &str, partition_id: Option<&str>) -> Vec<u32> {
        generate_hashes_for_string(data, partition_id, &self.decrypted_salt[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_works_for_correct_size() -> Result<()> {
        let bytes = [0u8; 32];
        let _: IronSimpleSearch = (&bytes[..]).try_into()?;
        Ok(())
    }
    #[test]
    fn try_from_errors_for_incorrect_size() -> Result<()> {
        let bytes = [0u8; 100];
        let maybe_error: Result<IronSimpleSearch> = (&bytes[..]).try_into();
        let error = maybe_error.unwrap_err();
        assert_that!(&error, is_variant!(IronOxideErr::WrongSizeError));
        Ok(())
    }
}
