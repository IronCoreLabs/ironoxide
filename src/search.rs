//! Blind Index Search API
//!
//! This is a technique that allows you to hide the terms that have been indexed. This particular implementation uses tri-grams, which
//! are salted and hashed to produce the list of tokens.
//!
//! ## BlindIndexSearch
//!
//! The BlindIndexSearch gives the ability to generate queries as well as create the search entries to store.
//!
//! # Optional
//! This requires the optional `beta` feature to be enabled.

#[cfg(feature = "blocking")]
use crate::blocking::BlockingIronOxide;

use crate::{
    document::{
        advanced::{DocumentAdvancedOps, DocumentEncryptUnmanagedResult},
        DocumentEncryptOpts,
    },
    group::GroupId,
    internal::take_lock,
    IronOxide, IronOxideErr, Result,
};
use async_trait::async_trait;
pub use ironcore_search_helpers::transliterate_string;
use ironcore_search_helpers::{
    generate_hashes_for_string, generate_hashes_for_string_with_padding,
};
use rand::{
    self,
    rngs::{adapter::ReseedingRng, OsRng},
    RngCore, SeedableRng,
};
use rand_chacha::ChaChaCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    ops::DerefMut,
    sync::Mutex,
};

///The required length of the salt.
const REQUIRED_LEN: usize = 32;
/// number of bytes that can be read from `BlindIndexSearch.rng` before it is reseeded. 1 MB
const BYTES_BEFORE_RESEEDING: u64 = 1024 * 1024;

#[derive(Debug, PartialEq, Clone, Hash, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedBlindIndexSalt {
    pub encrypted_deks: Vec<u8>,
    pub encrypted_salt_bytes: Vec<u8>,
}

impl EncryptedBlindIndexSalt {
    //encrypt the blind index salt and give back the BlindIndexSearch object.
    pub async fn initialize_search(&self, ironoxide: &IronOxide) -> Result<BlindIndexSearch> {
        let decrypted_value = ironoxide
            .document_decrypt_unmanaged(&self.encrypted_salt_bytes[..], &self.encrypted_deks[..])
            .await?;
        decrypted_value.decrypted_data().try_into()
    }

    #[cfg(feature = "blocking")]
    pub fn initialize_search_blocking(&self, bio: &BlockingIronOxide) -> Result<BlindIndexSearch> {
        bio.runtime.block_on(self.initialize_search(&bio.ironoxide))
    }
}

///Trait which gives the ability to create a blind index.
#[async_trait]
pub trait BlindIndexSearchInitialize {
    ///Create an index and encrypt it to the provided group_id.
    async fn create_blind_index(&self, group_id: &GroupId) -> Result<EncryptedBlindIndexSalt>;
}

#[async_trait]
impl BlindIndexSearchInitialize for IronOxide {
    async fn create_blind_index(&self, group_id: &GroupId) -> Result<EncryptedBlindIndexSalt> {
        let salt = {
            let mut mut_salt = [0u8; 32];
            take_lock(&self.rng).deref_mut().fill_bytes(&mut mut_salt);
            mut_salt
        };

        let encrypted_salt = self
            .document_encrypt_unmanaged(
                salt.into(),
                &DocumentEncryptOpts::with_explicit_grants(
                    None,
                    None,
                    false,
                    vec![group_id.into()],
                ),
            )
            .await?;
        encrypted_salt.try_into()
    }
}

#[derive(Debug)]
pub struct BlindIndexSearch {
    decrypted_salt: [u8; 32],
    rng: Mutex<ReseedingRng<ChaChaCore, OsRng>>,
}

impl TryFrom<&[u8]> for BlindIndexSearch {
    type Error = IronOxideErr;
    fn try_from(bytes: &[u8]) -> Result<BlindIndexSearch> {
        let decrypted_len = bytes.len();
        if decrypted_len != REQUIRED_LEN {
            Err(IronOxideErr::WrongSizeError(
                Some(decrypted_len),
                Some(REQUIRED_LEN),
            ))
        } else {
            let mut a = [0u8; 32];
            a.copy_from_slice(&bytes[0..32]);
            Ok(BlindIndexSearch::new(a))
        }
    }
}

impl TryFrom<DocumentEncryptUnmanagedResult> for EncryptedBlindIndexSalt {
    type Error = IronOxideErr;
    fn try_from(r: DocumentEncryptUnmanagedResult) -> Result<EncryptedBlindIndexSalt> {
        match r.access_errs().get(0) {
            None => Ok(EncryptedBlindIndexSalt {
                encrypted_deks: r.encrypted_deks().to_vec(),
                encrypted_salt_bytes: r.encrypted_data().to_vec(),
            }),
            Some(err) => Err(IronOxideErr::UserOrGroupDoesNotExist(
                err.user_or_group.clone(),
            )),
        }
    }
}

impl BlindIndexSearch {
    fn new(decrypted_salt: [u8; 32]) -> BlindIndexSearch {
        let rng = Mutex::new(ReseedingRng::new(
            rand_chacha::ChaChaCore::from_entropy(),
            BYTES_BEFORE_RESEEDING,
            OsRng::default(),
        ));
        BlindIndexSearch {
            decrypted_salt,
            rng,
        }
    }

    /// Generate the list of tokens to use to find entries that match the search query, given the specified partition_id.
    /// query - The string you want to tokenize and hash
    /// partition_id - An extra string you want to include in every hash, this allows 2 queries with different partition_ids to produce a different set of tokens for the same query
    pub fn tokenize_query(&self, query: &str, partition_id: Option<&str>) -> Result<HashSet<u32>> {
        generate_hashes_for_string(query, partition_id, &self.decrypted_salt[..])
            .map_err(|message| IronOxideErr::ValidationError("query".to_string(), message))
    }

    /// Generate the list of tokens to create a search entry for `data`. This function will also return some random values in the HashSet, which will make
    /// it harder for someone to know what the input was. Because of this, calling this function will not be the same as `tokenize_query`, but `tokenize_query` will always
    /// return a subset of the values returned by `tokenize_data`.
    ///
    /// data - The string you want to tokenize and hash
    /// partition_id - An extra string you want to include in every hash, this allows 2 queries with different partition_ids to produce a different set of tokens for the same data
    pub fn tokenize_data(&self, data: &str, partition_id: Option<&str>) -> Result<HashSet<u32>> {
        generate_hashes_for_string_with_padding(
            data,
            partition_id,
            &self.decrypted_salt[..],
            &self.rng,
        )
        .map_err(|message| IronOxideErr::ValidationError("data".to_string(), message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galvanic_assert::*;

    #[test]
    fn try_from_works_for_correct_size() -> Result<()> {
        let bytes = [0u8; 32];
        let _: BlindIndexSearch = (&bytes[..]).try_into()?;
        Ok(())
    }
    #[test]
    fn try_from_errors_for_incorrect_size() -> Result<()> {
        let bytes = [0u8; 100];
        let maybe_error: Result<BlindIndexSearch> = (&bytes[..]).try_into();
        let error = maybe_error.unwrap_err();
        assert_that!(&error, is_variant!(IronOxideErr::WrongSizeError));
        Ok(())
    }
}
