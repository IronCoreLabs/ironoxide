use crate::internal::{
    document_api::{DocAccessEditErr, UserOrGroup},
    IronOxideErr, PublicKey, WithKey,
};
use itertools::{Either, Itertools};
use recrypt::{
    api::{DerivedSymmetricKey, EncryptedValue, Plaintext, PrivateKey, RecryptErr},
    prelude::*,
};

/// Generate a DEK and it's associated symmetric key for a new document
pub fn generate_new_doc_key<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
) -> (Plaintext, DerivedSymmetricKey) {
    let dek = recrypt.gen_plaintext();
    let symmetric_key = recrypt.derive_symmetric_key(&dek);
    (dek, symmetric_key)
}

/// Generate a plaintext and a keypair necessary to create a new group
pub fn gen_group_keys<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
) -> Result<(Plaintext, PrivateKey, PublicKey), IronOxideErr> {
    let plaintext = recrypt.gen_plaintext();
    let priv_key = recrypt.derive_private_key(&plaintext);
    let pub_key = recrypt.compute_public_key(&priv_key)?;

    Ok((plaintext, priv_key.into(), pub_key.into()))
}

/// Decrypt the provided encrypted plaintext and return both the plaintext and the symmetric key that
/// is derived from it.
pub fn decrypt_plaintext<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    encrypted_plaintext: EncryptedValue,
    user_device_private_key: &PrivateKey,
) -> Result<(Plaintext, DerivedSymmetricKey), IronOxideErr> {
    let plaintext = recrypt.decrypt(encrypted_plaintext, &user_device_private_key)?;
    let symmetric_key = recrypt.derive_symmetric_key(&plaintext);
    Ok((plaintext, symmetric_key))
}

/// Encrypt the plaintext to all the public keys in the `with_keys` list. If the encryption succeeds, return the values in the right
/// list. If encryption fails, return them in the left list.
pub fn encrypt_to_with_key<T, CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    plaintext: &recrypt::api::Plaintext,
    signing_keys: &recrypt::api::SigningKeypair,
    with_keys: Vec<WithKey<T>>,
) -> (
    Vec<(WithKey<T>, recrypt::api::RecryptErr)>,
    Vec<(WithKey<T>, recrypt::api::EncryptedValue)>,
) {
    //Generate encrypted results for all the users we can. If they error, we'll put them in the acc_fails list.
    let enc_results_iter = with_keys.into_iter().map(move |key_entry| {
        let enc_result = recrypt.encrypt(
            plaintext.into(),
            &key_entry.public_key.clone().into(),
            signing_keys,
        );
        match enc_result {
            Ok(recrypt_transform_key) => Either::Right((key_entry, recrypt_transform_key)),
            Err(e) => Either::Left((key_entry, e)),
        }
    });
    //Now split the failures from the successes, this is done as a separate step
    //because we can't mutate recrypt in a partition_map call.
    enc_results_iter.partition_map(std::convert::identity)
}
impl From<(WithKey<UserOrGroup>, RecryptErr)> for DocAccessEditErr {
    fn from((user_or_group, err): (WithKey<UserOrGroup>, RecryptErr)) -> Self {
        match user_or_group {
            WithKey { id, .. } => DocAccessEditErr::new(
                id,
                format!("Access grant failed with error {}", err.to_string()),
            ),
        }
    }
}
