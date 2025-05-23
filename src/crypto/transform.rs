use crate::internal::{
    IronOxideErr, PublicKey, WithKey,
    document_api::{DocAccessEditErr, UserOrGroup},
};
use itertools::{Either, Itertools};
use recrypt::{
    api::{DerivedSymmetricKey, EncryptedValue, Plaintext, PrivateKey, RecryptErr},
    prelude::*,
};

/// Generate a DEK and its associated symmetric key for a new document
pub fn generate_new_doc_key<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
) -> (Plaintext, DerivedSymmetricKey) {
    let dek = recrypt.gen_plaintext();
    let symmetric_key = recrypt.derive_symmetric_key(&dek);
    (dek, symmetric_key)
}

/// Generate a plaintext and a key pair necessary to create a new group
pub fn gen_group_keys<R: CryptoOps + KeyGenOps>(
    recrypt: &R,
) -> Result<(Plaintext, PrivateKey, PublicKey), IronOxideErr> {
    let plaintext = recrypt.gen_plaintext();
    let priv_key = recrypt.derive_private_key(&plaintext);
    let pub_key = recrypt.compute_public_key(&priv_key)?;
    Ok((plaintext, priv_key, pub_key.into()))
}

/// Decrypt the provided encrypted plaintext and return the symmetric key that is derived from it.
pub fn decrypt_as_symmetric_key<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    encrypted_plaintext: EncryptedValue,
    user_device_private_key: &PrivateKey,
) -> Result<DerivedSymmetricKey, IronOxideErr> {
    let plaintext = recrypt.decrypt(encrypted_plaintext, user_device_private_key)?;
    let symmetric_key = recrypt.derive_symmetric_key(&plaintext);
    Ok(symmetric_key)
}

/// Decrypt the provided encrypted plaintext and return both the plaintext and the private key that
/// is derived from it.
pub fn decrypt_as_private_key<CR: rand::CryptoRng + rand::RngCore>(
    recrypt: &Recrypt<Sha256, Ed25519, RandomBytes<CR>>,
    encrypted_plaintext: EncryptedValue,
    user_device_private_key: &PrivateKey,
) -> Result<(Plaintext, PrivateKey), IronOxideErr> {
    let plaintext = recrypt.decrypt(encrypted_plaintext, user_device_private_key)?;
    let private_key = recrypt.derive_private_key(&plaintext);
    Ok((plaintext, private_key))
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
            plaintext,
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
        let WithKey { id, .. } = user_or_group;
        DocAccessEditErr::new(id, format!("Access grant failed with error {err}"))
    }
}
