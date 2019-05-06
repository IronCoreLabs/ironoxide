//! IronOxide - IronCore Labs Rust SDK
//!
//! The IronOxide Rust SDK is a pure Rust library that integrates IronCore's privacy, security, and data control solution into
//! your Rust application. Operations in the IronOxide SDK are performed in the context of a user or backend service account. This
//! SDK supports all possible operations that work in the IronCore platform including creating and managing users and groups, encrypting
//! and decrypting document bytes, and granting and revoking access to documents to users and groups.
//!
//! ## [User Operations](user/trait.UserOps.html)
//!
//! The IronOxide SDK user methods allow for multiple operations to manage your synced users/service accounts from your application
//! into the IronCore platform:
//!
//! + Lookup existing synced users in the IronCore system given their unique account IDs
//! + Sync and generate cryptographic keys for authenticated users from your application into IronCore
//! + List, create, and delete cryptographic device keys for synced users
//! + List a users devices
//!
//! ## [Document Operations](document/trait.DocumentOps.html)
//!
//! All secret data that is encrypted using the IronCore platform are referred to as documents. Documents wrap the raw bytes of
//! secret data to encrypt along with various metadata that helps convey access information to that data. Documents can be encrypted,
//! decrypted, updated, granted to users and groups, and revoked from users and groups.
//!
//! ## [Group Operations](group/trait.GroupOps.html)
//!
//! Groups are one of the many differentiating features of the IronCore platform. This SDK allows for easy management of your cryptographic
//! groups. Groups can be created, updated, and deleted along with management of a groups administrators and members.
//!

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate base64_serde;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate lazy_static;
#[cfg(test)]
#[macro_use]
extern crate galvanic_assert;

mod crypto;
mod internal;

/// Code specific to binding to another language
///
/// Code is only included here if it needs to live inside the ironoxide crate.
/// See [ironoxide-java](https://github.com/IronCoreLabs/ironoxide-java) for the Java binding.
pub mod binding;

/// SDK document operations
pub mod document;

/// SDK group operations
pub mod group;

/// Convenience re-export of essential IronOxide types
pub mod prelude;

/// SDK user operations
pub mod user;

pub use crate::internal::{
    DeviceContext, DeviceSigningKeyPair, IronOxideErr, KeyPair, PrivateKey, PublicKey,
};
use rand::rngs::ThreadRng;
use recrypt::api::{Ed25519, RandomBytes, Recrypt, Sha256};
use tokio::runtime::current_thread::Runtime;

/// Result of an Sdk operation
pub type Result<T> = std::result::Result<T, IronOxideErr>;

/// Struct that is used to make authenticated requests to the IronCore API. Instantiated with the details
/// of an accounts various ids, device, and signing keys. Once instantiated all operations will be
/// performed in the context of the account provided.
pub struct IronOxide {
    pub(crate) recrypt: Recrypt<Sha256, Ed25519, RandomBytes<ThreadRng>>,
    /// Master public key for the user identified by `account_id`
    pub(crate) user_master_pub_key: PublicKey,
    pub(crate) device: DeviceContext,
    pub(crate) rng: ThreadRng,
}

/// Initialize the IronOxide SDK with a device. Verifies that the provided user/segment exists and the provided device
/// keys are valid and exist for the provided account. If successful returns an instance of the IronOxide SDK
pub fn initialize(device_context: &DeviceContext) -> Result<IronOxide> {
    let mut rt = Runtime::new().unwrap();
    let account_id = device_context.account_id();
    rt.block_on(crate::internal::user_api::user_key_list(
        &device_context.auth(),
        &vec![account_id.clone()],
    ))
    .and_then(|mut users| {
        users
            //We're using remove here because we don't actually need this HashMap anymore and remove
            //returns us ownership so we can avoid a clone.
            .remove(&device_context.account_id())
            .map(|current_user_public_key| IronOxide {
                recrypt: Recrypt::new(),
                device: device_context.clone(),
                user_master_pub_key: current_user_public_key,
                rng: rand::thread_rng(),
            })
            .ok_or(IronOxideErr::InitializeError)
    })
}

impl IronOxide {
    /// Get the `DeviceContext` instance that was used to create this SDK instance
    pub fn device(&self) -> &DeviceContext {
        &self.device
    }
}
