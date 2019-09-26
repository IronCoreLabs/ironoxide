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

// required by quick_error or IronOxideErr
#![recursion_limit = "128"]

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

mod proto;

/// SDK document operations
pub mod document;

/// SDK group operations
pub mod group;

/// SDK user operations
pub mod user;

/// Policy types
pub mod policy;

/// Convenience re-export of essential IronOxide types
pub mod prelude;

use crate::internal::group_api::GroupId;
use crate::internal::user_api::UserId;
pub use crate::internal::{
    DeviceContext, DeviceSigningKeyPair, IronOxideErr, KeyPair, PrivateKey, PublicKey,
};
use itertools::EitherOrBoth;
use rand::rngs::adapter::ReseedingRng;
use rand::rngs::EntropyRng;
use rand::FromEntropy;
use rand_chacha::ChaChaCore;
use recrypt::api::{Ed25519, RandomBytes, Recrypt, Sha256};
use std::sync::Mutex;
use tokio::runtime::current_thread::Runtime;

/// Result of an Sdk operation
pub type Result<T> = std::result::Result<T, IronOxideErr>;

/// Struct that is used to make authenticated requests to the IronCore API. Instantiated with the details
/// of an account's various ids, device, and signing keys. Once instantiated all operations will be
/// performed in the context of the account provided.
pub struct IronOxide {
    pub(crate) recrypt: Recrypt<Sha256, Ed25519, RandomBytes<recrypt::api::DefaultRng>>,
    /// Master public key for the user identified by `account_id`
    pub(crate) user_master_pub_key: PublicKey,
    pub(crate) device: DeviceContext,
    pub(crate) rng: Mutex<ReseedingRng<ChaChaCore, EntropyRng>>,
}

/// Result of calling `initialize_check_rotation`
pub enum InitAndRotationCheck {
    /// Initialization succeeded, and no requests for private key rotations were present
    NoRotationNeeded(IronOxide),
    /// Initialization succeeded, but some keys should be rotated
    RotationNeeded(IronOxide, PrivateKeyRotationCheckResult),
}

impl InitAndRotationCheck {
    pub fn unwrap(self) -> IronOxide {
        match self {
            InitAndRotationCheck::NoRotationNeeded(io) => io,
            InitAndRotationCheck::RotationNeeded(io, _) => io,
        }
    }
}

/// Provides soft rotation capabilities for user and group keys
pub struct PrivateKeyRotationCheckResult {
    pub rotations_needed: EitherOrBoth<UserId, Vec<GroupId>>,
}

impl PrivateKeyRotationCheckResult {
    pub fn user_rotation_needed() -> Option<UserId> {
        unimplemented!()
    }

    //    pub fn group_rotation_needed() -> Option<Vec<GroupId>> {
    //        unimplemented!()
    //    }
}

/// Initialize the IronOxide SDK with a device. Verifies that the provided user/segment exists and the provided device
/// keys are valid and exist for the provided account. If successful returns an instance of the IronOxide SDK
pub fn initialize(device_context: &DeviceContext) -> Result<IronOxide> {
    // 1 MB
    const BYTES_BEFORE_RESEEDING: u64 = 1 * 1024 * 1024;
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
                rng: Mutex::new(ReseedingRng::new(
                    rand_chacha::ChaChaCore::from_entropy(),
                    BYTES_BEFORE_RESEEDING,
                    EntropyRng::new(),
                )),
            })
            .ok_or(IronOxideErr::InitializeError)
    })
}

/// Initialize the IronOxide SDK and check to see if the user that owns this `DeviceContext` is
/// marked for private key rotation, or if any of the groups that the user is an admin of is marked
/// for private key rotation.
pub fn initialize_check_rotation(device_context: &DeviceContext) -> Result<InitAndRotationCheck> {
    Ok(unimplemented!())
}

impl IronOxide {
    /// Get the `DeviceContext` instance that was used to create this SDK instance
    pub fn device(&self) -> &DeviceContext {
        &self.device
    }
}

/// A way to turn IronSdkErr into Strings for the Java binding
impl From<IronOxideErr> for String {
    fn from(err: IronOxideErr) -> Self {
        format!("{}", err)
    }
}
