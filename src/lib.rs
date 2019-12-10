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
#[macro_use]
extern crate vec1;
#[cfg(test)]
#[macro_use]
extern crate galvanic_assert;
#[cfg(test)]
#[macro_use]
extern crate double;

#[macro_use]
extern crate percent_encoding;

mod crypto;
mod internal;

// include generated proto code as a proto module
// mod proto
include!(concat!(env!("OUT_DIR"), "/transform.rs"));

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

use crate::internal::{
    group_api::GroupId,
    user_api::{UserId, UserResult},
};
pub use crate::internal::{
    DeviceContext, DeviceSigningKeyPair, IronOxideErr, KeyPair, PrivateKey, PublicKey,
};
use itertools::EitherOrBoth;
use rand::{
    rngs::{adapter::ReseedingRng, EntropyRng},
    FromEntropy,
};
use rand_chacha::ChaChaCore;
use recrypt::api::{Ed25519, RandomBytes, Recrypt, Sha256};
use std::sync::Mutex;
use tokio::runtime::current_thread::Runtime;
use vec1::Vec1;

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
    pub(crate) runtime: tokio::runtime::Runtime,
}

/// Result of calling `initialize_check_rotation`
pub enum InitAndRotationCheck {
    /// Initialization succeeded, and no requests for private key rotations were present
    NoRotationNeeded(IronOxide),
    /// Initialization succeeded, but some keys should be rotated
    RotationNeeded(IronOxide, PrivateKeyRotationCheckResult),
}

impl InitAndRotationCheck {
    /// Caller asked to check rotation on initialize, but doesn't want to handle the result.
    /// Consider using [initialize](fn.initialize.html) instead.
    pub fn discard_check(self) -> IronOxide {
        match self {
            InitAndRotationCheck::NoRotationNeeded(io)
            | InitAndRotationCheck::RotationNeeded(io, _) => io,
        }
    }

    /// Convenience constructor to make an InitAndRotationCheck::RotationNeeded from an IronOxide
    /// and an EitherOrBoth<UserId, Vec1<GroupId>> directly.
    pub fn new_rotation_needed(
        io: IronOxide,
        rotations_needed: EitherOrBoth<UserId, Vec1<GroupId>>,
    ) -> InitAndRotationCheck {
        InitAndRotationCheck::RotationNeeded(io, PrivateKeyRotationCheckResult { rotations_needed })
    }
}

/// number of bytes that can be read from `IronOxide.rng` before it is reseeded. 1 MB
const BYTES_BEFORE_RESEEDING: u64 = 1 * 1024 * 1024;

/// Provides soft rotation capabilities for user and group keys
pub struct PrivateKeyRotationCheckResult {
    pub rotations_needed: EitherOrBoth<UserId, Vec1<GroupId>>,
}

impl PrivateKeyRotationCheckResult {
    pub fn user_rotation_needed(&self) -> Option<UserId> {
        match &self.rotations_needed {
            EitherOrBoth::Left(u) | EitherOrBoth::Both(u, _) => Some(u.clone()),
            _ => None,
        }
    }

    pub fn group_rotation_needed(&self) -> Option<Vec1<GroupId>> {
        match &self.rotations_needed {
            EitherOrBoth::Right(groups) | EitherOrBoth::Both(_, groups) => Some(groups.clone()),
            _ => None,
        }
    }

    // pub fn rotate_all(ironoxide: &IronOxide) -> (UserId, Vec<GroupId>) //TODO consider when group private key rotation is added
}

/// Initialize the IronOxide SDK with a device. Verifies that the provided user/segment exists and the provided device
/// keys are valid and exist for the provided account. If successful returns an instance of the IronOxide SDK
pub fn initialize(device_context: &DeviceContext) -> Result<IronOxide> {
    let mut rt = Runtime::new().unwrap();
    rt.block_on(internal::user_api::user_get_current(&device_context.auth()))
        .map(|current_user| IronOxide::create(&current_user, device_context))
        .map_err(|_| IronOxideErr::InitializeError)
}
/// Initialize the IronOxide SDK and check to see if the user that owns this `DeviceContext` is
/// marked for private key rotation, or if any of the groups that the user is an admin of is marked
/// for private key rotation.
pub fn initialize_check_rotation(device_context: &DeviceContext) -> Result<InitAndRotationCheck> {
    Runtime::new()
        .unwrap()
        .block_on(initialize_check_rotation_async(device_context))
}

// Finds the groups that the caller is an admin of that need rotation and
// forms an InitAndRotationCheck from the user/groups needing rotation.
fn check_groups_and_collect_rotation(
    groups: &Vec<internal::group_api::GroupMetaResult>,
    user_needs_rotation: bool,
    account_id: UserId,
    ironoxide: IronOxide,
) -> InitAndRotationCheck {
    use EitherOrBoth::{Both, Left, Right};
    let groups_needing_rotation = groups
        .into_iter()
        .filter(|meta_result| meta_result.needs_rotation() == Some(true))
        .map(|meta_result| meta_result.id().to_owned())
        .collect::<Vec<_>>();
    // If this is a Some, there are groups needing rotation
    let maybe_groups_needing_rotation = Vec1::try_from_vec(groups_needing_rotation).ok();
    match (user_needs_rotation, maybe_groups_needing_rotation) {
        (false, None) => InitAndRotationCheck::NoRotationNeeded(ironoxide),
        (true, None) => InitAndRotationCheck::new_rotation_needed(ironoxide, Left(account_id)),
        (false, Some(groups)) => {
            InitAndRotationCheck::new_rotation_needed(ironoxide, Right(groups))
        }
        (true, Some(groups)) => {
            InitAndRotationCheck::new_rotation_needed(ironoxide, Both(account_id, groups))
        }
    }
}

async fn initialize_check_rotation_async(
    device_context: &DeviceContext,
) -> Result<InitAndRotationCheck> {
    let (curr_user, group_list_result) = futures::try_join!(
        internal::user_api::user_get_current(device_context.auth()),
        internal::group_api::list(device_context.auth(), None)
    )?;
    let ironoxide = IronOxide::create(&curr_user, &device_context);
    let user_groups = group_list_result.result();

    Ok(check_groups_and_collect_rotation(
        user_groups,
        curr_user.needs_rotation(),
        curr_user.account_id().to_owned(),
        ironoxide,
    ))
}

impl IronOxide {
    /// Get the `DeviceContext` instance that was used to create this SDK instance
    pub fn device(&self) -> &DeviceContext {
        &self.device
    }

    /// Create an IronOxide instance. Depends on the system having enough entropy to seed a RNG.
    fn create(curr_user: &UserResult, device_context: &DeviceContext) -> IronOxide {
        // create a tokio runtime with the default number of core threads (num of cores on a machine)
        // and an elevated number of blocking_threads as we expect heavy concurrency to be network-bound
        let runtime = tokio::runtime::Builder::new()
            .blocking_threads(250) // most all SDK methods will block on the network
            .keep_alive(None)
            .build()
            .expect("tokio runtime failed to initialize");
        IronOxide {
            recrypt: Recrypt::new(),
            device: device_context.clone(),
            user_master_pub_key: curr_user.user_public_key().to_owned(),
            rng: Mutex::new(ReseedingRng::new(
                rand_chacha::ChaChaCore::from_entropy(),
                BYTES_BEFORE_RESEEDING,
                EntropyRng::new(),
            )),
            runtime,
        }
    }
}

/// A way to turn IronSdkErr into Strings for the Java binding
impl From<IronOxideErr> for String {
    fn from(err: IronOxideErr) -> Self {
        format!("{}", err)
    }
}
