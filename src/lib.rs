//! IronOxide - IronCore Labs Rust SDK
//!
//! The IronOxide Rust SDK is a pure Rust library that integrates IronCore's privacy, security, and data control solution into
//! your Rust application. Operations in the IronOxide SDK are performed in the context of a user or backend service account. This
//! SDK supports all possible operations that work in the IronCore platform including creating and managing users and groups, encrypting
//! and decrypting document bytes, and granting and revoking access to documents to users and groups.
//!
//! # User Operations
//!
//! Users are the basis of IronOxide's functionality. Each user is a unique identity that has its own public/private key-pair. Users must always act
//! through devices. A device is authorized using a user's private encryption key and is therefore tightly bound to that user. Data can be never be encrypted
//! directly to a device, so devices can be considered ephemeral as there is no penalty for deleting a device and creating a new one.
//!
//! This SDK provides all the necessary functionality to manage users and devices. Users can be created, fetched, listed, and updated, while devices can be created
//! and deleted all using IronOxide's [UserOps](user/trait.UserOps.html).
//!
//! ### Creating a User
//!
//! Creating a user with [IronOxide::user_create](user/trait.UserOps.html#tymethod.user_create) requires a valid IronCore or Auth0 JWT as well as
//! the desired password that will be used to encrypt and escrow the user's private key.
//!
//! ```
//! # fn get_jwt() -> &'static str {
//! #     unimplemented!()
//! # }
//! # async fn run() -> Result<(), ironoxide::IronOxideErr> {
//! # use ironoxide::prelude::*;
//! // Assuming an external function to get the jwt
//! let jwt_str = get_jwt();
//! let jwt = Jwt::new(jwt_str)?;
//! let password = "foobar";
//! let opts = UserCreateOpts::new(false);
//! let user_result = IronOxide::user_create(&jwt, password, &opts, None).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Until they generate a device, this user will be unable to make any SDK calls.
//!
//! ### Generating a Device
//!
//! Generating a device with [IronOxide::generate_new_device](user/trait.UserOps.html#tymethod.generate_new_device) requires a valid IronCore or Auth0 JWT
//! corresponding to the desired user, as well as the user's password (needed to decrypt the user's escrowed private key).
//!
//! ```
//! # fn get_jwt() -> &'static str {
//! #     unimplemented!()
//! # }
//! # async fn run() -> Result<(), ironoxide::IronOxideErr> {
//! # use ironoxide::prelude::*;
//! // Assuming an external function to get the jwt
//! let jwt_str = get_jwt();
//! let jwt = Jwt::new(jwt_str)?;
//! let password = "foobar";
//! let opts = DeviceCreateOpts::new(None);
//! let device_result = IronOxide::generate_new_device(&jwt, password, &opts, None).await?;
//! // A `DeviceAddResult` can be converted into a `DeviceContext` used to initialize the SDK
//! let device_context: DeviceContext = device_result.into();
//! # Ok(())
//! # }
//! ```
//!
//! This `DeviceContext` can now be used to initialize the SDK.
//!
//! ### Initializing the SDK
//!
//! With [ironoxide::initialize](fn.initialize.html), you can use a `DeviceContext` to create an instance of the `IronOxide` SDK object
//! that can be used to make calls using the provided device.
//!
//! ```
//! # async fn run() -> Result<(), ironoxide::IronOxideErr> {
//! # use ironoxide::prelude::*;
//! # let device_context: DeviceContext = unimplemented!();
//! let config = IronOxideConfig::default();
//! let sdk = ironoxide::initialize(&device_context, &config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! All calls made with `sdk` will use the user's provided device.
//!
//! # Group Operations
//!
//! Groups are one of the many differentiating features of the DataControl platform. Groups are collections of users who share access permissions.
//! Group members are able to encrypt and decrypt documents using the group, and group administrators are able to update the group and modify its membership.
//! Members can be dynamically added and removed without the need to re-encrypt the data. This requires a series of cryptographic operations
//! involving the administrator's keys, the group’s keys, and the new member’s public key. By making it simple to control group membership,
//! we provide efficient and precise control over who has access to what information!
//!
//! This SDK allows for easy management of your cryptographic groups. Groups can be created, fetched, updated, and deleted using IronOxide's
//! [GroupOps](group/trait.GroupOps.html).
//!
//! ### Creating a Group
//!
//! For simple group creation, the [group_create](group/trait.GroupOps.html#tymethod.group_create) function can be
//! called with default values.
//!
//! ```
//! # async fn run() -> Result<(), ironoxide::IronOxideErr> {
//! # use ironoxide::prelude::*;
//! # let sdk: IronOxide = unimplemented!();
//! use ironoxide::group::GroupCreateOpts;
//! let group_result = sdk.group_create(&GroupCreateOpts::default()).await?;
//! // Group ID used for future calls to this group
//! let group_id: &GroupId = group_result.id();
//! # Ok(())
//! # }
//! ```
//!
//! # Document Operations
//!
//! All secret data that is encrypted using the IronCore platform are referred to as documents. Documents wrap the raw bytes of
//! secret data to encrypt along with various metadata that helps convey access information to that data. Documents can be encrypted,
//! decrypted, updated, granted to users and groups, and revoked from users and groups using IronOxide's
//! [DocumentOps](document/trait.DocumentOps.html).
//!
//! ### Encrypting a Document
//!
//! For simple encryption to self, the [document_encrypt](document/trait.DocumentOps.html#tymethod.document_encrypt) function can be
//! called with default values.
//!
//!```
//! # async fn run() -> Result<(), ironoxide::IronOxideErr> {
//! # use ironoxide::prelude::*;
//! # let sdk: IronOxide = unimplemented!();
//! use ironoxide::document::DocumentEncryptOpts;
//! let data = "secret data".to_string().into_bytes();
//! let encrypted = sdk.document_encrypt(data, &DocumentEncryptOpts::default()).await?;
//! let encrypted_bytes = encrypted.encrypted_data();
//! # Ok(())
//! # }
//! ```
//!
//! ### Decrypting a Document
//!
//! Decrypting a document is even simpler, as the only thing required by
//! [document_decrypt](document/trait.DocumentOps.html#tymethod.document_decrypt) is the bytes of the encrypted document.
//!
//!```
//! # async fn run() -> Result<(), ironoxide::IronOxideErr> {
//! # use ironoxide::prelude::*;
//! # let sdk: IronOxide = unimplemented!();
//! # let encrypted_bytes: &[u8] = &[1;1];
//! let document = sdk.document_decrypt(encrypted_bytes).await?;
//! let decrypted_data = document.decrypted_data();
//! # Ok(())
//! # }
//! ```

#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
// required by quick_error or IronOxideErr
#![recursion_limit = "128"]
// required as of rust 1.46.0
#![type_length_limit = "2000000"]

// include generated proto code as a proto module
mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto/mod.rs"));
}

mod crypto {
    pub mod aes;
    pub mod transform;
}
mod internal;

pub mod document;
pub mod group;
pub mod policy;
pub mod prelude;
pub mod user;

#[cfg(feature = "beta")]
pub mod search;

#[cfg(feature = "blocking")]
pub mod blocking;

pub use crate::internal::IronOxideErr;

use crate::{
    common::{DeviceContext, DeviceSigningKeyPair, PublicKey, SdkOperation},
    config::IronOxideConfig,
    document::UserOrGroup,
    group::{GroupId, GroupUpdatePrivateKeyResult},
    internal::{add_optional_timeout, WithKey},
    policy::PolicyGrant,
    user::{UserId, UserResult, UserUpdatePrivateKeyResult},
};
use dashmap::DashMap;
use itertools::EitherOrBoth;
use rand::{
    rngs::{adapter::ReseedingRng, OsRng},
    SeedableRng,
};
use rand_chacha::ChaChaCore;
use recrypt::api::{Ed25519, RandomBytes, Recrypt, Sha256};
use std::{
    convert::TryInto,
    fmt,
    sync::{Arc, Mutex},
};
use vec1::Vec1;

/// A `Result` alias where the Err case is `IronOxideErr`
pub type Result<T> = std::result::Result<T, IronOxideErr>;
type PolicyCache = DashMap<PolicyGrant, Vec<WithKey<UserOrGroup>>>;

// This is where we export structs that don't fit into a single module.
// They were previously exported at the top level, but added clutter to the docs landing page.
/// Types useful in multiple modules
pub mod common {
    pub use crate::internal::{
        DeviceContext, DeviceSigningKeyPair, PrivateKey, PublicKey, SdkOperation,
    };
}

/// IronOxide SDK configuration
pub mod config {
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    /// Top-level configuration object for IronOxide
    #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
    pub struct IronOxideConfig {
        /// See [PolicyCachingConfig](struct.PolicyCachingConfig.html)
        pub policy_caching: PolicyCachingConfig,
        /// Timeout for all SDK methods. Will return IronOxideErr::OperationTimedOut on timeout.
        pub sdk_operation_timeout: Option<Duration>,
    }

    impl Default for IronOxideConfig {
        fn default() -> Self {
            IronOxideConfig {
                policy_caching: PolicyCachingConfig::default(),
                sdk_operation_timeout: Some(Duration::from_secs(30)),
            }
        }
    }

    /// Policy evaluation caching config
    ///
    /// The lifetime of the cache is the lifetime of the `IronOxide` struct.
    ///
    /// Since policies are evaluated by the webservice, caching the result can greatly speed
    /// up encrypting a document with a [PolicyGrant](../policy/struct.PolicyGrant.html). There is no expiration of the cache, so
    /// if you want to clear it at runtime, call [IronOxide::clear_policy_cache](../struct.IronOxide.html#method.clear_policy_cache).
    #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
    pub struct PolicyCachingConfig {
        /// maximum number of policy evaluations that will be cached by the SDK.
        /// If the maximum number is exceeded, the cache will be cleared prior to storing the next entry
        pub max_entries: usize,
    }

    impl Default for PolicyCachingConfig {
        fn default() -> Self {
            PolicyCachingConfig { max_entries: 128 }
        }
    }
}

/// Primary SDK Object
///
/// Struct that is used to make authenticated requests to the IronCore API. Instantiated with the details
/// of an account's various ids, device, and signing keys. Once instantiated all operations will be
/// performed in the context of the account provided.
pub struct IronOxide {
    pub(crate) config: IronOxideConfig,
    pub(crate) recrypt: Arc<Recrypt<Sha256, Ed25519, RandomBytes<recrypt::api::DefaultRng>>>,
    /// Master public key for the user identified by `account_id`
    pub(crate) user_master_pub_key: PublicKey,
    pub(crate) device: DeviceContext,
    pub(crate) rng: Mutex<ReseedingRng<ChaChaCore, OsRng>>,
    pub(crate) policy_eval_cache: PolicyCache,
}

/// Manual implementation of Debug without the `recrypt` or `rng` fields
impl fmt::Debug for IronOxide {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IronOxide")
            .field("config", &self.config)
            .field("user_master_pub_key", &self.user_master_pub_key)
            .field("device", &self.device)
            .field("policy_eval_cache", &self.policy_eval_cache)
            .finish()
    }
}

/// Result of calling `initialize_check_rotation`
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum InitAndRotationCheck<T> {
    /// Initialization succeeded, and no requests for private key rotations were present
    NoRotationNeeded(T),
    /// Initialization succeeded, but some keys should be rotated
    RotationNeeded(T, PrivateKeyRotationCheckResult),
}

impl<T> InitAndRotationCheck<T> {
    /// Caller asked to check rotation on initialize, but doesn't want to handle the result.
    /// Consider using [initialize](fn.initialize.html) instead.
    pub fn discard_check(self) -> T {
        match self {
            InitAndRotationCheck::NoRotationNeeded(io)
            | InitAndRotationCheck::RotationNeeded(io, _) => io,
        }
    }

    /// Convenience constructor to make an InitAndRotationCheck::RotationNeeded from an IronOxide
    /// and an EitherOrBoth<UserId, Vec1<GroupId>> directly.
    pub fn new_rotation_needed(
        io: T,
        rotations_needed: EitherOrBoth<UserId, Vec1<GroupId>>,
    ) -> InitAndRotationCheck<T> {
        InitAndRotationCheck::RotationNeeded(io, PrivateKeyRotationCheckResult { rotations_needed })
    }
}

/// number of bytes that can be read from `IronOxide.rng` before it is reseeded. 1 MB
const BYTES_BEFORE_RESEEDING: u64 = 1024 * 1024;

/// Provides soft rotation capabilities for user and group keys
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PrivateKeyRotationCheckResult {
    pub rotations_needed: EitherOrBoth<UserId, Vec1<GroupId>>,
}

impl PrivateKeyRotationCheckResult {
    pub fn user_rotation_needed(&self) -> Option<&UserId> {
        match &self.rotations_needed {
            EitherOrBoth::Left(u) | EitherOrBoth::Both(u, _) => Some(u),
            _ => None,
        }
    }

    pub fn group_rotation_needed(&self) -> Option<&Vec1<GroupId>> {
        match &self.rotations_needed {
            EitherOrBoth::Right(groups) | EitherOrBoth::Both(_, groups) => Some(groups),
            _ => None,
        }
    }
}

/// Initializes the IronOxide SDK with a device.
///
/// Verifies that the provided user/segment exists and the provided device keys are valid and
/// exist for the provided account.
pub async fn initialize(
    device_context: &DeviceContext,
    config: &IronOxideConfig,
) -> Result<IronOxide> {
    internal::add_optional_timeout(
        internal::user_api::user_get_current(device_context.auth()),
        config.sdk_operation_timeout,
        SdkOperation::InitializeSdk,
    )
    .await?
    .map(|current_user| IronOxide::create(&current_user, device_context, config))
    .map_err(|e: IronOxideErr| IronOxideErr::InitializeError(e.to_string()))
}

/// Finds the groups that the caller is an admin of that need rotation and
/// forms an InitAndRotationCheck from the user/groups needing rotation.
fn check_groups_and_collect_rotation<T>(
    groups: &[internal::group_api::GroupMetaResult],
    user_needs_rotation: bool,
    account_id: UserId,
    ironoxide: T,
) -> InitAndRotationCheck<T> {
    use EitherOrBoth::{Both, Left, Right};
    let groups_needing_rotation = groups
        .iter()
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

/// Initializes the IronOxide SDK with a device and checks for necessary private key rotations
///
/// Checks to see if the user that owns this `DeviceContext` is marked for private key rotation,
/// or if any of the groups that the user is an admin of are marked for private key rotation.
pub async fn initialize_check_rotation(
    device_context: &DeviceContext,
    config: &IronOxideConfig,
) -> Result<InitAndRotationCheck<IronOxide>> {
    let (curr_user, group_list_result) = add_optional_timeout(
        futures::future::try_join(
            internal::user_api::user_get_current(device_context.auth()),
            internal::group_api::list(device_context.auth(), None),
        ),
        config.sdk_operation_timeout,
        SdkOperation::InitializeSdkCheckRotation,
    )
    .await??;

    let ironoxide = IronOxide::create(&curr_user, device_context, config);
    let user_groups = group_list_result.result();

    Ok(check_groups_and_collect_rotation(
        user_groups,
        curr_user.needs_rotation(),
        curr_user.account_id().to_owned(),
        ironoxide,
    ))
}

impl IronOxide {
    /// DeviceContext that was used to create this SDK instance
    pub fn device(&self) -> &DeviceContext {
        &self.device
    }

    /// Clears all entries from the policy cache.
    ///
    /// Returns the number of entries cleared from the cache.
    pub fn clear_policy_cache(&self) -> usize {
        let size = self.policy_eval_cache.len();
        self.policy_eval_cache.clear();
        size
    }

    /// Create an IronOxide instance. Depends on the system having enough entropy to seed a RNG.
    fn create(
        curr_user: &UserResult,
        device_context: &DeviceContext,
        config: &IronOxideConfig,
    ) -> IronOxide {
        IronOxide {
            config: config.clone(),
            recrypt: Arc::new(Recrypt::new()),
            device: device_context.clone(),
            user_master_pub_key: curr_user.user_public_key().to_owned(),
            rng: Mutex::new(ReseedingRng::new(
                rand_chacha::ChaChaCore::from_entropy(),
                BYTES_BEFORE_RESEEDING,
                OsRng::default(),
            )),
            policy_eval_cache: DashMap::new(),
        }
    }

    /// Rotate the private key of the calling user and all groups they are an administrator of where needs_rotation is true.
    /// Note that this function has the potential to take much longer than other functions, as rotation will be done
    /// individually on each user/group. If rotation is only needed for a specific group, it is strongly recommended
    /// to call [user_rotate_private_key](user\/trait.UserOps.html#tymethod.user_rotate_private_key) or
    /// [group_rotate_private_key](group\/trait.GroupOps.html#tymethod.group_rotate_private_key) instead.
    /// # Arguments
    /// - `rotations` - PrivateKeyRotationCheckResult that holds all users and groups to be rotated
    /// - `password` - Password to unlock the current user's user master key
    /// - `timeout` - timeout for rotate_all. This is a separate timeout from the SDK-wide timeout as it is
    /// expected that this operation might take significantly longer than other operations.
    pub async fn rotate_all(
        &self,
        rotations: &PrivateKeyRotationCheckResult,
        password: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<(
        Option<UserUpdatePrivateKeyResult>,
        Option<Vec<GroupUpdatePrivateKeyResult>>,
    )> {
        let valid_password: internal::Password = password.try_into()?;
        let user_future = rotations.user_rotation_needed().map(|_| {
            internal::user_api::user_rotate_private_key(
                &self.recrypt,
                valid_password,
                self.device().auth(),
            )
        });
        let group_futures = rotations.group_rotation_needed().map(|groups| {
            let group_futures = groups
                .into_iter()
                .map(|group_id| {
                    internal::group_api::group_rotate_private_key(
                        &self.recrypt,
                        self.device().auth(),
                        group_id,
                        self.device().device_private_key(),
                    )
                })
                .collect::<Vec<_>>();
            futures::future::join_all(group_futures)
        });
        let user_opt_future: futures::future::OptionFuture<_> = user_future.into();
        let group_opt_future: futures::future::OptionFuture<_> = group_futures.into();
        let (user_opt_result, group_opt_vec_result) = add_optional_timeout(
            futures::future::join(user_opt_future, group_opt_future),
            timeout,
            SdkOperation::RotateAll,
        )
        .await?;
        let group_opt_result_vec = group_opt_vec_result.map(|g| g.into_iter().collect());
        Ok((
            user_opt_result.transpose()?,
            group_opt_result_vec.transpose()?,
        ))
    }
}
