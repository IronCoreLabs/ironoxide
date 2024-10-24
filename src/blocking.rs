//! Blocking variant of IronOxide
//!
//! These synchronous functions will block the current thread to execute instead
//! of returning futures that need to be executed on a runtime. In every other way,
//! they are identical to their asynchronous counterparts.
//!
//! # Optional
//! This requires the optional `blocking` feature to be enabled.

#[doc(no_inline)]
use crate::prelude::*;

use crate::{
    InitAndRotationCheck::{NoRotationNeeded, RotationNeeded},
    Result,
};
use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "beta")]
use crate::search::{BlindIndexSearchInitialize, EncryptedBlindIndexSalt};
use tokio::runtime::Runtime;

/// Struct that is used to hold the regular DeviceContext as well as a runtime that will be used
/// when initializing a BlockingIronOxide. This was added to fix a bug where initializing multiple
/// SDK instances with a single device would hang indefinitely (as each initialization call would
/// create its own runtime but share a request client)
#[derive(Clone, Debug)]
pub struct BlockingDeviceContext {
    pub device: DeviceContext,
    pub(crate) rt: Arc<Runtime>,
}

impl BlockingDeviceContext {
    pub fn new(device: DeviceContext) -> Self {
        Self {
            device,
            rt: Arc::new(create_runtime()),
        }
    }
    /// ID of the device's owner
    pub fn account_id(&self) -> &UserId {
        &self.device.auth().account_id()
    }
    /// ID of the segment
    pub fn segment_id(&self) -> usize {
        self.device.auth().segment_id()
    }
    /// Private signing key of the device
    pub fn signing_private_key(&self) -> &DeviceSigningKeyPair {
        &self.device.auth().signing_private_key()
    }
    /// Private encryption key of the device
    pub fn device_private_key(&self) -> &PrivateKey {
        &self.device.device_private_key()
    }
}

/// Struct that is used to make authenticated requests to the IronCore API. Instantiated with the details
/// of an account's various ids, device, and signing keys. Once instantiated all operations will be
/// performed in the context of the account provided. Identical to IronOxide but also contains a Runtime.
#[derive(Debug)]
pub struct BlockingIronOxide {
    pub(crate) ironoxide: IronOxide,
    pub(crate) runtime: Arc<tokio::runtime::Runtime>,
}

impl BlockingIronOxide {
    /// Get the `DeviceContext` instance that was used to create this SDK instance
    pub fn device(&self) -> &DeviceContext {
        &self.ironoxide.device
    }

    /// See [ironoxide::IronOxide::clear_policy_cache](../struct.IronOxide.html#method.clear_policy_cache)
    pub fn clear_policy_cache(&self) -> usize {
        self.ironoxide.clear_policy_cache()
    }

    /// See [ironoxide::IronOxide::create_blind_index](../struct.IronOxide.html#method.create_blind_index)
    #[cfg(feature = "beta")]
    pub fn create_blind_index(&self, group_id: &GroupId) -> Result<EncryptedBlindIndexSalt> {
        self.runtime
            .block_on(self.ironoxide.create_blind_index(group_id))
    }

    /// See [ironoxide::IronOxide::rotate_all](../struct.IronOxide.html#method.rotate_all)
    pub fn rotate_all(
        &self,
        rotations: &PrivateKeyRotationCheckResult,
        password: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<(
        Option<UserUpdatePrivateKeyResult>,
        Option<Vec<GroupUpdatePrivateKeyResult>>,
    )> {
        self.runtime
            .block_on(self.ironoxide.rotate_all(rotations, password, timeout))
    }

    /// See [ironoxide::document::DocumentOps::document_list](trait.DocumentOps.html#tymethod.document_list)
    pub fn document_list(&self) -> Result<DocumentListResult> {
        self.runtime.block_on(self.ironoxide.document_list())
    }
    /// See [ironoxide::document::DocumentOps::document_get_metadata](trait.DocumentOps.html#tymethod.document_get_metadata)
    pub fn document_get_metadata(&self, id: &DocumentId) -> Result<DocumentMetadataResult> {
        self.runtime
            .block_on(self.ironoxide.document_get_metadata(id))
    }
    /// See [ironoxide::document::DocumentOps::document_get_id_from_bytes](trait.DocumentOps.html#tymethod.document_get_id_from_bytes)
    pub fn document_get_id_from_bytes(&self, encrypted_document: &[u8]) -> Result<DocumentId> {
        self.ironoxide
            .document_get_id_from_bytes(encrypted_document)
    }
    /// See [ironoxide::document::DocumentOps::document_encrypt](trait.DocumentOps.html#tymethod.document_encrypt)
    pub fn document_encrypt(
        &self,
        document_data: Vec<u8>,
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptResult> {
        self.runtime
            .block_on(self.ironoxide.document_encrypt(document_data, encrypt_opts))
    }
    /// See [ironoxide::document::DocumentOps::document_update_bytes](trait.DocumentOps.html#tymethod.document_update_bytes)
    pub fn document_update_bytes(
        &self,
        id: &DocumentId,
        new_document_data: Vec<u8>,
    ) -> Result<DocumentEncryptResult> {
        self.runtime
            .block_on(self.ironoxide.document_update_bytes(id, new_document_data))
    }
    /// See [ironoxide::document::DocumentOps::document_decrypt](trait.DocumentOps.html#tymethod.document_decrypt)
    pub fn document_decrypt(&self, encrypted_document: &[u8]) -> Result<DocumentDecryptResult> {
        self.runtime
            .block_on(self.ironoxide.document_decrypt(encrypted_document))
    }
    /// See [ironoxide::document::DocumentOps::document_update_name](trait.DocumentOps.html#tymethod.document_update_name)
    pub fn document_update_name(
        &self,
        id: &DocumentId,
        name: Option<&DocumentName>,
    ) -> Result<DocumentMetadataResult> {
        self.runtime
            .block_on(self.ironoxide.document_update_name(id, name))
    }
    /// See [ironoxide::document::DocumentOps::document_grant_access](trait.DocumentOps.html#tymethod.document_grant_access)
    pub fn document_grant_access(
        &self,
        id: &DocumentId,
        grant_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        self.runtime
            .block_on(self.ironoxide.document_grant_access(id, grant_list))
    }
    /// See [ironoxide::document::DocumentOps::document_revoke_access](trait.DocumentOps.html#tymethod.document_revoke_access)
    pub fn document_revoke_access(
        &self,
        id: &DocumentId,
        revoke_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        self.runtime
            .block_on(self.ironoxide.document_revoke_access(id, revoke_list))
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_encrypt_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_encrypt_unmanaged)
    pub fn document_encrypt_unmanaged(
        &self,
        data: Vec<u8>,
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptUnmanagedResult> {
        self.runtime.block_on(
            self.ironoxide
                .document_encrypt_unmanaged(data, encrypt_opts),
        )
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_decrypt_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_decrypt_unmanaged)
    pub fn document_decrypt_unmanaged(
        &self,
        encrypted_data: &[u8],
        encrypted_deks: &[u8],
    ) -> Result<DocumentDecryptUnmanagedResult> {
        self.runtime.block_on(
            self.ironoxide
                .document_decrypt_unmanaged(encrypted_data, encrypted_deks),
        )
    }
    /// See [ironoxide::group::GroupOps::group_list](trait.GroupOps.html#tymethod.group_list)
    pub fn group_list(&self) -> Result<GroupListResult> {
        self.runtime.block_on(self.ironoxide.group_list())
    }
    /// See [ironoxide::group::GroupOps::group_create](trait.GroupOps.html#tymethod.group_create)
    pub fn group_create(&self, opts: &GroupCreateOpts) -> Result<GroupCreateResult> {
        self.runtime.block_on(self.ironoxide.group_create(opts))
    }
    /// See [ironoxide::group::GroupOps::group_get_metadata](trait.GroupOps.html#tymethod.group_get_metadata)
    pub fn group_get_metadata(&self, id: &GroupId) -> Result<GroupGetResult> {
        self.runtime.block_on(self.ironoxide.group_get_metadata(id))
    }
    /// See [ironoxide::group::GroupOps::group_delete](trait.GroupOps.html#tymethod.group_delete)
    pub fn group_delete(&self, id: &GroupId) -> Result<GroupId> {
        self.runtime.block_on(self.ironoxide.group_delete(id))
    }
    /// See [ironoxide::group::GroupOps::group_update_name](trait.GroupOps.html#tymethod.group_update_name)
    pub fn group_update_name(
        &self,
        id: &GroupId,
        name: Option<&GroupName>,
    ) -> Result<GroupMetaResult> {
        self.runtime
            .block_on(self.ironoxide.group_update_name(id, name))
    }
    /// See [ironoxide::group::GroupOps::group_add_members](trait.GroupOps.html#tymethod.group_add_members)
    pub fn group_add_members(
        &self,
        id: &GroupId,
        grant_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .block_on(self.ironoxide.group_add_members(id, grant_list))
    }
    /// See [ironoxide::group::GroupOps::group_remove_members](trait.GroupOps.html#tymethod.group_remove_members)
    pub fn group_remove_members(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .block_on(self.ironoxide.group_remove_members(id, revoke_list))
    }
    /// See [ironoxide::group::GroupOps::group_add_admins](trait.GroupOps.html#tymethod.group_add_admins)
    pub fn group_add_admins(
        &self,
        id: &GroupId,
        users: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .block_on(self.ironoxide.group_add_admins(id, users))
    }
    /// See [ironoxide::group::GroupOps::group_remove_admins](trait.GroupOps.html#tymethod.group_remove_admins)
    pub fn group_remove_admins(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .block_on(self.ironoxide.group_remove_admins(id, revoke_list))
    }
    /// See [ironoxide::group::GroupOps::group_rotate_private_key](trait.GroupOps.html#tymethod.group_rotate_private_key)
    pub fn group_rotate_private_key(&self, id: &GroupId) -> Result<GroupUpdatePrivateKeyResult> {
        self.runtime
            .block_on(self.ironoxide.group_rotate_private_key(id))
    }
    /// See [ironoxide::user::UserOps::user_create](trait.UserOps.html#tymethod.user_create)
    pub fn user_create(
        jwt: &Jwt,
        password: &str,
        user_create_opts: &UserCreateOpts,
        timeout: Option<std::time::Duration>,
    ) -> Result<UserCreateResult> {
        let rt = create_runtime();
        rt.block_on(IronOxide::user_create(
            jwt,
            password,
            user_create_opts,
            timeout,
        ))
    }
    /// See [ironoxide::user::UserOps::user_list_devices](trait.UserOps.html#tymethod.user_list_devices)
    pub fn user_list_devices(&self) -> Result<UserDeviceListResult> {
        self.runtime.block_on(self.ironoxide.user_list_devices())
    }
    /// See [ironoxide::user::UserOps::generate_new_device](trait.UserOps.html#tymethod.generate_new_device)
    pub fn generate_new_device(
        jwt: &Jwt,
        password: &str,
        device_create_options: &DeviceCreateOpts,
        timeout: Option<std::time::Duration>,
    ) -> Result<BlockingDeviceContext> {
        let rt = create_runtime();
        let device: DeviceContext = rt
            .block_on(IronOxide::generate_new_device(
                jwt,
                password,
                device_create_options,
                timeout,
            ))?
            .into();
        Ok(BlockingDeviceContext {
            device,
            rt: Arc::new(rt),
        })
    }
    /// See [ironoxide::user::UserOps::user_delete_device](trait.UserOps.html#tymethod.user_delete_device)
    pub fn user_delete_device(&self, device_id: Option<&DeviceId>) -> Result<DeviceId> {
        self.runtime
            .block_on(self.ironoxide.user_delete_device(device_id))
    }
    /// See [ironoxide::user::UserOps::user_verify](trait.UserOps.html#tymethod.user_verify)
    pub fn user_verify(
        jwt: &Jwt,
        timeout: Option<std::time::Duration>,
    ) -> Result<Option<UserResult>> {
        let rt = create_runtime();
        rt.block_on(IronOxide::user_verify(jwt, timeout))
    }
    /// See [ironoxide::user::UserOps::user_get_public_key](trait.UserOps.html#tymethod.user_get_public_key)
    pub fn user_get_public_key(&self, users: &[UserId]) -> Result<HashMap<UserId, PublicKey>> {
        self.runtime
            .block_on(self.ironoxide.user_get_public_key(users))
    }
    /// See [ironoxide::user::UserOps::user_rotate_private_key](trait.UserOps.html#tymethod.user_rotate_private_key)
    pub fn user_rotate_private_key(&self, password: &str) -> Result<UserUpdatePrivateKeyResult> {
        self.runtime
            .block_on(self.ironoxide.user_rotate_private_key(password))
    }
    /// See [ironoxide::user::UserOps::user_change_password](trait.UserOps.html#tymethod.user_change_password)
    pub fn user_change_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<UserUpdateResult> {
        self.runtime.block_on(
            self.ironoxide
                .user_change_password(current_password, new_password),
        )
    }
}

/// Creates a tokio runtime on the current thread
fn create_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all() // enable both I/O and time drivers
        .build()
        .expect("tokio runtime failed to initialize")
}

/// Initialize the BlockingIronOxide SDK with a device. Verifies that the provided user/segment exists and the provided device
/// keys are valid and exist for the provided account. If successful, returns instance of the BlockingIronOxide SDK.
pub fn initialize(
    device_context: &BlockingDeviceContext,
    config: &IronOxideConfig,
) -> Result<BlockingIronOxide> {
    let maybe_io = device_context
        .rt
        .block_on(crate::initialize(&device_context.device, config));
    maybe_io.map(|io| BlockingIronOxide {
        ironoxide: io,
        runtime: device_context.rt.clone(),
    })
}

/// Initialize the BlockingIronOxide SDK and check to see if the user that owns this `DeviceContext` is
/// marked for private key rotation, or if any of the groups that the user is an admin of are marked
/// for private key rotation.
pub fn initialize_check_rotation(
    device_context: &BlockingDeviceContext,
    config: &IronOxideConfig,
) -> Result<InitAndRotationCheck<BlockingIronOxide>> {
    let maybe_init = device_context.rt.block_on(crate::initialize_check_rotation(
        &device_context.device,
        config,
    ));
    maybe_init.map(|init| match init {
        NoRotationNeeded(io) => NoRotationNeeded(BlockingIronOxide {
            ironoxide: io,
            runtime: device_context.rt.clone(),
        }),
        RotationNeeded(io, rot) => RotationNeeded(
            BlockingIronOxide {
                ironoxide: io,
                runtime: device_context.rt.clone(),
            },
            rot,
        ),
    })
}
