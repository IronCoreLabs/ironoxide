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

/// Result of rotating all keys that need rotation. UniFFI-compatible wrapper for the
/// tuple return of `IronOxide::rotate_all`.
#[cfg(feature = "uniffi")]
#[derive(uniffi::Record)]
pub struct RotateAllResult {
    pub user_result: Option<Arc<UserUpdatePrivateKeyResult>>,
    pub group_results: Option<Vec<Arc<GroupUpdatePrivateKeyResult>>>,
}

/// Concrete enum for UniFFI representing the result of SDK initialization with rotation check.
/// Replaces the generic `InitAndRotationCheck<BlockingIronOxide>` which UniFFI can't handle.
#[cfg(feature = "uniffi")]
#[derive(uniffi::Enum)]
pub enum BlockingInitResult {
    NoRotationNeeded { sdk: Arc<BlockingIronOxide> },
    RotationNeeded { sdk: Arc<BlockingIronOxide>, rotations: Arc<PrivateKeyRotationCheckResult> },
}

/// Struct that is used to hold the regular DeviceContext as well as a runtime that will be used
/// when initializing a BlockingIronOxide. This was added to fix a bug where initializing multiple
/// SDK instances with a single device would hang indefinitely (as each initialization call would
/// create its own runtime but share a request client)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct BlockingDeviceContext {
    pub device: DeviceContext,
    pub(crate) rt: Arc<Runtime>,
}

impl From<DeviceAddResult> for BlockingDeviceContext {
    fn from(value: DeviceAddResult) -> Self {
        Self {
            device: value.into(),
            rt: Arc::new(create_runtime()),
        }
    }
}

#[cfg(not(feature = "uniffi"))]
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
        self.device.device_private_key_internal()
    }
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl BlockingDeviceContext {
    #[uniffi::constructor]
    pub fn new(device: Arc<DeviceContext>) -> Self {
        Self {
            device: (*device).clone(),
            rt: Arc::new(create_runtime()),
        }
    }
    /// ID of the device's owner
    pub fn account_id(&self) -> UserId {
        self.device.account_id_internal().clone()
    }
    /// ID of the segment
    pub fn segment_id(&self) -> u64 {
        self.device.auth().segment_id() as u64
    }
    /// Private signing key of the device
    pub fn signing_private_key(&self) -> DeviceSigningKeyPair {
        self.device.signing_private_key_internal().clone()
    }
    /// Private encryption key of the device
    pub fn device_private_key(&self) -> PrivateKey {
        self.device.device_private_key_internal().clone()
    }
}

/// Struct that is used to make authenticated requests to the IronCore API. Instantiated with the details
/// of an account's various ids, device, and signing keys. Once instantiated all operations will be
/// performed in the context of the account provided. Identical to IronOxide but also contains a Runtime.
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct BlockingIronOxide {
    pub(crate) ironoxide: IronOxide,
    pub(crate) runtime: Arc<tokio::runtime::Runtime>,
}

// Shared impl - methods where return types work for both uniffi and non-uniffi
impl BlockingIronOxide {
    /// See [ironoxide::IronOxide::export_public_key_cache](../struct.IronOxide.html#method.export_public_key_cache)
    pub fn export_public_key_cache(&self) -> Result<Vec<u8>> {
        self.ironoxide.export_public_key_cache()
    }
}

#[cfg(not(feature = "uniffi"))]
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
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_get_metadata_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_get_metadata_unmanaged)
    pub fn document_get_metadata_unmanaged(
        &self,
        encrypted_deks: &[u8],
    ) -> Result<DocumentMetadataUnmanagedResult> {
        self.ironoxide
            .document_get_metadata_unmanaged(encrypted_deks)
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_get_id_from_bytes_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_get_id_from_bytes_unmanaged)
    pub fn document_get_id_from_bytes_unmanaged(
        &self,
        encrypted_document: &[u8],
    ) -> Result<DocumentId> {
        self.ironoxide
            .document_get_id_from_bytes_unmanaged(encrypted_document)
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_get_id_from_edeks_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_get_id_from_edeks_unmanaged)
    pub fn document_get_id_from_edeks_unmanaged(&self, edeks: &[u8]) -> Result<DocumentId> {
        self.ironoxide.document_get_id_from_edeks_unmanaged(edeks)
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_grant_access_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_grant_access_unmanaged)
    pub fn document_grant_access_unmanaged(
        &self,
        edeks: &[u8],
        grant_list: &[UserOrGroup],
    ) -> Result<DocumentAccessUnmanagedResult> {
        self.runtime.block_on(
            self.ironoxide
                .document_grant_access_unmanaged(edeks, grant_list),
        )
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_revoke_access_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_revoke_access_unmanaged)
    pub fn document_revoke_access_unmanaged(
        &self,
        edeks: &[u8],
        revoke_list: &[UserOrGroup],
    ) -> Result<DocumentAccessUnmanagedResult> {
        self.ironoxide
            .document_revoke_access_unmanaged(edeks, revoke_list)
    }

    /// See [ironoxide::document::file::DocumentFileOps::document_file_encrypt](trait.DocumentFileOps.html#tymethod.document_file_encrypt)
    pub fn document_file_encrypt(
        &self,
        source_path: &str,
        destination_path: &str,
        opts: &DocumentEncryptOpts,
    ) -> Result<DocumentFileEncryptResult> {
        self.runtime.block_on(self.ironoxide.document_file_encrypt(
            source_path,
            destination_path,
            opts,
        ))
    }

    /// See [ironoxide::document::file::DocumentFileOps::document_file_decrypt](trait.DocumentFileOps.html#tymethod.document_file_decrypt)
    pub fn document_file_decrypt(
        &self,
        source_path: &str,
        destination_path: &str,
    ) -> Result<DocumentFileDecryptResult> {
        self.runtime.block_on(
            self.ironoxide
                .document_file_decrypt(source_path, destination_path),
        )
    }

    /// See [ironoxide::document::file::DocumentFileAdvancedOps::document_file_encrypt_unmanaged](trait.DocumentFileAdvancedOps.html#tymethod.document_file_encrypt_unmanaged)
    pub fn document_file_encrypt_unmanaged(
        &self,
        source_path: &str,
        destination_path: &str,
        opts: &DocumentEncryptOpts,
    ) -> Result<DocumentFileEncryptUnmanagedResult> {
        self.runtime
            .block_on(self.ironoxide.document_file_encrypt_unmanaged(
                source_path,
                destination_path,
                opts,
            ))
    }

    /// See [ironoxide::document::file::DocumentFileAdvancedOps::document_file_decrypt_unmanaged](trait.DocumentFileAdvancedOps.html#tymethod.document_file_decrypt_unmanaged)
    pub fn document_file_decrypt_unmanaged(
        &self,
        source_path: &str,
        destination_path: &str,
        encrypted_deks: &[u8],
    ) -> Result<DocumentFileDecryptUnmanagedResult> {
        self.runtime
            .block_on(self.ironoxide.document_file_decrypt_unmanaged(
                source_path,
                destination_path,
                encrypted_deks,
            ))
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
    ) -> Result<DeviceAddResult> {
        let rt = create_runtime();
        rt.block_on(IronOxide::generate_new_device(
            jwt,
            password,
            device_create_options,
            timeout,
        ))
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

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl BlockingIronOxide {
    /// Get the `DeviceContext` instance that was used to create this SDK instance
    pub fn device(&self) -> Arc<DeviceContext> {
        Arc::new(self.ironoxide.device.clone())
    }

    /// See [ironoxide::IronOxide::clear_policy_cache](../struct.IronOxide.html#method.clear_policy_cache)
    pub fn clear_policy_cache(&self) -> u64 {
        self.ironoxide.clear_policy_cache() as u64
    }

    /// See [ironoxide::document::DocumentOps::document_list](trait.DocumentOps.html#tymethod.document_list)
    pub fn document_list(&self) -> Result<DocumentListResult> {
        self.runtime.block_on(self.ironoxide.document_list())
    }
    /// See [ironoxide::document::DocumentOps::document_get_metadata](trait.DocumentOps.html#tymethod.document_get_metadata)
    pub fn document_get_metadata(&self, id: DocumentId) -> Result<DocumentMetadataResult> {
        self.runtime
            .block_on(self.ironoxide.document_get_metadata(&id))
    }
    /// See [ironoxide::document::DocumentOps::document_get_id_from_bytes](trait.DocumentOps.html#tymethod.document_get_id_from_bytes)
    pub fn document_get_id_from_bytes(&self, encrypted_document: Vec<u8>) -> Result<DocumentId> {
        self.ironoxide
            .document_get_id_from_bytes(&encrypted_document)
    }
    /// See [ironoxide::document::DocumentOps::document_encrypt](trait.DocumentOps.html#tymethod.document_encrypt)
    pub fn document_encrypt(
        &self,
        document_data: Vec<u8>,
        encrypt_opts: Arc<DocumentEncryptOpts>,
    ) -> Result<DocumentEncryptResult> {
        self.runtime
            .block_on(self.ironoxide.document_encrypt(document_data, &encrypt_opts))
    }
    /// See [ironoxide::document::DocumentOps::document_update_bytes](trait.DocumentOps.html#tymethod.document_update_bytes)
    pub fn document_update_bytes(
        &self,
        id: DocumentId,
        new_document_data: Vec<u8>,
    ) -> Result<DocumentEncryptResult> {
        self.runtime
            .block_on(self.ironoxide.document_update_bytes(&id, new_document_data))
    }
    /// See [ironoxide::document::DocumentOps::document_decrypt](trait.DocumentOps.html#tymethod.document_decrypt)
    pub fn document_decrypt(&self, encrypted_document: Vec<u8>) -> Result<DocumentDecryptResult> {
        self.runtime
            .block_on(self.ironoxide.document_decrypt(&encrypted_document))
    }
    /// See [ironoxide::document::DocumentOps::document_update_name](trait.DocumentOps.html#tymethod.document_update_name)
    pub fn document_update_name(
        &self,
        id: DocumentId,
        name: Option<DocumentName>,
    ) -> Result<DocumentMetadataResult> {
        self.runtime
            .block_on(self.ironoxide.document_update_name(&id, name.as_ref()))
    }
    /// See [ironoxide::document::DocumentOps::document_grant_access](trait.DocumentOps.html#tymethod.document_grant_access)
    pub fn document_grant_access(
        &self,
        id: DocumentId,
        grant_list: Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        self.runtime
            .block_on(self.ironoxide.document_grant_access(&id, &grant_list))
    }
    /// See [ironoxide::document::DocumentOps::document_revoke_access](trait.DocumentOps.html#tymethod.document_revoke_access)
    pub fn document_revoke_access(
        &self,
        id: DocumentId,
        revoke_list: Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        self.runtime
            .block_on(self.ironoxide.document_revoke_access(&id, &revoke_list))
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_encrypt_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_encrypt_unmanaged)
    pub fn document_encrypt_unmanaged(
        &self,
        data: Vec<u8>,
        encrypt_opts: Arc<DocumentEncryptOpts>,
    ) -> Result<DocumentEncryptUnmanagedResult> {
        self.runtime.block_on(
            self.ironoxide
                .document_encrypt_unmanaged(data, &encrypt_opts),
        )
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_decrypt_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_decrypt_unmanaged)
    pub fn document_decrypt_unmanaged(
        &self,
        encrypted_data: Vec<u8>,
        encrypted_deks: Vec<u8>,
    ) -> Result<DocumentDecryptUnmanagedResult> {
        self.runtime.block_on(
            self.ironoxide
                .document_decrypt_unmanaged(&encrypted_data, &encrypted_deks),
        )
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_get_metadata_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_get_metadata_unmanaged)
    pub fn document_get_metadata_unmanaged(
        &self,
        encrypted_deks: Vec<u8>,
    ) -> Result<DocumentMetadataUnmanagedResult> {
        self.ironoxide
            .document_get_metadata_unmanaged(&encrypted_deks)
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_get_id_from_bytes_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_get_id_from_bytes_unmanaged)
    pub fn document_get_id_from_bytes_unmanaged(
        &self,
        encrypted_document: Vec<u8>,
    ) -> Result<DocumentId> {
        self.ironoxide
            .document_get_id_from_bytes_unmanaged(&encrypted_document)
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_get_id_from_edeks_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_get_id_from_edeks_unmanaged)
    pub fn document_get_id_from_edeks_unmanaged(&self, edeks: Vec<u8>) -> Result<DocumentId> {
        self.ironoxide
            .document_get_id_from_edeks_unmanaged(&edeks)
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_grant_access_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_grant_access_unmanaged)
    pub fn document_grant_access_unmanaged(
        &self,
        edeks: Vec<u8>,
        grant_list: Vec<UserOrGroup>,
    ) -> Result<DocumentAccessUnmanagedResult> {
        self.runtime.block_on(
            self.ironoxide
                .document_grant_access_unmanaged(&edeks, &grant_list),
        )
    }
    /// See [ironoxide::document::advanced::DocumentAdvancedOps::document_revoke_access_unmanaged](trait.DocumentAdvancedOps.html#tymethod.document_revoke_access_unmanaged)
    pub fn document_revoke_access_unmanaged(
        &self,
        edeks: Vec<u8>,
        revoke_list: Vec<UserOrGroup>,
    ) -> Result<DocumentAccessUnmanagedResult> {
        self.ironoxide
            .document_revoke_access_unmanaged(&edeks, &revoke_list)
    }

    /// See [ironoxide::document::file::DocumentFileOps::document_file_encrypt](trait.DocumentFileOps.html#tymethod.document_file_encrypt)
    pub fn document_file_encrypt(
        &self,
        source_path: String,
        destination_path: String,
        opts: Arc<DocumentEncryptOpts>,
    ) -> Result<DocumentFileEncryptResult> {
        self.runtime.block_on(self.ironoxide.document_file_encrypt(
            &source_path,
            &destination_path,
            &opts,
        ))
    }

    /// See [ironoxide::document::file::DocumentFileOps::document_file_decrypt](trait.DocumentFileOps.html#tymethod.document_file_decrypt)
    pub fn document_file_decrypt(
        &self,
        source_path: String,
        destination_path: String,
    ) -> Result<DocumentFileDecryptResult> {
        self.runtime.block_on(
            self.ironoxide
                .document_file_decrypt(&source_path, &destination_path),
        )
    }

    /// See [ironoxide::document::file::DocumentFileAdvancedOps::document_file_encrypt_unmanaged](trait.DocumentFileAdvancedOps.html#tymethod.document_file_encrypt_unmanaged)
    pub fn document_file_encrypt_unmanaged(
        &self,
        source_path: String,
        destination_path: String,
        opts: Arc<DocumentEncryptOpts>,
    ) -> Result<DocumentFileEncryptUnmanagedResult> {
        self.runtime
            .block_on(self.ironoxide.document_file_encrypt_unmanaged(
                &source_path,
                &destination_path,
                &opts,
            ))
    }

    /// See [ironoxide::document::file::DocumentFileAdvancedOps::document_file_decrypt_unmanaged](trait.DocumentFileAdvancedOps.html#tymethod.document_file_decrypt_unmanaged)
    pub fn document_file_decrypt_unmanaged(
        &self,
        source_path: String,
        destination_path: String,
        encrypted_deks: Vec<u8>,
    ) -> Result<DocumentFileDecryptUnmanagedResult> {
        self.runtime
            .block_on(self.ironoxide.document_file_decrypt_unmanaged(
                &source_path,
                &destination_path,
                &encrypted_deks,
            ))
    }

    /// See [ironoxide::group::GroupOps::group_list](trait.GroupOps.html#tymethod.group_list)
    pub fn group_list(&self) -> Result<GroupListResult> {
        self.runtime.block_on(self.ironoxide.group_list())
    }
    /// See [ironoxide::group::GroupOps::group_create](trait.GroupOps.html#tymethod.group_create)
    pub fn group_create(&self, opts: Arc<GroupCreateOpts>) -> Result<GroupCreateResult> {
        self.runtime.block_on(self.ironoxide.group_create(&opts))
    }
    /// See [ironoxide::group::GroupOps::group_get_metadata](trait.GroupOps.html#tymethod.group_get_metadata)
    pub fn group_get_metadata(&self, id: GroupId) -> Result<GroupGetResult> {
        self.runtime
            .block_on(self.ironoxide.group_get_metadata(&id))
    }
    /// See [ironoxide::group::GroupOps::group_delete](trait.GroupOps.html#tymethod.group_delete)
    pub fn group_delete(&self, id: GroupId) -> Result<GroupId> {
        self.runtime.block_on(self.ironoxide.group_delete(&id))
    }
    /// See [ironoxide::group::GroupOps::group_update_name](trait.GroupOps.html#tymethod.group_update_name)
    pub fn group_update_name(
        &self,
        id: GroupId,
        name: Option<GroupName>,
    ) -> Result<GroupMetaResult> {
        self.runtime
            .block_on(self.ironoxide.group_update_name(&id, name.as_ref()))
    }
    /// See [ironoxide::group::GroupOps::group_add_members](trait.GroupOps.html#tymethod.group_add_members)
    pub fn group_add_members(
        &self,
        id: GroupId,
        grant_list: Vec<UserId>,
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .block_on(self.ironoxide.group_add_members(&id, &grant_list))
    }
    /// See [ironoxide::group::GroupOps::group_remove_members](trait.GroupOps.html#tymethod.group_remove_members)
    pub fn group_remove_members(
        &self,
        id: GroupId,
        revoke_list: Vec<UserId>,
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .block_on(self.ironoxide.group_remove_members(&id, &revoke_list))
    }
    /// See [ironoxide::group::GroupOps::group_add_admins](trait.GroupOps.html#tymethod.group_add_admins)
    pub fn group_add_admins(
        &self,
        id: GroupId,
        users: Vec<UserId>,
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .block_on(self.ironoxide.group_add_admins(&id, &users))
    }
    /// See [ironoxide::group::GroupOps::group_remove_admins](trait.GroupOps.html#tymethod.group_remove_admins)
    pub fn group_remove_admins(
        &self,
        id: GroupId,
        revoke_list: Vec<UserId>,
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .block_on(self.ironoxide.group_remove_admins(&id, &revoke_list))
    }
    /// See [ironoxide::group::GroupOps::group_rotate_private_key](trait.GroupOps.html#tymethod.group_rotate_private_key)
    pub fn group_rotate_private_key(
        &self,
        id: GroupId,
    ) -> Result<GroupUpdatePrivateKeyResult> {
        self.runtime
            .block_on(self.ironoxide.group_rotate_private_key(&id))
    }
    /// See [ironoxide::user::UserOps::user_list_devices](trait.UserOps.html#tymethod.user_list_devices)
    pub fn user_list_devices(&self) -> Result<UserDeviceListResult> {
        self.runtime.block_on(self.ironoxide.user_list_devices())
    }
    /// See [ironoxide::user::UserOps::user_delete_device](trait.UserOps.html#tymethod.user_delete_device)
    pub fn user_delete_device(&self, device_id: Option<DeviceId>) -> Result<DeviceId> {
        self.runtime
            .block_on(self.ironoxide.user_delete_device(device_id.as_ref()))
    }
    /// See [ironoxide::user::UserOps::user_get_public_key](trait.UserOps.html#tymethod.user_get_public_key)
    pub fn user_get_public_key(&self, users: Vec<UserId>) -> Result<HashMap<UserId, PublicKey>> {
        self.runtime
            .block_on(self.ironoxide.user_get_public_key(&users))
    }
    /// See [ironoxide::user::UserOps::user_rotate_private_key](trait.UserOps.html#tymethod.user_rotate_private_key)
    pub fn user_rotate_private_key(&self, password: String) -> Result<UserUpdatePrivateKeyResult> {
        self.runtime
            .block_on(self.ironoxide.user_rotate_private_key(&password))
    }
    /// See [ironoxide::user::UserOps::user_change_password](trait.UserOps.html#tymethod.user_change_password)
    pub fn user_change_password(
        &self,
        current_password: String,
        new_password: String,
    ) -> Result<UserUpdateResult> {
        self.runtime.block_on(
            self.ironoxide
                .user_change_password(&current_password, &new_password),
        )
    }

    pub fn rotate_all(
        &self,
        rotations: Arc<PrivateKeyRotationCheckResult>,
        password: String,
        timeout_millis: Option<u64>,
    ) -> Result<RotateAllResult> {
        let timeout = timeout_millis.map(std::time::Duration::from_millis);
        let (user, groups) = self
            .runtime
            .block_on(self.ironoxide.rotate_all(&rotations, &password, timeout))?;
        Ok(RotateAllResult {
            user_result: user.map(Arc::new),
            group_results: groups.map(|v| v.into_iter().map(Arc::new).collect()),
        })
    }
}

// Static methods as free functions for UniFFI (associated functions not supported).
// These call IronOxide methods directly rather than going through the not(uniffi) impl block.
#[cfg(feature = "uniffi")]
#[uniffi::export]
fn blocking_user_create(
    jwt: Arc<Jwt>,
    password: String,
    user_create_opts: Arc<UserCreateOpts>,
    timeout_millis: Option<u64>,
) -> Result<UserCreateResult> {
    let rt = create_runtime();
    rt.block_on(IronOxide::user_create(
        &jwt,
        &password,
        &user_create_opts,
        timeout_millis.map(std::time::Duration::from_millis),
    ))
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
fn blocking_user_verify(
    jwt: Arc<Jwt>,
    timeout_millis: Option<u64>,
) -> Result<Option<Arc<UserResult>>> {
    let rt = create_runtime();
    rt.block_on(IronOxide::user_verify(
        &jwt,
        timeout_millis.map(std::time::Duration::from_millis),
    ))
    .map(|opt| opt.map(Arc::new))
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
fn blocking_generate_new_device(
    jwt: Arc<Jwt>,
    password: String,
    device_create_options: Arc<DeviceCreateOpts>,
    timeout_millis: Option<u64>,
) -> Result<DeviceAddResult> {
    let rt = create_runtime();
    rt.block_on(IronOxide::generate_new_device(
        &jwt,
        &password,
        &device_create_options,
        timeout_millis.map(std::time::Duration::from_millis),
    ))
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
#[cfg(not(feature = "uniffi"))]
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

/// Initialize the BlockingIronOxide SDK with a device and cached public keys, enabling offline encryption immediately.
///
/// Verifies that the provided user/segment exists and the provided device keys are valid and
/// exist for the provided account. Verifies the public key cache has not been tampered with.
#[cfg(not(feature = "uniffi"))]
pub fn initialize_with_public_keys(
    device_context: &BlockingDeviceContext,
    config: &IronOxideConfig,
    public_key_cache: Vec<u8>,
) -> Result<BlockingIronOxide> {
    let maybe_io = device_context
        .rt
        .block_on(crate::initialize_with_public_keys(
            &device_context.device,
            config,
            public_key_cache,
        ));
    maybe_io.map(|io| BlockingIronOxide {
        ironoxide: io,
        runtime: device_context.rt.clone(),
    })
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
fn blocking_initialize(
    device_context: &BlockingDeviceContext,
    config: &IronOxideConfig,
) -> Result<Arc<BlockingIronOxide>> {
    let maybe_io = device_context
        .rt
        .block_on(crate::initialize(&device_context.device, config));
    maybe_io.map(|io| {
        Arc::new(BlockingIronOxide {
            ironoxide: io,
            runtime: device_context.rt.clone(),
        })
    })
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
fn blocking_initialize_with_public_keys(
    device_context: &BlockingDeviceContext,
    config: &IronOxideConfig,
    public_key_cache: Vec<u8>,
) -> Result<Arc<BlockingIronOxide>> {
    let maybe_io = device_context
        .rt
        .block_on(crate::initialize_with_public_keys(
            &device_context.device,
            config,
            public_key_cache,
        ));
    maybe_io.map(|io| {
        Arc::new(BlockingIronOxide {
            ironoxide: io,
            runtime: device_context.rt.clone(),
        })
    })
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
fn blocking_initialize_check_rotation(
    device_context: &BlockingDeviceContext,
    config: &IronOxideConfig,
) -> Result<BlockingInitResult> {
    let init = device_context.rt.block_on(crate::initialize_check_rotation(
        &device_context.device,
        config,
    ))?;
    Ok(match init {
        NoRotationNeeded(io) => BlockingInitResult::NoRotationNeeded {
            sdk: Arc::new(BlockingIronOxide {
                ironoxide: io,
                runtime: device_context.rt.clone(),
            }),
        },
        RotationNeeded(io, rot) => BlockingInitResult::RotationNeeded {
            sdk: Arc::new(BlockingIronOxide {
                ironoxide: io,
                runtime: device_context.rt.clone(),
            }),
            rotations: Arc::new(rot),
        },
    })
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
fn blocking_initialize_with_public_keys_and_check_rotation(
    device_context: &BlockingDeviceContext,
    config: &IronOxideConfig,
    public_key_cache: Vec<u8>,
) -> Result<BlockingInitResult> {
    let init = device_context
        .rt
        .block_on(crate::initialize_with_public_keys_and_check_rotation(
            &device_context.device,
            config,
            public_key_cache,
        ))?;
    Ok(match init {
        NoRotationNeeded(io) => BlockingInitResult::NoRotationNeeded {
            sdk: Arc::new(BlockingIronOxide {
                ironoxide: io,
                runtime: device_context.rt.clone(),
            }),
        },
        RotationNeeded(io, rot) => BlockingInitResult::RotationNeeded {
            sdk: Arc::new(BlockingIronOxide {
                ironoxide: io,
                runtime: device_context.rt.clone(),
            }),
            rotations: Arc::new(rot),
        },
    })
}

#[cfg(not(feature = "uniffi"))]
pub fn initialize_with_public_keys_and_check_rotation(
    device_context: &BlockingDeviceContext,
    config: &IronOxideConfig,
    public_key_cache: Vec<u8>,
) -> Result<InitAndRotationCheck<BlockingIronOxide>> {
    let maybe_init =
        device_context
            .rt
            .block_on(crate::initialize_with_public_keys_and_check_rotation(
                &device_context.device,
                config,
                public_key_cache,
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

#[cfg(not(feature = "uniffi"))]
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
