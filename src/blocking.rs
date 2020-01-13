//!
//! A blocking version of the SDK.
//!
//! These synchronous functions will block the current thread to execute instead
//! of returning futures that need to be executed on a runtime. In every other way,
//! they are identitical to their asynchronous counterparts.
//!
//! # Optional
//! This requires the optional `blocking` feature to be enabled.
use crate::Result;
use crate::{
    document::{
        advanced::DocumentAdvancedOps as AsyncDocumentAdvancedOps, DocumentEncryptOpts,
        DocumentOps as AsyncDocumentOps,
    },
    group::{GroupCreateOpts, GroupOps as AsyncGroupOps},
    internal::{
        document_api::{
            DocumentAccessResult, DocumentDecryptResult, DocumentDecryptUnmanagedResult,
            DocumentEncryptResult, DocumentEncryptUnmanagedResult, DocumentId, DocumentListResult,
            DocumentMetadataResult, DocumentName, UserOrGroup,
        },
        group_api::{
            GroupAccessEditResult, GroupCreateResult, GroupGetResult, GroupId, GroupListResult,
            GroupMetaResult, GroupName, GroupUpdatePrivateKeyResult,
        },
        user_api::{
            DeviceId, UserCreateResult, UserDeviceListResult, UserId, UserResult,
            UserUpdatePrivateKeyResult,
        },
        DeviceContext, PublicKey,
    },
    user::{DeviceCreateOpts, UserCreateOpts, UserOps as AsyncUserOps},
    InitAndRotationCheck::{self, NoRotationNeeded, RotationNeeded},
    IronOxide, PrivateKeyRotationCheckResult,
};
use futures::executor::block_on;
use ironoxide_macros::add_async;
use std::collections::HashMap;

/// Struct that is used to make authenticated requests to the IronCore API. Instantiated with the details
/// of an account's various ids, device, and signing keys. Once instantiated all operations will be
/// performed in the context of the account provided. Identical to IronOxide but also contains a Runtime.
pub struct BlockingIronOxide {
    pub(crate) ironoxide: IronOxide,
    pub(crate) runtime: tokio::runtime::Runtime,
}

impl BlockingIronOxide {
    /// Get the `DeviceContext` instance that was used to create this SDK instance
    pub fn device(&self) -> &DeviceContext {
        &self.ironoxide.device
    }

    /// Rotate the private key of the calling user and all groups they are an administrator of where needs_rotation is true.
    /// Note that this function has the potential to take much longer than other functions, as rotation will be done
    /// individually on each user/group. If rotation is only needed for a specific group, it is strongly recommended
    /// to call [user_rotate_private_key()](user\/trait.UserOps.html#tymethod.user_rotate_private_key) or
    /// [group_rotate_private_key()](group\/trait.GroupOps.html#tymethod.group_rotate_private_key) instead.
    /// # Arguments
    /// - `rotations` - PrivateKeyRotationCheckResult that holds all users and groups to be rotated
    /// - `password` - Password to unlock the current user's user master key
    pub fn rotate_all(
        &self,
        rotations: &PrivateKeyRotationCheckResult,
        password: &str,
    ) -> Result<(
        Option<UserUpdatePrivateKeyResult>,
        Option<Vec<GroupUpdatePrivateKeyResult>>,
    )> {
        self.runtime
            .enter(|| block_on(self.ironoxide.rotate_all(rotations, password)))
    }
}

/// Creates a tokio runtime with the default number of core threads (num of cores on a machine)
/// and an elevated number of blocking_threads as we expect heavy concurrency to be network-bound
fn create_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new()
        .threaded_scheduler() // use multi-threaded scheduler
        .enable_all() // enable both I/O and time drivers
        .max_threads(250) // core_threads default to number of cores, blocking threads are max - core
        .build()
        .expect("tokio runtime failed to initialize")
}

/// Initialize the IronOxide SDK with a device. Verifies that the provided user/segment exists and the provided device
/// keys are valid and exist for the provided account. If successful, returns an instance of the IronOxide SDK
pub fn initialize(device_context: &DeviceContext) -> Result<BlockingIronOxide> {
    let rt = create_runtime();
    let maybe_io = rt.enter(|| block_on(crate::initialize(device_context)));
    maybe_io.map(|io| BlockingIronOxide {
        ironoxide: io,
        runtime: rt,
    })
}

/// Initialize the IronOxide SDK and check to see if the user that owns this `DeviceContext` is
/// marked for private key rotation, or if any of the groups that the user is an admin of is marked
/// for private key rotation.
pub fn initialize_check_rotation(
    device_context: &DeviceContext,
) -> Result<InitAndRotationCheck<BlockingIronOxide>> {
    let rt = create_runtime();
    let maybe_init = rt.enter(|| block_on(crate::initialize_check_rotation(device_context)));
    maybe_init.map(|init| match init {
        NoRotationNeeded(io) => NoRotationNeeded(BlockingIronOxide {
            ironoxide: io,
            runtime: rt,
        }),
        RotationNeeded(io, rot) => RotationNeeded(
            BlockingIronOxide {
                ironoxide: io,
                runtime: rt,
            },
            rot,
        ),
    })
}

crate::document_ops!(add_async(blocking));

impl DocumentOps for crate::blocking::BlockingIronOxide {
    fn document_list(&self) -> Result<DocumentListResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.document_list()))
    }
    fn document_get_metadata(&self, id: &DocumentId) -> Result<DocumentMetadataResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.document_get_metadata(id)))
    }
    fn document_get_id_from_bytes(&self, encrypted_document: &[u8]) -> Result<DocumentId> {
        self.runtime.enter(|| {
            block_on(
                self.ironoxide
                    .document_get_id_from_bytes(encrypted_document),
            )
        })
    }
    fn document_encrypt(
        &self,
        document_data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.document_encrypt(document_data, encrypt_opts)))
    }
    fn document_update_bytes(
        &self,
        id: &DocumentId,
        new_document_data: &[u8],
    ) -> Result<DocumentEncryptResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.document_update_bytes(id, new_document_data)))
    }
    fn document_decrypt(&self, encrypted_document: &[u8]) -> Result<DocumentDecryptResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.document_decrypt(encrypted_document)))
    }
    fn document_update_name(
        &self,
        id: &DocumentId,
        name: Option<&DocumentName>,
    ) -> Result<DocumentMetadataResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.document_update_name(id, name)))
    }
    fn document_grant_access(
        &self,
        id: &DocumentId,
        grant_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.document_grant_access(id, grant_list)))
    }
    fn document_revoke_access(
        &self,
        id: &DocumentId,
        revoke_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.document_revoke_access(id, revoke_list)))
    }
}

crate::document_advanced_ops!(add_async(blocking));

impl DocumentAdvancedOps for BlockingIronOxide {
    fn document_encrypt_unmanaged(
        &self,
        data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptUnmanagedResult> {
        self.runtime.enter(|| {
            block_on(
                self.ironoxide
                    .document_encrypt_unmanaged(data, encrypt_opts),
            )
        })
    }
    fn document_decrypt_unmanaged(
        &self,
        encrypted_data: &[u8],
        encrypted_deks: &[u8],
    ) -> Result<DocumentDecryptUnmanagedResult> {
        self.runtime.enter(|| {
            block_on(
                self.ironoxide
                    .document_decrypt_unmanaged(encrypted_data, encrypted_deks),
            )
        })
    }
}

crate::group_ops!(add_async(blocking));

impl GroupOps for BlockingIronOxide {
    fn group_list(&self) -> Result<GroupListResult> {
        self.runtime.enter(|| block_on(self.ironoxide.group_list()))
    }
    fn group_create(&self, opts: &GroupCreateOpts) -> Result<GroupCreateResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.group_create(opts)))
    }
    fn group_get_metadata(&self, id: &GroupId) -> Result<GroupGetResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.group_get_metadata(id)))
    }
    fn group_delete(&self, id: &GroupId) -> Result<GroupId> {
        self.runtime
            .enter(|| block_on(self.ironoxide.group_delete(id)))
    }
    fn group_update_name(&self, id: &GroupId, name: Option<&GroupName>) -> Result<GroupMetaResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.group_update_name(id, name)))
    }
    fn group_add_members(
        &self,
        id: &GroupId,
        grant_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.group_add_members(id, grant_list)))
    }
    fn group_remove_members(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.group_remove_members(id, revoke_list)))
    }
    fn group_add_admins(&self, id: &GroupId, users: &[UserId]) -> Result<GroupAccessEditResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.group_add_admins(id, users)))
    }
    fn group_remove_admins(
        &self,
        id: &GroupId,
        revoke_list: &[UserId],
    ) -> Result<GroupAccessEditResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.group_remove_admins(id, revoke_list)))
    }
    fn group_rotate_private_key(&self, id: &GroupId) -> Result<GroupUpdatePrivateKeyResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.group_rotate_private_key(id)))
    }
}

crate::user_ops!(add_async(blocking));

impl UserOps for BlockingIronOxide {
    fn user_create(
        jwt: &str,
        password: &str,
        user_create_opts: &UserCreateOpts,
    ) -> Result<UserCreateResult> {
        let rt = create_runtime();
        rt.enter(|| block_on(IronOxide::user_create(jwt, password, user_create_opts)))
    }
    fn user_list_devices(&self) -> Result<UserDeviceListResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.user_list_devices()))
    }
    fn generate_new_device(
        jwt: &str,
        password: &str,
        device_create_options: &DeviceCreateOpts,
    ) -> Result<DeviceContext> {
        let rt = create_runtime();
        rt.enter(|| {
            block_on(IronOxide::generate_new_device(
                jwt,
                password,
                device_create_options,
            ))
        })
    }
    fn user_delete_device(&self, device_id: Option<&DeviceId>) -> Result<DeviceId> {
        self.runtime
            .enter(|| block_on(self.ironoxide.user_delete_device(device_id)))
    }
    fn user_verify(jwt: &str) -> Result<Option<UserResult>> {
        let rt = create_runtime();
        rt.enter(|| block_on(IronOxide::user_verify(jwt)))
    }
    fn user_get_public_key(&self, users: &[UserId]) -> Result<HashMap<UserId, PublicKey>> {
        self.runtime
            .enter(|| block_on(self.ironoxide.user_get_public_key(users)))
    }
    fn user_rotate_private_key(&self, password: &str) -> Result<UserUpdatePrivateKeyResult> {
        self.runtime
            .enter(|| block_on(self.ironoxide.user_rotate_private_key(password)))
    }
}
