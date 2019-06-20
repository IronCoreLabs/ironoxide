pub use crate::internal::user_api::{
    UserCreateKeyPair, UserDevice, UserDeviceListResult, UserId, UserVerifyResult,
};
use crate::{
    internal::{
        user_api::{self, DeviceId, DeviceName},
        PublicKey, OUR_REQUEST,
    },
    DeviceContext, IronOxide, Result,
};
use recrypt::api::Recrypt;
use std::{collections::HashMap, convert::TryInto};
use tokio::runtime::current_thread::Runtime;

/// Optional parameters for creating a new device instance.
#[derive(Debug, PartialEq, Clone)]
pub struct DeviceCreateOpts {
    device_name: Option<DeviceName>,
}
impl DeviceCreateOpts {
    /// Create a new device with an optional readable name for the device.
    pub fn new(device_name: Option<DeviceName>) -> DeviceCreateOpts {
        DeviceCreateOpts { device_name }
    }
}
impl Default for DeviceCreateOpts {
    fn default() -> Self {
        DeviceCreateOpts::new(None)
    }
}

pub trait UserOps {
    /// Sync a new user within the IronCore system.
    ///
    /// # Arguments
    /// - `jwt` - Valid IronCore or Auth0 JWT
    /// - `password` - Password used to encrypt and escrow the user's private master key
    ///
    /// # Returns
    /// Newly generated `UserCreateKeyPair` or Err. For most use cases this key pair can
    /// be discarded as IronCore escrows your user's keys. The escrowed keys are unlocked
    /// by the provided password.
    fn user_create(jwt: &str, password: &str) -> Result<UserCreateKeyPair>;

    /// Get all the devices for the current user
    ///
    /// # Returns
    /// All devices for the current user, sorted by the device id.
    fn user_list_devices(&self) -> Result<UserDeviceListResult>;

    /// Generates a new device for the user specified in the signed JWT.
    ///
    /// This will result in a new transform key (from the user's master private key to the new device's public key)
    /// being generated and stored with the IronCore Service.
    ///
    /// # Arguments
    /// - `jwt`                   - Valid IronCore JWT
    /// - `password`              - Password used to encrypt and escrow the user's private key
    /// - `device_create_options` - Optional device create arguments, like device name
    ///
    /// # Returns
    /// Details about the newly created device.
    fn generate_new_device(
        jwt: &str,
        password: &str,
        device_create_options: &DeviceCreateOpts,
    ) -> Result<DeviceContext>;

    /// Delete a user device.
    ///
    /// If deleting the currently signed in device (None for `device_id`), the sdk will need to be
    /// reinitialized with `IronOxide.initialize()` before further use.
    ///
    /// # Arguments
    /// - `device_id` - ID of the device to delete. Get from `user_list_devices`. If None, deletes the currently SDK contexts device which
    ///                 once deleted will cause this SDK instance to no longer function.
    ///
    /// # Returns
    /// Id of deleted device or IronOxideErr
    fn user_delete_device(&self, device_id: Option<&DeviceId>) -> Result<DeviceId>;

    /// Verify a user given a JWT for their user record.
    ///
    /// # Arguments
    /// - `jwt` - Valid IronCore JWT
    ///
    /// # Returns
    /// Option of whether the users account record exists in the IronCore system or not. Err if the request couldn't be made.
    fn user_verify(jwt: &str) -> Result<Option<UserVerifyResult>>;

    /// Get a list of user public keys given their IDs. Allows discovery of which user IDs have keys in the
    /// IronCore system to determine of they can be added to groups or have documents shared with them.
    ///
    /// # Arguments
    /// - users - List of user IDs to check
    ///
    /// # Returns
    /// Map from user ID to users public key. Only users who have public keys will be returned in the map.
    fn user_get_public_key(&self, users: &[UserId]) -> Result<HashMap<UserId, PublicKey>>;
}
impl UserOps for IronOxide {
    fn user_verify(jwt: &str) -> Result<Option<UserVerifyResult>> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(user_api::user_verify(jwt.try_into()?, OUR_REQUEST))
    }

    fn user_create(jwt: &str, password: &str) -> Result<UserCreateKeyPair> {
        let recrypt = Recrypt::new();
        let mut rt = Runtime::new().unwrap();
        rt.block_on(user_api::user_create(
            &recrypt,
            jwt.try_into()?,
            password.try_into()?,
            OUR_REQUEST,
        ))
    }

    fn generate_new_device(
        jwt: &str,
        password: &str,
        device_create_options: &DeviceCreateOpts,
    ) -> Result<DeviceContext> {
        let recrypt = Recrypt::new();
        let mut rt = Runtime::new().unwrap();
        let device_create_options = device_create_options.clone();

        rt.block_on(user_api::generate_device_key(
            &recrypt,
            &jwt.try_into()?,
            password.try_into()?,
            device_create_options.device_name,
            &std::time::SystemTime::now().into(),
            OUR_REQUEST,
        ))
    }

    fn user_get_public_key(&self, users: &[UserId]) -> Result<HashMap<UserId, PublicKey>> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(user_api::user_key_list(self.device.auth(), &users.to_vec()))
    }

    fn user_list_devices(&self) -> Result<UserDeviceListResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(user_api::device_list(self.device.auth()))
    }

    fn user_delete_device(&self, device_id: Option<&DeviceId>) -> Result<DeviceId> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(user_api::device_delete(self.device.auth(), device_id))
    }
}
