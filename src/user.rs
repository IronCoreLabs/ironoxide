//! User API
//!
//! See [UserOps](trait.UserOps.html) for user functions and key terms.

pub use crate::internal::user_api::{
    DeviceAddResult, DeviceId, DeviceName, EncryptedPrivateKey, KeyPair, UserCreateResult,
    UserDevice, UserDeviceListResult, UserId, UserResult, UserUpdatePrivateKeyResult,
};
use crate::{
    common::{PublicKey, SdkOperation},
    internal::{add_optional_timeout, user_api, OUR_REQUEST},
    IronOxide, Result,
};
use async_trait::async_trait;
use recrypt::api::Recrypt;
use std::{collections::HashMap, convert::TryInto};

/// Options for device creation.
///
/// Default values are provided with [DeviceCreateOpts::default()](#method.default)
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DeviceCreateOpts {
    device_name: Option<DeviceName>,
}
impl DeviceCreateOpts {
    /// # Arguments
    /// - device_name
    ///   - `None` (default) - The device will be created with no name.
    ///   - `Some` - The provided name will be used as the device's name.
    pub fn new(device_name: Option<DeviceName>) -> DeviceCreateOpts {
        DeviceCreateOpts { device_name }
    }
}
impl Default for DeviceCreateOpts {
    /// Default `DeviceCreateOpts` for common use cases.
    ///
    /// The device will be created with no name.
    fn default() -> Self {
        DeviceCreateOpts::new(None)
    }
}

/// Options for user creation.
///
/// Default values are provided with [UserCreateOpts::default()](#method.default)
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UserCreateOpts {
    needs_rotation: bool,
}

impl UserCreateOpts {
    /// # Arguments
    /// - `needs_rotation` - `true` if the private key for this user marked for rotation
    pub fn new(needs_rotation: bool) -> UserCreateOpts {
        UserCreateOpts { needs_rotation }
    }
}

impl Default for UserCreateOpts {
    /// Default `UserCreateOpts` for common use cases.
    ///
    /// The user will be created with their private key not marked for rotation.
    fn default() -> Self {
        UserCreateOpts::new(false)
    }
}

/// IronOxide User Operations
///
/// # Key Terms
/// - Device - The only entity in the Data Control Platform that can decrypt data. A device is authorized using a user’s private key,
///     therefore a device is tightly bound to a user.
/// - ID - The ID representing a user or device. It must be unique within its segment and will **not** be encrypted.
/// - Password - The string used to encrypt and escrow a user's private key.
/// - Rotation - Changing a user's private key while leaving their public key unchanged. This can be accomplished by calling
///     [user_rotate_private_key](trait.UserOps.html#tymethod.user_rotate_private_key).
#[async_trait]
pub trait UserOps {
    /// Creates a user.
    ///
    /// # Arguments
    /// - `jwt`              - Valid IronCore or Auth0 JWT
    /// - `password`         - Password to use for encrypting and escrowing the user's private key
    /// - `user_create_opts` - User creation parameters. Default values are provided with
    ///      [UserCreateOpts::default()](struct.UserCreateOpts.html#method.default)
    /// - `timeout`          - Timeout for this operation or `None` for no timeout
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let jwt = "";
    /// let password = "foobar";
    /// let opts = UserCreateOpts::new(false);
    /// let user_result = IronOxide::user_create(jwt, password, &opts, None).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn user_create(
        jwt: &str,
        password: &str,
        user_create_opts: &UserCreateOpts,
        timeout: Option<std::time::Duration>,
    ) -> Result<UserCreateResult>;

    /// Generates a new device for the user specified in the JWT.
    ///
    /// This will result in a new transform key (from the user's master private key to the new device's public key)
    /// being generated and stored with the IronCore Service.
    ///
    /// # Arguments
    /// - `jwt`                   - Valid IronCore or Auth0 JWT
    /// - `password`              - Password for the user specified in the JWT
    /// - `device_create_options` - Device creation parameters. Default values are provided with
    ///      [DeviceCreateOpts::default()](struct.DeviceCreateOpts.html#method.default)
    /// - `timeout`               - Timeout for this operation or `None` for no timeout
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # use std::convert::TryFrom;
    /// # let jwt = "";
    /// let password = "foobar";
    /// let device_name = DeviceName::try_from("primary_device")?;
    /// let opts = DeviceCreateOpts::new(Some(device_name));
    /// let device_result = IronOxide::generate_new_device(jwt, password, &opts, None).await?;
    /// let device_id: &DeviceId = device_result.device_id();
    /// # Ok(())
    /// # }
    /// ```
    async fn generate_new_device(
        jwt: &str,
        password: &str,
        device_create_options: &DeviceCreateOpts,
        timeout: Option<std::time::Duration>,
    ) -> Result<DeviceAddResult>;

    /// Verifies the existence of a user using a JWT to identify their user record.
    ///
    /// Returns a `None` if the user could not be found.
    ///
    /// # Arguments
    /// - `jwt`     - Valid IronCore or Auth0 JWT
    /// - `timeout` - Timeout for this operation or `None` for no timeout
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let jwt = "";
    /// let verify_result = IronOxide::user_verify(jwt, None).await?;
    /// let user_id = verify_result.expect("User not found!").account_id();
    /// # Ok(())
    /// # }
    /// ```
    async fn user_verify(
        jwt: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<Option<UserResult>>;

    /// Lists all of the devices for the current user.
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// let devices_result = sdk.user_list_devices().await?;
    /// let devices: Vec<UserDevice> = devices_result.result().to_vec();
    /// # Ok(())
    /// # }
    /// ```
    async fn user_list_devices(&self) -> Result<UserDeviceListResult>;

    /// Gets users' public keys given their IDs.
    ///
    /// Allows discovery of which user IDs have keys in the IronCore system to help determine if they can be added to groups
    /// or have documents shared with them.
    ///
    /// Only returns users whose keys were found in the IronCore system.
    ///
    /// # Arguments
    /// - `users` - List of user IDs to check
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # use std::convert::TryFrom;
    /// # let sdk: IronOxide = unimplemented!();
    /// let user1 = UserId::try_from("colt")?;
    /// let user2 = UserId::try_from("fake_user")?;
    /// let users = [user1, user2];
    /// // This will only return one entry, for user "colt"
    /// let get_result = sdk.user_get_public_key(&users).await?;
    /// let (valid_users, invalid_users): (Vec<&UserId>, Vec<&UserId>) =
    ///     users.iter().partition(|u| get_result.contains_key(u));
    /// # Ok(())
    /// # }
    /// ```
    async fn user_get_public_key(&self, users: &[UserId]) -> Result<HashMap<UserId, PublicKey>>;

    /// Rotates the current user's private key while leaving their public key the same.
    ///
    /// There's no black magic here! This is accomplished via multi-party computation with the IronCore webservice.
    ///
    /// The main use case for this is a workflow that requires that users be generated prior to the user logging in for the first time.
    /// In this situation, a user's cryptographic identity can be generated by a third party, like a server process, and then
    /// the user can take control of their keys by rotating their private key.
    ///
    /// # Arguments
    /// `password` - Password to unlock the current user's private key
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// let password = "foobar";
    /// let rotate_result = sdk.user_rotate_private_key(password).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn user_rotate_private_key(&self, password: &str) -> Result<UserUpdatePrivateKeyResult>;

    /// Deletes a device.
    ///
    /// If deleting the currently signed-in device, the SDK will need to be
    /// re-initialized with [IronOxide::initialize](../fn.initialize.html) before further use.
    ///
    /// Returns the ID of the deleted device.
    ///
    /// # Arguments
    /// - `device_id` - ID of the device to delete. If `None`, deletes the current device
    ///
    /// # Examples
    /// ```
    /// # async fn run() -> Result<(), ironoxide::IronOxideErr> {
    /// # use ironoxide::prelude::*;
    /// # let sdk: IronOxide = unimplemented!();
    /// # let device_id: DeviceId = unimplemented!();
    /// // If successful, returns the same `DeviceId` it is passed.
    /// let deleted_device: DeviceId = sdk.user_delete_device(Some(&device_id)).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn user_delete_device(&self, device_id: Option<&DeviceId>) -> Result<DeviceId>;
}

#[async_trait]
impl UserOps for IronOxide {
    async fn user_create(
        jwt: &str,
        password: &str,
        user_create_opts: &UserCreateOpts,
        timeout: Option<std::time::Duration>,
    ) -> Result<UserCreateResult> {
        let recrypt = Recrypt::new();
        add_optional_timeout(
            user_api::user_create(
                &recrypt,
                jwt.try_into()?,
                password.try_into()?,
                user_create_opts.needs_rotation,
                *OUR_REQUEST,
            ),
            timeout,
            SdkOperation::UserCreate,
        )
        .await?
    }

    async fn generate_new_device(
        jwt: &str,
        password: &str,
        device_create_options: &DeviceCreateOpts,
        timeout: Option<std::time::Duration>,
    ) -> Result<DeviceAddResult> {
        let recrypt = Recrypt::new();

        let device_create_options = device_create_options.clone();

        add_optional_timeout(
            user_api::generate_device_key(
                &recrypt,
                &jwt.try_into()?,
                password.try_into()?,
                device_create_options.device_name,
                &std::time::SystemTime::now().into(),
                &OUR_REQUEST,
            ),
            timeout,
            SdkOperation::GenerateNewDevice,
        )
        .await?
    }

    async fn user_verify(
        jwt: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<Option<UserResult>> {
        add_optional_timeout(
            user_api::user_verify(jwt.try_into()?, *OUR_REQUEST),
            timeout,
            SdkOperation::UserVerify,
        )
        .await?
    }

    async fn user_list_devices(&self) -> Result<UserDeviceListResult> {
        add_optional_timeout(
            user_api::device_list(self.device.auth()),
            self.config.sdk_operation_timeout,
            SdkOperation::UserListDevices,
        )
        .await?
    }

    async fn user_get_public_key(&self, users: &[UserId]) -> Result<HashMap<UserId, PublicKey>> {
        add_optional_timeout(
            user_api::user_key_list(self.device.auth(), &users.to_vec()),
            self.config.sdk_operation_timeout,
            SdkOperation::UserGetPublicKey,
        )
        .await?
    }

    async fn user_rotate_private_key(&self, password: &str) -> Result<UserUpdatePrivateKeyResult> {
        add_optional_timeout(
            user_api::user_rotate_private_key(
                &self.recrypt,
                password.try_into()?,
                self.device().auth(),
            ),
            self.config.sdk_operation_timeout,
            SdkOperation::UserRotatePrivateKey,
        )
        .await?
    }

    async fn user_delete_device(&self, device_id: Option<&DeviceId>) -> Result<DeviceId> {
        add_optional_timeout(
            user_api::device_delete(self.device.auth(), device_id),
            self.config.sdk_operation_timeout,
            SdkOperation::UserDeleteDevice,
        )
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galvanic_assert::{matchers::*, *};

    #[test]
    fn user_create_opts_defaults() {
        let opts = UserCreateOpts::default();
        assert_that!(
            &opts,
            has_structure!(UserCreateOpts {
                needs_rotation: eq(false)
            })
        )
    }
    #[test]
    fn user_create_opts_new() {
        let opts = UserCreateOpts::new(true);
        assert_that!(
            &opts,
            has_structure!(UserCreateOpts {
                needs_rotation: eq(true)
            })
        )
    }
}
