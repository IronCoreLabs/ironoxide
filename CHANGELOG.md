# Changelog

## 0.14.0 (Unreleased)

- [[#76](https://github.com/IronCoreLabs/ironoxide/pull/76)]
  - Allows adding admins at group creation time.
  - Allows specifying an owner at group creation time.
- [[#72](https://github.com/IronCoreLabs/ironoxide/pull/72)]
  - Allows adding members at group creation time.
- [[#69](https://github.com/IronCoreLabs/ironoxide/pull/69)]
  - Allows changing of IronCore environment at runtime.
- [[#64](https://github.com/IronCoreLabs/ironoxide/pull/64)]
  - Adds need_rotation to `GroupCreateOpts`, allowing a group to be created with its private key marked for rotation.

## 0.13.0

- [[#59](https://github.com/IronCoreLabs/ironoxide/pull/59)]
  - Adds method UserOps::user_rotate_private_key
  - Adds a new initialization option: ironoxide::initialize_check_rotation to enable users to know if any of their private keys need rotation.
  - Renames `user::UserVerifyResult` -> `user::UserResult`

## 0.12.1

- [[#56](https://github.com/IronCoreLabs/ironoxide/pull/56)]
  - Added `needs_rotation` as an `Option<bool>` to `GroupMetaResult`, `GroupGetResult`, `GroupBasicApiResponse`, and `GroupGetApiResponse`.

## 0.12.0

- [[#52](https://github.com/IronCoreLabs/ironoxide/pull/52)]
  - Added `device_id` as a parameter to `DeviceContext::new`, renamed other parameters.
  - Changed Serialization/Deserialization of `DeviceContext`.

## 0.11.0

- Added `TryFrom<&[u8]>` for `PublicKey`
- `UserCreateKeyPair` has been renamed to `UserCreateResult`
- [[#35](https://github.com/IronCoreLabs/ironoxide/pull/35)]
  - Clarified documentation for several struct parameters.
- [[#43](https://github.com/IronCoreLabs/ironoxide/pull/43)]
  - Users can now be created with a `needs_rotation` flag set.
- [[#47](https://github.com/IronCoreLabs/ironoxide/pull/47)]
  - `UserVerifyResult` now contains `needs_rotation` for the user.

## 0.10.1

- [[#32](https://github.com/IronCoreLabs/ironoxide/pull/32)]
  - DocumentAdvancedOps::document_decrypt_unmanaged function added for advanced use cases. This decrypt operation is the inverse of DocumentAdvancedOps::document_encrypt_unmanaged

## 0.10.0

- [[#27](https://github.com/IronCoreLabs/ironoxide/pull/27)]
  - DocumentAdvancedOps::document_encrypt_unmanaged function added for advanced use cases where the calling application wants to manage both the encrypted data and the associated edeks instead of using the IronCore service for EDEK management.

## 0.9.0

- [[#23](https://github.com/IronCoreLabs/ironoxide/pull/23)]
  - IronOxide no longer has mutable references in its API, making it possible to share an IronOxide between threads.
  - The RNG used for AES now periodically reseeds itself.

## 0.8.0

- Added the ability to encrypt via policy.

## 0.7.0

- Added the ability to encrypt without granting to the author.

## 0.6.1

- [[#1](https://github.com/IronCoreLabs/ironoxide/pull/1)]
  - added `UserCreateKeyPair` to public API
  - added `IronOxideErr` to the `prelude`
  - added `From<IronOxideErr> for String` to lib.rs

## 0.6.0

- Initial Open Source Release
