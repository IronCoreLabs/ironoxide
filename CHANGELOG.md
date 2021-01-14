# Changelog

## 0.25.1

- [[#216](https://github.com/IronCoreLabs/ironoxide/pull/216)] Fix compatibility with serde 1.0.119

## 0.25.0

- [[#209](https://github.com/IronCoreLabs/ironoxide/pull/209)] Update to itertools 0.10.0
- [[#211](https://github.com/IronCoreLabs/ironoxide/pull/211)] Update to dashmap 4.0.1
- [[#213](https://github.com/IronCoreLabs/ironoxide/pull/213)]
  - Update to tokio 1.0
  - Update to reqwest 0.11.0
  - Update to bytes 1.0
  - Require minimum protobuf of 2.20.0
- [[#215](https://github.com/IronCoreLabs/ironoxide/pull/215)]
  - Update to recrypt 0.12.0
  - Bump MSRV to 1.41.1

## 0.24.0

- [[#183](https://github.com/IronCoreLabs/ironoxide/pull/183)]
  - Update to rust-protobuf 2.17
- [[#193](https://github.com/IronCoreLabs/ironoxide/pull/193)]
  - Relax rust-protobuf dependency requirement. This should allow downstream consumers more freedom in what rust-protobuf version they are using.
- [[#196](https://github.com/IronCoreLabs/ironoxide/pull/196)]
  - Add group encrypt benchmarks
- Various non-breaking dependency updates

## 0.23.1

- [[#170](https://github.com/IronCoreLabs/ironoxide/pull/170)]
  - Update `JwtClaims` struct to handle "http://ironcore/" namespace prefix on private claims
  - Add optional `uid` claim that is added by Auth0
  - Change type of `pid` and `kid` fields in claims from `usize` to `u32`
- [[#177](https://github.com/IronCoreLabs/ironoxide/pull/177)]
  - Add explicit `type_length_limit` because as of Rust 1.46.0, the default wasn't sufficient
  - Update dependencies

## 0.23.0

- [[#164](https://github.com/IronCoreLabs/ironoxide/pull/164)] [[#168](https://github.com/IronCoreLabs/ironoxide/pull/168)]
  - Add `Jwt` struct that validates JWT algorithm and payload form
  - Add `JwtClaims` struct to help form a valid `Jwt` payload
  - Change `user_create`, `user_verify`, and `generate_new_device` to use new `Jwt` struct

## 0.22.0

- [[#142](https://github.com/IronCoreLabs/ironoxide/pull/142)]
  - Significant changes to organization of structs
    - Add `ironoxide::common` module to hold structs that span modules
    - Add all structs and traits to `ironoxide::prelude`
    - Move `DeviceId`, `DeviceName`, `DeviceAddResult`, and `KeyPair` to `ironoxide::user` module
    - Move `DocumentId` and `DocumentName` to `ironoxide::document` module
- [[#148](https://github.com/IronCoreLabs/ironoxide/pull/148)]
  - Add serde support for `EncryptedBlindSearchIndex`
  - Expose `transliterate_string` function
- [[#155](https://github.com/IronCoreLabs/ironoxide/pull/155)]
  - Upgrade dependencies
- [[#156](https://github.com/IronCoreLabs/ironoxide/pull/156)]
  - `proto` module is no longer `pub` as it is only used internally
- [[#139](https://github.com/IronCoreLabs/ironoxide/pull/139)] [[#152](https://github.com/IronCoreLabs/ironoxide/pull/152)]
  [[#154](https://github.com/IronCoreLabs/ironoxide/pull/154)] [[#158](https://github.com/IronCoreLabs/ironoxide/pull/158)]
  - Improve documentation throughout crate

## 0.21.1

- [[#138](https://github.com/IronCoreLabs/ironoxide/pull/138)]
  - Remove `publicsuffix` default features (openssl-sys)
- [[#129](https://github.com/IronCoreLabs/ironoxide/pull/129)]
  - Improve error message for SDK initialization failure
- [[#132](https://github.com/IronCoreLabs/ironoxide/pull/132)]
  - Add feature flags to enable alternative TLS linking and implementations

## 0.21.0

- [[#126](https://github.com/IronCoreLabs/ironoxide/pull/126)]
  - Upgrade dependencies (`rand`, `rand_chacha`, `recrypt`)
- [[#118](https://github.com/IronCoreLabs/ironoxide/pull/118)]
  - Introduce `search` module with ability to create blind indexes. (behind beta flag)

## 0.20.0

- [[#119](https://github.com/IronCoreLabs/ironoxide/pull/119)]
  - Add `Clone`, `Debug`, `Eq`, `Hash`, and `PartialEq` to almost all public structs.
  - Upgrade to itertools 0.9.0
- [[#123](https://github.com/IronCoreLabs/ironoxide/pull/123)]
  - Add better error message for missing policy

## 0.19.1

- [[#120](https://github.com/IronCoreLabs/ironoxide/pull/120)]
  - Add `clear_policy_cache()` to `BlockingIronOxide`.

## 0.19.0

- [[#114](https://github.com/IronCoreLabs/ironoxide/pull/114)]
  - Adds timeouts to all public API methods. Most timeouts use a top-level config set in IronOxideConfig. Some special cases allow for passing an optional timeout directly (rotate_all, user_create, user_verify, generate_new_device). Timeouts apply to both IronOxide and BlockingIronOxide
  - Configs can now be set on BlockingIronOxide. Before, defaults were always used.
  - Trying out an "open" struct for all config objects to allow for easier construction and access
  - Adds dependency on tokio/rt-threaded feature flag

## 0.18.0

- [[#112](https://github.com/IronCoreLabs/ironoxide/pull/112)]
  - Make the default API async
  - Add feature flag `blocking` to enable the sync API
- [[#111](https://github.com/IronCoreLabs/ironoxide/pull/111)]
  - Adds simple policy caching
- [[#108](https://github.com/IronCoreLabs/ironoxide/pull/108)]
  - Fix bug to allow decryption of 0 and 1 byte documents

## 0.17.0

- [[#107](https://github.com/IronCoreLabs/ironoxide/pull/107)]
  - Change `generate_new_device()` to return a `DeviceAddResult`
- [[#101](https://github.com/IronCoreLabs/ironoxide/pull/101)]
  - Dependency upgrades

## 0.16.0

- [[#98](https://github.com/IronCoreLabs/ironoxide/pull/98)]
  - Removes `device_id` from RequestAuth and DeviceContext::new()

## 0.15.0

- [[#94](https://github.com/IronCoreLabs/ironoxide/pull/94)]
  - Adds rotate_all() to `PrivateKeyRotationCheckResult`
  - Adds id() to `GroupUpdatePrivateKeyResult`
- [[#91](https://github.com/IronCoreLabs/ironoxide/pull/91)]
  - Adds simple sharing of tokio runtime across device authenticated SDK calls
- [[#90](https://github.com/IronCoreLabs/ironoxide/pull/90)]
  - Adds method GroupOps::group_rotate_private_key

## 0.14.0

- [[#81](https://github.com/IronCoreLabs/ironoxide/pull/81)][[#80](https://github.com/IronCoreLabs/ironoxide/pull/80)][[#77](https://github.com/IronCoreLabs/ironoxide/pull/77)]
  - internal group api to async/await syntax
  - internal document api to async/await syntax
  - internal user api to async/await syntax
  - Tokio 0.2.0-alpha.2 upgrade
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
