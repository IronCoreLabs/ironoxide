# Changelog

## 0.10.0
- [[#27](https://github.com/IronCoreLabs/ironoxide/pull/23)]
  - DocumentAdvancedOps::document_encrypt_unmanaged function added for advanced use cases where the calling application wants to manage both the encrypted data and the associated edeks instead of using the IronCore service for EDEK management.

## 0.9.0
- [[#23](https://github.com/IronCoreLabs/ironoxide/pull/23)]
  - IronOxide no longer has mutable references in it's API, making it possible to share an IronOxide between threads.
  - The RNG used for for AES now periodically reseeds itself.

## 0.8.0

- add the ability to encrypt via policy

## 0.7.0

- add the ability to encrypt without granting to the author

## 0.6.1

- [[#1](#1)]
  - added `UserCreateKeyPair` to public API
  - added `IronOxideErr` to the `prelude`
  - added `From<IronOxideErr> for String` to lib.rs

## 0.6.0

- Initial Open Source Release
