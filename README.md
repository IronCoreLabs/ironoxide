# IronOxide- IronCore Labs Rust SDK

[![](https://img.shields.io/crates/v/ironoxide.svg)](https://crates.io/crates/ironoxide) [![](https://docs.rs/ironoxide/badge.svg)](https://docs.rs/ironoxide)
[![](https://github.com/IronCoreLabs/ironoxide/workflows/CI/badge.svg)](https://github.com/IronCoreLabs/ironoxide/actions)

IronOxide is an SDK for accessing IronCore's privacy platform. It is appropriate for both client and server applications.

## Usage

To include IronOxide in your Rust application, see https://crates.io/crates/ironoxide for the most recent version.

If you are not building a Rust application, you might be interested in one of these SDKs:

- [ironoxide-java](https://github.com/IronCoreLabs/ironoxide-java) - Java bindings for ironoxide. Appropriate for all JVM languages.
- [ironoxide-scala](https://github.com/IronCoreLabs/ironoxide-scala) - Scala wrappers around `ironoxide-java`.
- [ironnode](https://github.com/IronCoreLabs/ironnode) - NodeJS implementation of IronCore's Privacy Platform.
- [ironweb](https://github.com/IronCoreLabs/ironweb) - Javascript implementation of IronCore's Privacy Platform. Appropriate for all modern browsers.

All SDKs are intended to be compatible with one another.

## API Docs and Example Usage

Please see https://ironoxide.rs

## Contributing

IronCore welcomes community participation through the issue tracker or pull request process.

#### Building

Rust (stable) and [libstd](https://doc.rust-lang.org/std/) required.

`cargo build`

It may be possible to build with `no_std`, but we haven't looked at this.
We test on a variety of architectures (including Linux-x86_64 MacOSX-x86_64, IOS-aarch64, Android-aarch64), and should generally work anywhere Rust stable works.

#### Running Unit Tests

IronCore has integration tests that are not runnable by the public. If you are interested in the results, [CI runs the integration tests (every test file with *_ops in its name)](https://github.com/IronCoreLabs/ironoxide/actions/workflows/ci.yaml). If you think you need to run the integration tests on a development machine, please open an issue.

To run the unit test suite, use:

`cargo t --lib`

## Benchmarks

- `./benches/data` files must be decrypted with `ironhide`. Contact us if you'd like to be added to the decryption group.

Run the benchmark set with

```
cargo bench
```

## Cryptography Notice

This repository includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted. See https://www.wassenaar.org/ for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002, which includes information security software using or performing cryptographic functions. The form and manner of this distribution makes it eligible for export under the License Exception ENC (see the BIS Export Administration Regulations, Section 740.17.B.3.i.B and also the publicly available source code exemption, under 742.15; notice has been given to BIS and NSA).

## License

IronOxide is licensed under the [GNU Affero General Public License](LICENSE).
We also offer commercial licenses - [email](mailto:info@ironcorelabs.com) for more information.

Copyright (c) 2024 IronCore Labs, Inc.
All rights reserved.
