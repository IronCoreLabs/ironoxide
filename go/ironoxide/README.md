# ironoxide-go

Go bindings for [IronOxide](https://github.com/IronCoreLabs/ironoxide), IronCore Labs' Rust SDK for accessing the IronCore privacy platform.

These bindings are auto-generated from the Rust SDK using [UniFFI](https://mozilla.github.io/uniffi-rs/) and [uniffi-bindgen-go](https://github.com/NordSecurity/uniffi-bindgen-go). They provide a blocking (synchronous) API for user, group, and document operations.

## Prerequisites

- **Go** 1.21 or later
- **C compiler** (cgo is used to link the native library)
- **Pre-built `libironoxide` shared library** for your platform, or the Rust toolchain to build it from source

## Getting the native library

### Build from source

```bash
# Clone the repository
git clone https://github.com/IronCoreLabs/ironoxide.git
cd ironoxide

# Build the shared library with the uniffi feature
cargo build --release --features uniffi

# The library will be at:
#   macOS:  target/release/libironoxide.dylib
#   Linux:  target/release/libironoxide.so
```

### Pre-built binaries

Check the [releases page](https://github.com/IronCoreLabs/ironoxide/releases) for pre-built shared libraries for common platforms.

## Installation

1. Copy the shared library (`libironoxide.dylib` or `libironoxide.so`) to a location on your system (e.g., `/usr/local/lib`).

2. Generate the Go bindings (or use the pre-generated ones from a release):

   ```bash
   cargo run --features uniffi --bin uniffi-bindgen-go -- \
     --library target/release/libironoxide.dylib \
     --out-dir go/ \
     --config uniffi.toml
   ```

3. Add the generated `ironoxide` package to your Go project. You can either copy the generated files or use a Go module reference.

4. Set `CGO_LDFLAGS` to point to the shared library when building:

   ```bash
   CGO_LDFLAGS="-L/path/to/lib -lironoxide" go build ./...
   ```

   Or set the library path via `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS) at runtime.

## Quick start

```go
package main

import (
    "fmt"
    "github.com/IronCoreLabs/ironoxide-go/ironoxide"
)

func main() {
    // Create SDK configuration
    cachingConfig := ironoxide.NewPolicyCachingConfig(128)
    timeout := uint64(30000) // 30 seconds
    config := ironoxide.NewIronOxideConfig(cachingConfig, &timeout)

    // Create a device context from your device credentials
    deviceContext := ironoxide.NewDeviceContext(
        ironoxide.UserId("user@example.com"),
        1, // segment ID
        devicePrivateKeyBytes,  // []byte, 32 bytes
        signingKeyPairBytes,    // []byte, 64 bytes
    )

    // Initialize the blocking SDK
    blockingCtx := ironoxide.NewBlockingDeviceContext(deviceContext)
    sdk, err := ironoxide.BlockingInitialize(blockingCtx, config)
    if err != nil {
        panic(err)
    }

    // Encrypt a document
    data := []byte("sensitive data")
    opts := ironoxide.DocumentEncryptOptsWithExplicitGrants(nil, nil, true, nil)
    result, err := sdk.DocumentEncrypt(data, opts)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Encrypted document %s (%d bytes)\n",
        result.Id(), len(result.EncryptedData()))

    // Decrypt the document
    decrypted, err := sdk.DocumentDecrypt(result.EncryptedData())
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted: %s\n", string(decrypted.DecryptedData()))
}
```

## API overview

### Initialization

| Function | Description |
|----------|-------------|
| `BlockingInitialize` | Initialize the SDK with a device |
| `BlockingInitializeWithPublicKeys` | Initialize with cached public keys for offline encryption |
| `BlockingInitializeCheckRotation` | Initialize and check for needed key rotations |

### User operations

| Function | Description |
|----------|-------------|
| `BlockingUserCreate` | Create a new user |
| `BlockingUserVerify` | Verify a user exists |
| `BlockingGenerateNewDevice` | Generate a new device for a user |
| `sdk.UserListDevices()` | List a user's devices |
| `sdk.UserDeleteDevice()` | Delete a device |
| `sdk.UserRotatePrivateKey()` | Rotate a user's private key |
| `sdk.UserGetPublicKey()` | Get public keys for users |

### Document operations

| Function | Description |
|----------|-------------|
| `sdk.DocumentEncrypt()` | Encrypt data |
| `sdk.DocumentDecrypt()` | Decrypt data |
| `sdk.DocumentList()` | List accessible documents |
| `sdk.DocumentGetMetadata()` | Get document metadata |
| `sdk.DocumentGrantAccess()` | Grant access to users/groups |
| `sdk.DocumentRevokeAccess()` | Revoke access from users/groups |
| `sdk.DocumentUpdateBytes()` | Re-encrypt with new data |
| `sdk.DocumentUpdateName()` | Update document name |

### Group operations

| Function | Description |
|----------|-------------|
| `sdk.GroupCreate()` | Create a group |
| `sdk.GroupList()` | List groups |
| `sdk.GroupGetMetadata()` | Get group metadata |
| `sdk.GroupDelete()` | Delete a group |
| `sdk.GroupAddMembers()` | Add members to a group |
| `sdk.GroupRemoveMembers()` | Remove members from a group |
| `sdk.GroupAddAdmins()` | Add admins to a group |
| `sdk.GroupRemoveAdmins()` | Remove admins from a group |
| `sdk.GroupRotatePrivateKey()` | Rotate a group's private key |

### File operations

| Function | Description |
|----------|-------------|
| `sdk.DocumentFileEncrypt()` | Encrypt a file on disk |
| `sdk.DocumentFileDecrypt()` | Decrypt a file on disk |

## Testing

### Prerequisites

All test commands assume you have already built the native library (`cargo build --release --features uniffi`) and are running from the repo root inside the Nix dev shell (or have Go and a C compiler available).

```bash
# Enter the Nix dev shell (provides Go, Rust, pkg-config, etc.)
nix develop

# Set cgo linker flags and runtime library path
export CGO_LDFLAGS="-L$(pwd)/target/release -lironoxide"
export DYLD_LIBRARY_PATH="$(pwd)/target/release"  # macOS
# export LD_LIBRARY_PATH="$(pwd)/target/release"  # Linux
```

### Unit tests

Unit tests verify type construction, option builders, and error handling without requiring network access or credentials.

```bash
cd go/
go test ./... -v -count=1 -skip TestIntegration
```

### Integration tests

Integration tests create real users, devices, groups, and documents against the IronCore service. They require:

1. **Test config files** in `tests/testkeys/`:
   - `ironcore-config-stage.json` (or `ironcore-config-prod.json`) — project/segment/key IDs
   - `iak-stage.pem` (or `iak-prod.pem`) — Identity Assertion Key for signing JWTs

2. **Environment variable** `IRONCORE_ENV` set to `stage` or `prod` (defaults to `prod`).

```bash
cd go/
export IRONCORE_ENV=stage

# Run only integration tests
go test ./... -v -count=1 -run TestIntegration

# Run all tests (unit + integration)
go test ./... -v -count=1
```

If the test config files are not present, integration tests are automatically skipped.

## Type mappings

IronOxide types are mapped to Go as follows:

| Rust type | Go type |
|-----------|---------|
| `UserId`, `GroupId`, `DocumentId`, etc. | `string` |
| `DeviceId` | `uint64` |
| `PublicKey`, `PrivateKey`, `DeviceSigningKeyPair` | `[]byte` |
| `OffsetDateTime` | `int64` (unix timestamp, seconds) |
| `IronOxideErr` | `error` |
| Result types (e.g., `DocumentEncryptResult`) | Pointer to struct with getter methods |

## License

[GNU Affero General Public License](https://github.com/IronCoreLabs/ironoxide/blob/main/LICENSE). Commercial licenses available -- contact info@ironcorelabs.com.
