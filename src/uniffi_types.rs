//! UniFFI custom type converters for bridging ironoxide types to FFI-friendly representations.
//!
//! This module is only compiled when the `uniffi` feature is enabled.

use crate::internal::{
    DeviceSigningKeyPair, IronOxideErr, PrivateKey, PublicKey,
    document_api::{DocumentId, DocumentName},
    group_api::{GroupId, GroupName},
    user_api::{DeviceId, DeviceName, EncryptedPrivateKey, UserId},
};
use crate::policy::{Category, DataSubject, Sensitivity};
use time::OffsetDateTime;

// --- 3.1 Validated string newtypes (fallible conversion) ---

uniffi::custom_type!(UserId, String, {
    try_lift: |s| UserId::try_from(s).map_err(|e: IronOxideErr| e.into()),
    lower: |uid| uid.id().to_string(),
});

uniffi::custom_type!(GroupId, String, {
    try_lift: |s| GroupId::try_from(s).map_err(|e: IronOxideErr| e.into()),
    lower: |gid| gid.id().to_string(),
});

uniffi::custom_type!(DocumentId, String, {
    try_lift: |s| DocumentId::try_from(s).map_err(|e: IronOxideErr| e.into()),
    lower: |did| did.id().to_string(),
});

uniffi::custom_type!(DocumentName, String, {
    try_lift: |s| DocumentName::try_from(s).map_err(|e: IronOxideErr| e.into()),
    lower: |dn| dn.name().to_string(),
});

uniffi::custom_type!(GroupName, String, {
    try_lift: |s| GroupName::try_from(s).map_err(|e: IronOxideErr| e.into()),
    lower: |gn| gn.name().to_string(),
});

uniffi::custom_type!(DeviceName, String, {
    try_lift: |s| DeviceName::try_from(s).map_err(|e: IronOxideErr| e.into()),
    lower: |dn| dn.name().to_string(),
});

uniffi::custom_type!(Category, String, {
    try_lift: |s| Category::try_from(s).map_err(|e: IronOxideErr| e.into()),
    lower: |c| c.inner().to_string(),
});

uniffi::custom_type!(Sensitivity, String, {
    try_lift: |s| Sensitivity::try_from(s).map_err(|e: IronOxideErr| e.into()),
    lower: |s| s.inner().to_string(),
});

uniffi::custom_type!(DataSubject, String, {
    try_lift: |s| DataSubject::try_from(s).map_err(|e: IronOxideErr| e.into()),
    lower: |ds| ds.inner().to_string(),
});

// --- 3.2 Simple newtypes ---

uniffi::custom_type!(DeviceId, u64, {
    try_lift: |n| DeviceId::try_from(n).map_err(|e: IronOxideErr| e.into()),
    lower: |d| *d.id(),
});

uniffi::custom_type!(EncryptedPrivateKey, Vec<u8>, {
    try_lift: |bytes| Ok(EncryptedPrivateKey::new(bytes)),
    lower: |epk| epk.as_bytes().to_vec(),
});

// --- 3.3 Crypto key types ---

uniffi::custom_type!(PublicKey, Vec<u8>, {
    try_lift: |bytes| {
        PublicKey::try_from(bytes.as_slice()).map_err(|e: IronOxideErr| e.into())
    },
    lower: |pk| pk.as_bytes(),
});

uniffi::custom_type!(PrivateKey, Vec<u8>, {
    try_lift: |bytes| {
        PrivateKey::try_from(bytes.as_slice()).map_err(|e: IronOxideErr| e.into())
    },
    lower: |pk| pk.as_bytes().to_vec(),
});

uniffi::custom_type!(DeviceSigningKeyPair, Vec<u8>, {
    try_lift: |bytes| {
        DeviceSigningKeyPair::try_from(bytes.as_slice()).map_err(|e: IronOxideErr| e.into())
    },
    lower: |dsk| dsk.as_bytes().to_vec(),
});

// --- 3.4 OffsetDateTime ---

uniffi::custom_type!(OffsetDateTime, i64, {
    remote,
    try_lift: |ts| {
        OffsetDateTime::from_unix_timestamp(ts)
            .map_err(|e| IronOxideErr::ValidationError {
                field_name: "timestamp".into(),
                err: format!("Invalid unix timestamp: {e}"),
            }.into())
    },
    lower: |dt| dt.unix_timestamp(),
});
