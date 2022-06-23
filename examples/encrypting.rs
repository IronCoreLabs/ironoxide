use anyhow::Result;
use ironoxide::prelude::*;
use std::convert::TryFrom;
use std::{fs::File, path::PathBuf};

/// This is a very basic example of encrypting to a user_id and a group_id.
/// The group that's encrypted to is created each run, but the user is just the current user.
#[tokio::main]
async fn main() -> Result<()> {
    let (device_context, sdk) =
        initialize_sdk_from_file(&"examples/example-ironoxide-device.json".into()).await?;
    encrypt_to_group(&sdk).await?;
    encrypt_to_user(&sdk, device_context.account_id()).await?;
    encrypt_with_policy(&sdk).await?;
    Ok(())
}
/// Create a group, asking the SDK to generate a unique ID for it.
async fn encrypt_to_group(sdk: &IronOxide) -> Result<DocumentId> {
    // start-snippet{encryptToGroup}
    let group_id = create_group(sdk).await?;
    let message = "This is my secret which a whole group should see.".to_string();
    let encrypted_result = sdk
        .document_encrypt(
            message.into_bytes(),
            DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![(&group_id).into()]),
        )
        .await?;
    // end-snippet{encryptToGroup}
    println!("Encrypted to group {}", group_id.id());
    Ok(encrypted_result.id().clone())
}

async fn encrypt_to_user(sdk: &IronOxide, user_id: &UserId) -> Result<DocumentId> {
    // start-snippet{encryptToUser}
    let message = "This is my secret for a single user.".to_string();
    let encrypted_result = sdk
        .document_encrypt(
            message.into_bytes(),
            DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![user_id.into()]),
        )
        .await?;
    // end-snippet{encryptToUser}
    println!("Encrypted to user {}", user_id.id());

    Ok(encrypted_result.id().clone())
}

async fn encrypt_with_policy(sdk: &IronOxide) -> Result<DocumentId> {
    // start-snippet{encrypt_with_policy}
    let message = "this is my secret which has some labels.".to_string();
    let data_labels = PolicyGrant::new(
        Some(Category::try_from("PII")?),
        Some(Sensitivity::try_from("PRIVATE")?),
        None,
        None,
    );
    let encrypted_result = sdk
        .document_encrypt(
            message.into_bytes(),
            DocumentEncryptOpts::with_policy_grants(None, None, data_labels),
        )
        .await?;
    //end-snippet{encrypt_with_policy}
    println!("Encrypted with policy with labels PRIVATE/PII");
    Ok(encrypted_result.id().clone())
}

/// Load the device context and use it to initialize ironoxide.
/// If the file cannot be found, this function will panic.
async fn initialize_sdk_from_file(device_path: &PathBuf) -> Result<(DeviceContext, IronOxide)> {
    if device_path.is_file() {
        let device_context_file = File::open(&device_path)?;
        let device_context: DeviceContext = serde_json::from_reader(device_context_file)?;
        let ironoxide = ironoxide::initialize(&device_context, &Default::default()).await?;
        Ok((device_context, ironoxide))
    } else {
        panic!(
            "Couldn't open file {} containing DeviceContext",
            device_path.display()
        )
    }
}

async fn create_group(sdk: &IronOxide) -> Result<GroupId> {
    let result = sdk.group_create(GroupCreateOpts::default()).await?;
    Ok(result.id().clone())
}
