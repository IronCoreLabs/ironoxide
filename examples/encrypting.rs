use anyhow::Result;
use ironoxide::prelude::*;
use std::{fs::File, path::PathBuf};

/// This is a very basic example of encrypting to a user_id and a group_id.
/// The group that's encrypted to is created each run, but the user is just the current user.
#[tokio::main]
async fn main() -> Result<()> {
    let (device_context, sdk) =
        initialize_sdk_from_file(&PathBuf::from("examples/example-ironoxide-user.json")).await?;
    encrypt_to_group(&sdk).await?;
    encrypt_to_user(&sdk, device_context.account_id()).await?;
    Ok(())
}
///Create a random group and encrypt the super secret message to it.
async fn encrypt_to_group(sdk: &IronOxide) -> Result<DocumentId> {
    // start-snippet{encryptToGroup}
    let group_id = create_group(sdk).await?;
    let message = "This is my secret which a whole group should see.";
    let encrypted_result = sdk
        .document_encrypt(
            message.as_bytes(),
            &DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![(&group_id).into()]),
        )
        .await?;
    // end-snippet{encryptToGroup}
    println!("Encrypted to group {}", group_id.id());
    Ok(encrypted_result.id().clone())
}

async fn encrypt_to_user(sdk: &IronOxide, user_id: &UserId) -> Result<DocumentId> {
    // start-snippet{encryptToUser}
    let message = "This is my secret for a single user.";
    let encrypted_result = sdk
        .document_encrypt(
            message.as_bytes(),
            &DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![user_id.into()]),
        )
        .await?;
    // end-snippet{encryptToUser}
    println!("Encrypted to user {}", user_id.id());

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
        panic!(format!(
            "Couldn't open file {} containing DeviceContext",
            device_path.display()
        )
        .to_string(),)
    }
}

async fn create_group(sdk: &IronOxide) -> Result<GroupId> {
    let result = sdk.group_create(&Default::default()).await?;
    Ok(result.id().clone())
}
