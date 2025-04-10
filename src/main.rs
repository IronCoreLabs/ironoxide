use futures::stream::{self, StreamExt};
use ironoxide::{
    IronOxide, IronOxideErr,
    config::IronOxideConfig,
    prelude::DocumentOps,
    user::{Jwt, JwtClaims, UserCreateOpts, UserId, UserOps},
};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::{env, time::Instant};
use uuid::Uuid;

pub const USER_PASSWORD: &str = "foo";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    project_id: u32,
    segment_id: String,
    identity_assertion_key_id: u32,
}

lazy_static! {
    pub static ref ENV: String = match std::env::var("IRONCORE_ENV") {
        Ok(url) => match url.to_lowercase().as_ref() {
            "stage" => "-stage",
            "prod" => "-prod",
            _ => "",
        },
        _ => "-prod",
    }
    .to_string();
    static ref KEYPATH: (String, std::path::PathBuf) = {
        let mut path = std::env::current_dir().unwrap();
        let filename = format!("iak{}.pem", *ENV);
        path.push("tests");
        path.push("testkeys");
        path.push(filename.clone());
        (filename, path)
    };
    static ref IRONCORE_CONFIG_PATH: (String, std::path::PathBuf) = {
        let mut path = std::env::current_dir().unwrap();
        let filename = format!("ironcore-config{}.json", *ENV);
        path.push("tests");
        path.push("testkeys");
        path.push(filename.clone());
        (filename, path)
    };
    static ref CONFIG: Config = {
        use std::{fs::File, io::Read};
        let mut file = File::open(IRONCORE_CONFIG_PATH.1.clone()).unwrap_or_else(|err| {
            panic!(
                "Failed to open config file ({}) with error '{}'",
                IRONCORE_CONFIG_PATH.0, err
            )
        });
        let mut json_config = String::new();
        file.read_to_string(&mut json_config).unwrap_or_else(|err| {
            panic!(
                "Failed to read config file ({}) with error '{}'",
                IRONCORE_CONFIG_PATH.0, err
            )
        });
        serde_json::from_str(&json_config).unwrap_or_else(|err| {
            panic!(
                "Failed to deserialize config file ({}) with error '{}'",
                IRONCORE_CONFIG_PATH.0, err
            )
        })
    };
}

async fn time_future<F, T, E>(future: F) -> (Result<T, E>, std::time::Duration)
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let start = Instant::now();
    let result = future.await;
    let duration = start.elapsed();
    (result, duration)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let stream_size: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5000);
    let buffer_size: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
    println!(
        "Args: {:?}. Concurrent req: {}, Batch Size: {}",
        args, buffer_size, stream_size
    );
    let sdk = initialize_sdk().await?;

    let doc = [43u8; 64];
    let encrypted_doc = sdk
        .document_encrypt(doc.to_vec(), &Default::default())
        .await?;

    sdk.document_get_metadata(encrypted_doc.id()).await?;

    //Decrypt twice in case we have a load balanced pair. This should cache it.
    sdk.document_decrypt(encrypted_doc.encrypted_data()).await?;
    sdk.document_decrypt(encrypted_doc.encrypted_data()).await?;

    for i in 0..100_000_000 {
        let mut futures = stream::iter(0..stream_size)
            .map(|_| time_future(sdk.document_decrypt(encrypted_doc.encrypted_data())))
            .buffer_unordered(buffer_size);

        while let Some((r, duration)) = futures.next().await {
            r?;
            println!("Duration: {:?} in batch {}", duration, i);
        }
    }

    // assert_eq!(doc.to_vec(), decrypted.decrypted_data());
    Ok(())
}
pub async fn initialize_sdk() -> Result<IronOxide, IronOxideErr> {
    init_sdk_with_config(&Default::default()).await
}

fn generate_user_id() -> String {
    Uuid::new_v4().to_string()
}

pub async fn init_sdk_with_config(config: &IronOxideConfig) -> Result<IronOxide, IronOxideErr> {
    let account_id: UserId = generate_user_id().try_into()?;
    IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &UserCreateOpts::new(false),
        None,
    )
    .await?;
    let device = IronOxide::generate_new_device(
        &gen_jwt(Some(account_id.id())).0,
        USER_PASSWORD,
        &Default::default(),
        None,
    )
    .await?;
    ironoxide::initialize(&device.into(), config).await
}

pub fn gen_jwt(account_id: Option<&str>) -> (Jwt, String) {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    let iat_seconds = start
        .duration_since(UNIX_EPOCH)
        .expect("Time before epoch? Something's wrong.")
        .as_secs();
    let default_account_id = Uuid::new_v4().to_string();
    let sub = account_id.unwrap_or(&default_account_id);
    let my_claims = JwtClaims {
        sub: sub.to_string(),
        iat: iat_seconds,
        exp: iat_seconds + 120,
        pid: Some(CONFIG.project_id),
        sid: Some(CONFIG.segment_id.clone()),
        kid: Some(CONFIG.identity_assertion_key_id),
        uid: None,
        prefixed_pid: None,
        prefixed_sid: None,
        prefixed_kid: None,
        prefixed_uid: None,
    };
    let header = Header::new(Algorithm::ES256);
    let pem = std::fs::read_to_string(&KEYPATH.1).expect("Failed to open PEM file.");
    let key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("Invalid PEM file.");
    let jwt_str = jsonwebtoken::encode(&header, &my_claims, &key).expect("Failed to encode JWT.");
    let jwt = Jwt::new(&jwt_str).expect("Error creating IronCore JWT.");

    (jwt, sub.to_string())
}
