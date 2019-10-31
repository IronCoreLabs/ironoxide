use ironoxide::{prelude::*, user::UserVerifyResult};
use lazy_static::*;
use std::{convert::TryInto, default::Default};
use uuid::Uuid;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    project_id: usize,
    segment_id: String,
    identity_assertion_key_id: usize,
}

lazy_static! {
    static ref KEYPATH: std::path::PathBuf = {
        let mut path = std::env::current_dir().unwrap();
        path.push("tests");
        path.push("testkeys");
        path.push("test.pem");
        path
    };
    static ref IRONCORE_CONFIG_PATH: std::path::PathBuf = {
        let mut path = std::env::current_dir().unwrap();
        path.push("tests");
        path.push("testkeys");
        path.push("ironcore-config.json");
        path
    };
    static ref CONFIG: Config = {
        use std::io::Read;
        let mut file: std::fs::File = std::fs::File::open(IRONCORE_CONFIG_PATH.clone()).unwrap();
        let mut json_config: String = String::new();
        file.read_to_string(&mut json_config).unwrap();
        serde_json::from_str(&json_config).unwrap()
    };
}

pub fn gen_jwt(account_id: Option<&str>) -> (String, String) {
    //let mut keypath: std::path::PathBuf = std::env::current_dir().unwrap();
    //keypath.push("tests");
    //keypath.push("testkeys");
    // let mut ironcore_config_path: std::path::PathBuf = keypath.clone();
    // //keypath.push("test.pem");
    // ironcore_config_path.push("ironcore-config.json");

    // let mut file: std::fs::File = std::fs::File::open(IRONCORE_CONFIG_PATH.clone()).unwrap();
    // let mut json_config: String = String::new();
    // file.read_to_string(&mut json_config).unwrap();

    // let config: Config = serde_json::from_str(&json_config).unwrap();

    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    let iat_seconds = start
        .duration_since(UNIX_EPOCH)
        .expect("Time before epoch? Something's wrong.")
        .as_secs();

    let jwt_header = json!({});
    let default_account_id = Uuid::new_v4().to_string();
    let sub = account_id
        .or_else(|| Some(&default_account_id))
        .expect("Missing expected JWT account ID.");
    let jwt_payload = json!({
        "pid" : CONFIG.project_id,
        "sid" : CONFIG.segment_id,
        "kid" : CONFIG.identity_assertion_key_id,
        "iat" : iat_seconds,
        "exp" : iat_seconds + 120,
        "sub" : sub
    });
    let jwt = frank_jwt::encode(
        jwt_header,
        &KEYPATH.to_path_buf(),
        &jwt_payload,
        frank_jwt::Algorithm::ES256,
    )
    .expect("You don't appear to have the proper service private key to sign the test JWT.");
    (jwt, format!("{}", sub))
}

pub fn init_sdk() -> IronOxide {
    let (_, io) = init_sdk_get_user();
    io
}

pub fn init_sdk_get_user() -> (UserId, IronOxide) {
    let account_id: UserId = create_id_all_classes("").try_into().unwrap();
    IronOxide::user_create(
        &gen_jwt(Some(account_id.id())).0,
        "foo",
        &Default::default(),
    )
    .unwrap();

    let result = IronOxide::user_verify(&gen_jwt(Some(account_id.id())).0).unwrap();
    assert_eq!(true, result.is_some());
    let verify_resp = result.unwrap();

    assert_eq!(&account_id, verify_resp.account_id());
    assert_eq!(641, verify_resp.segment_id());

    let device = IronOxide::generate_new_device(
        &gen_jwt(Some(account_id.id())).0,
        "foo",
        &Default::default(),
    )
    .unwrap();

    //Manually unwrap all of these types and rewrap them just to prove that we can construct the DeviceContext
    //from its raw parts as part of the exposed SDK

    let users_account_id = device.account_id().id();
    let users_segment_id = device.segment_id();
    let users_device_id = *device.device_id().id();
    let users_device_private_key_bytes = &device.device_private_key().as_bytes()[..];
    let users_signing_keys_bytes = &device.signing_private_key().as_bytes()[..];

    let device_init = DeviceContext::new(
        users_device_id.try_into().unwrap(),
        users_account_id.try_into().unwrap(),
        users_segment_id,
        users_device_private_key_bytes.try_into().unwrap(),
        users_signing_keys_bytes.try_into().unwrap(),
    );

    (account_id, ironoxide::initialize(&device_init).unwrap())
}

pub fn create_second_user() -> UserVerifyResult {
    let (jwt, _) = gen_jwt(Some(&create_id_all_classes("")));
    let create_result = IronOxide::user_create(&jwt, "foo", &Default::default());
    assert!(create_result.is_ok());

    let verify_result = IronOxide::user_verify(&jwt);
    assert!(verify_result.is_ok());
    verify_result.unwrap().unwrap()
}

pub fn create_id_all_classes(prefix: &str) -> String {
    format!(
        "{}{}{}",
        prefix,
        "abcABC012_.$#|@/:;=+'-",
        Uuid::new_v4().to_string()
    )
}

#[allow(dead_code)]
// Use this test to print out a JWT and UUID if you need it
fn non_test_print_jwt() {
    dbg!(gen_jwt(None));
}
