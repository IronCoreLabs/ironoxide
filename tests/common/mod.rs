use ironoxide::{prelude::*, user::UserVerifyResult};
use std::convert::TryInto;
use std::default::Default;
use uuid::Uuid;

pub fn gen_jwt(
    project_id: usize,
    seg_id: &str,
    service_key_id: usize,
    account_id: Option<&str>,
) -> (String, String) {
    use std::env;

    let mut keypath = env::current_dir().unwrap();
    keypath.push("tests");
    keypath.push("testkeys");
    keypath.push("rsa_private.pem");

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
        "pid" : project_id,
        "sid" : seg_id,
        "kid" : service_key_id,
        "iat" : iat_seconds,
        "exp" : iat_seconds + 120,
        "sub" : sub
    });
    let jwt = frank_jwt::encode(
        jwt_header,
        &keypath.to_path_buf(),
        &jwt_payload,
        frank_jwt::Algorithm::RS256,
    )
    .expect("You don't appear to have the proper service private key to sign the test JWT.");
    (jwt, format!("{}", sub))
}

pub fn init_sdk() -> IronOxide {
    let (_, io) = init_sdk_get_user();
    io
}

pub fn init_sdk_get_user() -> (UserId, IronOxide) {
    let account_id: UserId = Uuid::new_v4().to_string().try_into().unwrap();
    IronOxide::user_create(
        &gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0,
        "foo",
        &Default::default(),
    )
    .unwrap();

    let result =
        IronOxide::user_verify(&gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0)
            .unwrap();
    assert_eq!(true, result.is_some());
    let verify_resp = result.unwrap();

    assert_eq!(&account_id, verify_resp.account_id());
    assert_eq!(2012, verify_resp.segment_id());

    let device = IronOxide::generate_new_device(
        &gen_jwt(1012, "test-segment", 551, Some(account_id.id())).0,
        "foo",
        &Default::default(),
    )
    .unwrap();

    //Manually unwrap all of these types and rewrap them just to prove that we can construct the DeviceContext
    //from it's raw parts as part of the exposed SDK

    let users_account_id = device.account_id().id();
    let users_segment_id = device.segment_id();
    let users_private_device_key_bytes = &device.private_device_key().as_bytes()[..];
    let users_signing_keys_bytes = &device.signing_keys().as_bytes()[..];

    let device_init = DeviceContext::new(
        users_account_id.try_into().unwrap(),
        users_segment_id,
        users_private_device_key_bytes.try_into().unwrap(),
        users_signing_keys_bytes.try_into().unwrap(),
    );

    (account_id, ironoxide::initialize(&device_init).unwrap())
}

pub fn create_second_user() -> UserVerifyResult {
    let (jwt, _) = gen_jwt(1012, "test-segment", 551, None);
    let create_result = IronOxide::user_create(&jwt, "foo", &Default::default());
    assert!(create_result.is_ok());

    let verify_result = IronOxide::user_verify(&jwt);
    assert!(verify_result.is_ok());
    verify_result.unwrap().unwrap()
}

#[allow(dead_code)]
// Use this test to print out a JWT and UUID if you need it
fn non_test_print_jwt() {
    dbg!(gen_jwt(1012, "test-segment", 551, None));
}
