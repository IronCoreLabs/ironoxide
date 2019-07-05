//! Helpers for talking to the ironcore service.

use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use futures::{stream::Stream, Future};
use reqwest::{
    header::HeaderMap,
    r#async::{Chunk, Client as RClient},
    Method, StatusCode,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::internal::{
    user_api::UserId, DeviceSigningKeyPair, IronOxideErr, Jwt, RequestErrorCode, OUR_REQUEST,
};

lazy_static! {
    static ref DEFAULT_HEADERS: HeaderMap = {
        let mut headers: HeaderMap = Default::default();
        headers.append("Content-Type", "application/json".parse().unwrap());
        headers
    };
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServerError {
    message: String,
    code: u32,
}

///URL encode the provided string so it can be used within a URL
pub fn url_encode(token: &str) -> String {
    percent_encoding::utf8_percent_encode(token, percent_encoding::USERINFO_ENCODE_SET).to_string()
}

///Enum representing all the ways that authorization can be done for the IronCoreRequest.
/// Currently just JWT, but will be ed25519 signed values soon.
pub enum Authorization<'a> {
    JwtAuth(&'a Jwt),
    MessageSignature {
        version: u8,
        message: String,
        signature: [u8; 64],
    },
}

impl<'a> Authorization<'a> {
    pub fn to_header(&self) -> HeaderMap {
        let auth_value = match self {
            Authorization::JwtAuth(jwt) => format!("jwt {}", jwt.0).parse().unwrap(),
            Authorization::MessageSignature {
                version,
                message,
                signature,
            } => format!(
                "ironcore {}.{}.{}",
                version,
                base64::encode(message),
                base64::encode(&signature[..])
            )
            .parse()
            .unwrap(),
        };
        let mut headers: HeaderMap = Default::default();
        headers.append("authorization", auth_value); //We're assuming that the JWT is ASCII.
        headers
    }

    pub fn create_message_signature_v1(
        time: DateTime<Utc>,
        segment_id: usize,
        user_id: &UserId,
        signing_keys: &DeviceSigningKeyPair,
    ) -> Authorization<'a> {
        //This may seem like it'd be easier to use serde-json or something here, but for doing it in a single spot and needing to verify
        //that the fields are in the correct order and the spacing is exact it was actually easier to do like this. We have a static test to verify
        //the safety of this value.
        let payload = format!(
            r#"{{"ts":{},"sid":{},"uid":"{}","x":"{}"}}"#,
            time.timestamp_millis(),
            segment_id,
            user_id.0,
            base64::encode(&signing_keys.public_key())
        );
        let signature = signing_keys.sign(payload.as_bytes());
        Authorization::MessageSignature {
            version: 1,
            message: payload,
            signature,
        }
    }
}

///A struct which holds the basic info that will be needed for making requests to an ironcore service. Currently just the base_url.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IronCoreRequest<'a> {
    base_url: &'a str,
}

impl Default for IronCoreRequest<'static> {
    fn default() -> Self {
        OUR_REQUEST
    }
}

impl<'a> IronCoreRequest<'a> {
    pub const fn new(base_url: &'a str) -> IronCoreRequest {
        IronCoreRequest { base_url }
    }

    pub fn base_url(&self) -> &'a str {
        self.base_url
    }

    ///POST body to the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub fn post<A: Serialize, B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &A,
        error_code: RequestErrorCode,
        auth: &Authorization,
    ) -> impl Future<Item = B, Error = IronOxideErr> {
        self.request::<A, _, String, _>(
            relative_url,
            Method::POST,
            Some(body),
            None,
            error_code,
            auth.to_header(),
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
    }

    ///PUT body to the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub fn put<A: Serialize, B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &A,
        error_code: RequestErrorCode,
        auth: &Authorization,
    ) -> impl Future<Item = B, Error = IronOxideErr> {
        self.request::<A, _, String, _>(
            relative_url,
            Method::PUT,
            Some(body),
            None,
            error_code,
            auth.to_header(),
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
    }

    ///GET the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub fn get<A: DeserializeOwned>(
        &self,
        relative_url: &str,
        error_code: RequestErrorCode,
        auth: &Authorization,
    ) -> impl Future<Item = A, Error = IronOxideErr> {
        //A little lie here, String isn't actually the body type as it's unused
        self.request::<String, _, String, _>(
            relative_url,
            Method::GET,
            None,
            None,
            error_code,
            auth.to_header(),
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
    }

    ///GET the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub fn get_with_query_params<A: DeserializeOwned>(
        &self,
        relative_url: &str,
        query_params: &[(String, String)],
        error_code: RequestErrorCode,
        auth: &Authorization,
    ) -> impl Future<Item = A, Error = IronOxideErr> {
        //A little lie here, String isn't actually the body type as it's unused
        self.request::<String, _, [(String, String)], _>(
            relative_url,
            Method::GET,
            None,
            Some(query_params),
            error_code,
            auth.to_header(),
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
    }

    ///This should be used for a GET where the result can be empty. If the result is empty the returned value will be None.
    pub fn get_with_empty_result<A: DeserializeOwned>(
        &self,
        relative_url: &str,
        error_code: RequestErrorCode,
        auth: &Authorization,
    ) -> impl Future<Item = Option<A>, Error = IronOxideErr> {
        //A little lie here, String isn't actually the body type as it's unused
        self.request::<String, _, String, _>(
            relative_url,
            Method::GET,
            None,
            None,
            error_code,
            auth.to_header(),
            move |server_resp| {
                if server_resp.len() > 0 {
                    IronCoreRequest::deserialize_body(&server_resp, error_code).map(|a| Some(a))
                } else {
                    Ok(None)
                }
            },
        )
    }

    /// DELETE body to the resource at relative_url using auth for authorization.
    /// If the request fails a RequestError will be raised.
    pub fn delete<A: Serialize, B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &A,
        error_code: RequestErrorCode,
        auth: &Authorization,
    ) -> impl Future<Item = B, Error = IronOxideErr> {
        self.request::<A, _, String, _>(
            relative_url,
            Method::DELETE,
            Some(body),
            None,
            error_code,
            auth.to_header(),
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
    }

    ///Make a request to the url using the specified method. DEFAULT_HEADERS will be used as well as whatever headers are passed
    /// in. The response will be sent to `resp_handler` so the caller can make the received bytes however they want.
    pub fn request<A, B, Q, F>(
        &self,
        relative_url: &str,
        method: Method,
        maybe_body: Option<&A>,
        maybe_query_params: Option<&Q>,
        error_code: RequestErrorCode,
        headers: HeaderMap,
        resp_handler: F,
    ) -> impl Future<Item = B, Error = IronOxideErr>
    where
        A: Serialize,
        B: DeserializeOwned,
        Q: Serialize + ?Sized,
        F: FnOnce(&Chunk) -> Result<B, IronOxideErr>,
    {
        let client = RClient::new();
        let mut builder = client.request(
            method,
            format!("{}{}", self.base_url, relative_url).as_str(),
        );
        // add query params, if any
        builder = maybe_query_params
            .iter()
            .fold(builder, |build, q| build.query(q));

        //We want to add the body as json if it was specified
        builder = maybe_body
            .iter()
            .fold(builder, |build, body| build.json(body));

        let req = builder.headers(DEFAULT_HEADERS.clone()).headers(headers);
        dbg!(&req);
        req.send()
            //Parse the body content into bytes
            .and_then(|res| {
                dbg!(&res);
                let status_code = res.status();
                res.into_body().concat2().map(move |body| {
                    dbg!(&body);
                    (status_code, body)
                })
            })
            //Now make the error type into the IronOxideErr and run the resp_handler which was passed to us.
            .then(move |resp| {
                //Map the generic error from reqwest to our error type.
                let (status, server_resp) = resp.map_err(|err| {
                    IronCoreRequest::create_request_err(err.to_string(), error_code, err.status())
                })?;
                //If the status code is a 5xx, return a fixed error code message
                if status.is_server_error() || status.is_client_error() {
                    Err(IronCoreRequest::request_failure_to_error(
                        status,
                        error_code,
                        &server_resp,
                    ))
                } else {
                    resp_handler(&server_resp)
                }
            })
    }

    pub fn delete_with_no_body<B: DeserializeOwned>(
        &self,
        relative_url: &str,
        error_code: RequestErrorCode,
        auth: &Authorization,
    ) -> impl Future<Item = B, Error = IronOxideErr> {
        self.delete(
            relative_url,
            &PhantomData::<u8>, // BS type, maybe there's a better way?
            error_code,
            auth,
        )
    }

    ///Deserialize the body of the response into a Result.
    fn deserialize_body<A: DeserializeOwned>(
        body: &[u8],
        error_code: RequestErrorCode,
    ) -> Result<A, IronOxideErr> {
        let deserialized = serde_json::from_slice(&body);
        deserialized.map_err(|serde_err| {
            IronCoreRequest::create_request_err(
                format!(
                    "Could not deserialize JSON response of: {:?} => serde error was: {}",
                    &std::str::from_utf8(&body),
                    serde_err
                ),
                error_code,
                None,
            )
        })
    }

    /// Given a request failure, determine which type of failure we have and return the appropriate error structure. Handles
    /// differentiating between 500 errors, 400 errors with an expected error body, and 404 errors without a response body.
    fn request_failure_to_error(
        status_code: StatusCode,
        error_code: RequestErrorCode,
        body: &[u8],
    ) -> IronOxideErr {
        if status_code.is_server_error() {
            IronCoreRequest::create_request_err(
                "Server encountered error attempting to make request.".to_string(),
                error_code,
                Some(status_code),
            )
        } else if status_code == StatusCode::NOT_FOUND {
            IronCoreRequest::create_request_err(
                "Requested resource was not found.".to_string(),
                error_code,
                Some(status_code),
            )
        } else if status_code == StatusCode::TOO_MANY_REQUESTS {
            //Handle Cloudflare rate limiting response code
            IronCoreRequest::create_request_err(
                "Request was denied due to rate limiting.".to_string(),
                error_code,
                Some(status_code),
            )
        } else {
            //If the status code is an error we can try and rip off the ServerErrors which ironcore-id
            //returns, otherwise process it the way the user wants.
            IronCoreRequest::deserialize_body::<Vec<ServerError>>(&body, error_code)
                .map(|error_response| IronOxideErr::RequestServerErrors {
                    errors: error_response,
                    code: error_code,
                    http_status: Some(status_code.as_u16()),
                })
                .unwrap_or_else(|e| e)
        }
    }

    // Generic method to build up a RequestError object with the provided text, error code and optional HTTP status code
    fn create_request_err(
        error_text: String,
        error_code: RequestErrorCode,
        status_code: Option<StatusCode>,
    ) -> IronOxideErr {
        IronOxideErr::RequestError {
            message: error_text,
            code: error_code,
            http_status: status_code.map(|s| s.as_u16()),
        }
    }
}

/// Common types for use across different internal apis
pub mod json {
    use crate::internal::{self, IronOxideErr, TryFrom};

    base64_serde_type!(pub Base64Standard, base64::STANDARD);

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    pub struct PublicKey {
        #[serde(with = "Base64Standard")]
        pub x: Vec<u8>,
        #[serde(with = "Base64Standard")]
        pub y: Vec<u8>,
    }

    impl From<internal::PublicKey> for PublicKey {
        fn from(internal_pub_key: internal::PublicKey) -> Self {
            let (x, y) = internal_pub_key.to_bytes_x_y();
            PublicKey { x, y }
        }
    }

    impl From<recrypt::api::PublicKey> for PublicKey {
        fn from(recrypt_pub_key: recrypt::api::PublicKey) -> Self {
            internal::PublicKey::from(recrypt_pub_key).into()
        }
    }

    impl TryFrom<PublicKey> for internal::PublicKey {
        type Error = IronOxideErr;

        fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
            internal::PublicKey::new_from_slice((&value.x, &value.y))
        }
    }

    #[derive(Serialize, Debug, PartialEq)]
    #[serde(rename_all = "camelCase")]
    pub struct TransformKey {
        ephemeral_public_key: PublicKey,
        to_public_key: PublicKey,
        #[serde(with = "Base64Standard")]
        encrypted_temp_key: Vec<u8>,
        #[serde(with = "Base64Standard")]
        hashed_temp_key: Vec<u8>,
        #[serde(with = "Base64Standard")]
        signature: Vec<u8>,
        #[serde(with = "Base64Standard")]
        public_signing_key: Vec<u8>,
    }

    impl From<internal::TransformKey> for TransformKey {
        fn from(tkey: internal::TransformKey) -> Self {
            use recrypt::api::Hashable;
            TransformKey {
                ephemeral_public_key: internal::PublicKey::from(
                    tkey.0.ephemeral_public_key().clone(),
                )
                .into(),
                to_public_key: internal::PublicKey::from(*tkey.0.to_public_key()).into(),
                encrypted_temp_key: tkey.0.encrypted_temp_key().to_bytes(),
                hashed_temp_key: tkey.0.hashed_temp_key().to_bytes(),
                signature: tkey.0.signature().bytes().to_vec(),
                public_signing_key: tkey.0.public_signing_key().bytes().to_vec(),
            }
        }
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct EncryptedOnceValue {
        #[serde(with = "Base64Standard")]
        encrypted_message: Vec<u8>,
        ephemeral_public_key: PublicKey,
        #[serde(with = "Base64Standard")]
        signature: Vec<u8>,
        #[serde(with = "Base64Standard")]
        auth_hash: Vec<u8>,
        #[serde(with = "Base64Standard")]
        public_signing_key: Vec<u8>,
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct TransformedEncryptedValue {
        #[serde(flatten)]
        encrypted_message: EncryptedOnceValue,
        transform_blocks: Vec<TransformBlock>,
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    #[serde(rename_all = "camelCase")]
    pub struct TransformBlock {
        #[serde(with = "Base64Standard")]
        encrypted_temp_key: Vec<u8>,
        public_key: PublicKey,
        #[serde(with = "Base64Standard")]
        random_transform_encrypted_temp_key: Vec<u8>,
        random_transform_public_key: PublicKey,
    }

    impl TryFrom<recrypt::api::EncryptedValue> for EncryptedOnceValue {
        type Error = IronOxideErr;

        fn try_from(ev: recrypt::api::EncryptedValue) -> Result<Self, Self::Error> {
            match ev {
                recrypt::api::EncryptedValue::EncryptedOnceValue {
                    ephemeral_public_key,
                    encrypted_message,
                    auth_hash,
                    public_signing_key,
                    signature,
                } => Ok(EncryptedOnceValue {
                    encrypted_message: encrypted_message.bytes().to_vec(),
                    ephemeral_public_key: ephemeral_public_key.into(),
                    signature: signature.bytes().to_vec(),
                    auth_hash: auth_hash.bytes().to_vec(),
                    public_signing_key: public_signing_key.bytes().to_vec(),
                }),
                _ => Err(IronOxideErr::InvalidRecryptEncryptedValue(
                    "Expected an EncryptedOnceValue but got an TransformedValue".to_string(),
                )),
            }
        }
    }

    impl TryFrom<recrypt::api::EncryptedValue> for TransformedEncryptedValue {
        type Error = IronOxideErr;

        fn try_from(ev: recrypt::api::EncryptedValue) -> Result<Self, Self::Error> {
            match ev {
                recrypt::api::EncryptedValue::TransformedValue {
                    ephemeral_public_key,
                    encrypted_message,
                    auth_hash,
                    public_signing_key,
                    signature,
                    transform_blocks,
                } => Ok(TransformedEncryptedValue {
                    transform_blocks: transform_blocks
                        .as_vec()
                        .iter()
                        .map(|tb| TransformBlock {
                            encrypted_temp_key: tb.encrypted_temp_key().bytes().to_vec(),
                            public_key: tb.public_key().clone().into(),
                            random_transform_encrypted_temp_key: tb
                                .encrypted_random_transform_temp_key()
                                .bytes()
                                .to_vec(),
                            random_transform_public_key: tb
                                .random_transform_public_key()
                                .clone()
                                .into(),
                        })
                        .collect(),
                    encrypted_message: EncryptedOnceValue {
                        encrypted_message: encrypted_message.bytes().to_vec(),
                        ephemeral_public_key: ephemeral_public_key.into(),
                        signature: signature.bytes().to_vec(),
                        auth_hash: auth_hash.bytes().to_vec(),
                        public_signing_key: public_signing_key.bytes().to_vec(),
                    },
                }),
                _ => Err(IronOxideErr::InvalidRecryptEncryptedValue(
                    "Expected a TransformedValue but got an EncryptedOnceValue".to_string(),
                )),
            }
        }
    }

    impl TryFrom<TransformBlock> for recrypt::api::TransformBlock {
        type Error = IronOxideErr;

        fn try_from(tb: TransformBlock) -> Result<Self, Self::Error> {
            recrypt::api::TransformBlock::new(
                &internal::PublicKey::try_from(tb.public_key)?.into(),
                &recrypt::api::EncryptedTempKey::new_from_slice(&tb.encrypted_temp_key[..])?,
                &internal::PublicKey::try_from(tb.random_transform_public_key)?.into(),
                &recrypt::api::EncryptedTempKey::new_from_slice(
                    &tb.random_transform_encrypted_temp_key[..],
                )?,
            )
            .map_err(|e| e.into())
        }
    }

    impl TryFrom<TransformedEncryptedValue> for recrypt::api::EncryptedValue {
        type Error = IronOxideErr;

        fn try_from(ev: TransformedEncryptedValue) -> Result<Self, Self::Error> {
            let transform_blocks: Result<Vec<recrypt::api::TransformBlock>, IronOxideErr> = ev
                .transform_blocks
                .into_iter()
                .map(recrypt::api::TransformBlock::try_from)
                .collect();

            Ok(recrypt::api::EncryptedValue::TransformedValue {
                ephemeral_public_key: internal::PublicKey::try_from(
                    ev.encrypted_message.ephemeral_public_key,
                )?
                .into(),
                encrypted_message: recrypt::api::EncryptedMessage::new_from_slice(
                    &ev.encrypted_message.encrypted_message[..],
                )?,
                auth_hash: recrypt::api::AuthHash::new_from_slice(
                    &ev.encrypted_message.auth_hash[..],
                )?,
                public_signing_key: recrypt::api::PublicSigningKey::new_from_slice(
                    &ev.encrypted_message.public_signing_key[..],
                )?,
                signature: recrypt::api::Ed25519Signature::new_from_slice(
                    &ev.encrypted_message.signature[..],
                )?,
                transform_blocks: recrypt::nonemptyvec::NonEmptyVec::try_from(&transform_blocks?)?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::test::{contains, length};
    use chrono::TimeZone;
    use galvanic_assert::matchers::{variant::*, *};

    #[test]
    fn create_message_signature_for_canned_values() {
        let expected_header = "ironcore 1.eyJ0cyI6MTIzNDU2LCJzaWQiOjEsInVpZCI6InVzZXItMTAiLCJ4IjoieHNxZitvaUJwUVBEcjY5amIrVHZLeE1TZG5ZQVRyN2lnTk5SL3VBMXd0dz0ifQ==.yzPtBfhoo6d2QxrY3OWdnSV4lyhHMwomPBCpKB4/Brt4X13nCqJWdEUe5/dBTUMawZhu8zOkwu6CQud8R+DtDg==";
        let ts = Utc.timestamp_millis(123456);
        let signing_key_bytes: [u8; 64] = [
            38, 218, 141, 117, 248, 58, 31, 187, 17, 183, 163, 49, 109, 66, 9, 132, 131, 77, 196,
            31, 117, 15, 61, 29, 171, 119, 177, 31, 219, 164, 218, 221, 198, 202, 159, 250, 136,
            129, 165, 3, 195, 175, 175, 99, 111, 228, 239, 43, 19, 18, 118, 118, 0, 78, 190, 226,
            128, 211, 81, 254, 224, 53, 194, 220,
        ];
        let key_pair = DeviceSigningKeyPair(
            recrypt::api::SigningKeypair::from_bytes(&signing_key_bytes).unwrap(),
        );
        let segment_id = 1;
        let user_id = UserId("user-10".to_string());
        let auth = Authorization::create_message_signature_v1(ts, segment_id, &user_id, &key_pair);
        let headers = auth.to_header();
        let header_result = headers.get("authorization").unwrap();
        assert_eq!(header_result, expected_header);
    }

    #[test]
    fn deserialize_errors() {
        let raw_string = r#"[{"message":"foo","code":2},{"message":"bar","code":3}]"#;
        let result: Vec<ServerError> = serde_json::from_slice(&raw_string.as_bytes()).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn request_failure_to_error_server_error() {
        let server_error = IronCoreRequest::request_failure_to_error(
            StatusCode::BAD_GATEWAY,
            RequestErrorCode::DocumentList,
            &[0u8; 0],
        );

        assert_that!(&server_error, is_variant!(IronOxideErr::RequestError));

        assert_that!(
            &server_error,
            has_structure!(IronOxideErr::RequestError {
                message: contains("Server encountered error"),
                code: eq(RequestErrorCode::DocumentList),
                http_status: maybe_some(eq(StatusCode::BAD_GATEWAY.as_u16()))
            })
        );
    }

    #[test]
    fn request_failure_to_rate_limiting_error() {
        let server_error = IronCoreRequest::request_failure_to_error(
            StatusCode::TOO_MANY_REQUESTS,
            RequestErrorCode::DocumentList,
            &[0u8; 0],
        );

        assert_that!(&server_error, is_variant!(IronOxideErr::RequestError));

        assert_that!(
            &server_error,
            has_structure!(IronOxideErr::RequestError {
                message: contains("rate limiting"),
                code: eq(RequestErrorCode::DocumentList),
                http_status: maybe_some(eq(StatusCode::TOO_MANY_REQUESTS.as_u16()))
            })
        );
    }

    #[test]
    fn request_failure_to_error_four_oh_four_error() {
        let server_error = IronCoreRequest::request_failure_to_error(
            StatusCode::NOT_FOUND,
            RequestErrorCode::DocumentList,
            &[0u8; 0],
        );

        assert_that!(&server_error, is_variant!(IronOxideErr::RequestError));

        assert_that!(
            &server_error,
            has_structure!(IronOxideErr::RequestError {
                message: contains("not found"),
                code: eq(RequestErrorCode::DocumentList),
                http_status: maybe_some(eq(StatusCode::NOT_FOUND.as_u16()))
            })
        );
    }

    #[test]
    fn request_failure_to_request_server_error() {
        let error_as_bytes =
            r#"[{"message":"foo","code":2},{"message":"bar","code":3}]"#.as_bytes();

        let server_error = IronCoreRequest::request_failure_to_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            RequestErrorCode::DocumentList,
            &error_as_bytes,
        );

        assert_that!(
            &server_error,
            is_variant!(IronOxideErr::RequestServerErrors)
        );

        assert_that!(
            &server_error,
            has_structure!(IronOxideErr::RequestServerErrors {
                errors: length(&2),
                code: eq(RequestErrorCode::DocumentList),
                http_status: maybe_some(eq(StatusCode::UNPROCESSABLE_ENTITY.as_u16()))
            })
        );
    }

    #[test]
    fn url_encode_ids() {
        // regex of allowed ids from ironcore-id: ^[a-zA-Z0-9_.$#|@/:;=+'-]{1,100}
        let not_url_safe_id = "'=#.other|/$non@;safe'-:;id_";
        let url_encoded = url_encode(&not_url_safe_id);
        assert_eq!(
            "\'%3D%23.other%7C%2F$non%40%3Bsafe\'-%3A%3Bid_",
            url_encoded
        )
    }
}
