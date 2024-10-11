//! Helpers for talking to the ironcore service.

use crate::internal::{
    auth_v2::AuthV2Builder,
    user_api::{Jwt, UserId},
    DeviceSigningKeyPair, IronOxideErr, RequestErrorCode, OUR_REQUEST,
};
use base64::engine::Engine;
use base64::prelude::BASE64_STANDARD;
use bytes::Bytes;
use lazy_static::lazy_static;
use percent_encoding::{AsciiSet, CONTROLS};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Method, Request, RequestBuilder, StatusCode, Url,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    borrow::BorrowMut,
    fmt::{Display, Error, Formatter},
    hash::Hash,
    marker::PhantomData,
    ops::Deref,
};
use time::OffsetDateTime;

lazy_static! {
    static ref DEFAULT_HEADERS: HeaderMap = {
        let mut headers: HeaderMap = Default::default();
        headers.append("Content-Type", "application/json".parse().unwrap());
        headers
    };
    static ref RAW_BYTES_HEADERS: HeaderMap = {
        let mut headers: HeaderMap = Default::default();
        // this works with cloudflare. tried `application/x-protobuf` and `application/protobuf` and both were flagged as potentially malicious
        headers.append("Content-Type", "application/octet-stream".parse().unwrap());
        headers
    };
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerError {
    message: String,
    code: u32,
}

/// This encode set should be used for path components and query strings.
/// `A-Z a-z 0-9 - _ . ! ~ * ' ( )` are the only characters we _don't_ want to encode.
///
/// If this is changed it will potentially need be changed in the webservice and all other SDKs.
#[rustfmt::skip]
const ICL_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ') // 0x20:
               // 0x21: ! ... no encode ..
    .add(b'"') // 0x22: "
    .add(b'#') // 0x23: #
    .add(b'$') // 0x24: $
    .add(b'%') // 0x25: %
    .add(b'&') // 0x26: &
               // 0x27: ' ... no encode ...
               // 0x28: ( ... no encode ...
               // 0x29: ) ... no encode ...
               // 0x2a: * ... no encode ...
    .add(b'+') // 0x2b: +
    .add(b',') // 0x2c: ,
               // 0x2d: - ... no encode ...
               // 0x2e: . ... no encode ...
    .add(b'/') // 0x2f: /
               // 0x30-0x39 are 0-9 ... no encode ...
    .add(b':') // 0x3a: :
    .add(b';') // 0x3b: ;
    .add(b'<') // 0x3c: <
    .add(b'=') // 0x3d: =
    .add(b'>') // 0x3e: >
    .add(b'?') // 0x3f: ?
    .add(b'@') // 0x40: @
               // 0x41-0x5a are A-Z ... no encode ...
    .add(b'[') // 0x5b: [
    .add(b'\\')// 0x5c: \
    .add(b']') // 0x5d: ]
    .add(b'^') // 0x5e: ^
               // 0x5f: _ ... no encode ...
    .add(b'`') // 0x60: `
               // 0x61-0x7a are a-z ... no encode ...
    .add(b'{') // 0x7b: {
    .add(b'|') // 0x7c: |
    .add(b'}'); //0x7d: }
                //0x7e: ~ ... no encode ...

#[derive(Clone, Debug)]
/// Newtype for strings that have been percent encoded
pub struct PercentEncodedString(pub(crate) String);

impl Deref for PercentEncodedString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for PercentEncodedString {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "{}", self.0)
    }
}

///URL encode the provided string so it can be used within a URL
pub fn url_encode(token: &str) -> PercentEncodedString {
    PercentEncodedString(percent_encoding::utf8_percent_encode(token, ICL_ENCODE_SET).to_string())
}

#[allow(clippy::large_enum_variant)]
///Enum representing all the ways that authorization can be done for the IronCoreRequest.
pub enum Authorization<'a> {
    JwtAuth(&'a Jwt),
    Version2 {
        user_context: HeaderIronCoreUserContext,
        request_sig: HeaderIronCoreRequestSig<'a>,
    },
}

impl<'a> Authorization<'a> {
    const VERSION_NUM: u8 = 2;
    pub fn to_auth_header(&self) -> HeaderMap {
        let auth_value = match self {
            Authorization::JwtAuth(jwt) => format!("jwt {}", jwt.jwt())
                .parse()
                .expect("IronCore JWTs should be ASCII"),
            Authorization::Version2 {
                user_context,
                request_sig,
            } => format!(
                "IronCore {}.{}",
                Authorization::VERSION_NUM,
                BASE64_STANDARD.encode(user_context.signature(request_sig.signing_keys))
            )
            .parse()
            .expect("Auth v2 headers should only contain ASCII"),
        };
        let mut headers: HeaderMap = Default::default();
        headers.append("authorization", auth_value);
        headers
    }

    pub fn create_signatures_v2(
        time: OffsetDateTime,
        segment_id: usize,
        user_id: &UserId,
        method: Method,
        signature_url: SignatureUrlString,
        body: Option<&'a [u8]>,
        signing_keys: &'a DeviceSigningKeyPair,
    ) -> Authorization<'a> {
        let user_context = HeaderIronCoreUserContext {
            timestamp: time,
            segment_id,
            user_id: user_id.clone(),
            public_signing_key: signing_keys.public_key(),
        };
        Authorization::Version2 {
            user_context: user_context.clone(),
            request_sig: HeaderIronCoreRequestSig {
                signing_keys,
                url: signature_url,
                method,
                ironcore_user_context: user_context,
                body,
            },
        }
    }
}

/// For API auth, we sign over the path + query string percent encoded with specific rules.
///
/// For the URL: `https://api.ironcorelabs.com/api/1/users?id=abcABC012_.$#|@/:;=+'-`
/// We sign over: `/api/1/users?id=abcABC012_.%24%23%7C%40%2F%3A%3B%3D%2B'-`
///
/// Anyone wanting to verify this signature will need to be able to match this exact encoding.
#[derive(Clone, Debug)]
pub struct SignatureUrlString(String);

impl SignatureUrlString {
    pub fn new(encoded_full_url: &str) -> Result<SignatureUrlString, url::ParseError> {
        let parsed_url = Url::parse(encoded_full_url)?;
        //The formatter for the query string is overfomatting compared to what we want, so we want to replace
        //the %27 with a ' so we're signing over the right value.
        let query_str_format = |q: &str| format!("?{}", q.replace("%27", "'"));

        Ok(SignatureUrlString(format!(
            "{}{}",
            parsed_url.path(),
            parsed_url.query().map_or("".into(), query_str_format)
        )))
    }

    /// String to sign over
    fn signature_string(&self) -> &str {
        &self.0
    }
}

/// Representation of X-IronCore-User-Context header
#[derive(Clone, Debug)]
pub struct HeaderIronCoreUserContext {
    timestamp: OffsetDateTime,
    segment_id: usize,
    user_id: UserId,
    public_signing_key: [u8; 32],
}

pub const fn as_unix_timestamp_millis(ts: OffsetDateTime) -> i128 {
    ts.unix_timestamp() as i128 * 1_000 + ts.millisecond() as i128
}

impl HeaderIronCoreUserContext {
    /// Payload of the header
    fn payload(&self) -> String {
        format!(
            "{},{},{},{}",
            as_unix_timestamp_millis(self.timestamp),
            self.segment_id,
            self.user_id.id(),
            BASE64_STANDARD.encode(self.public_signing_key)
        )
    }

    /// Signature over the header's payload
    fn signature(&self, signing_keys: &DeviceSigningKeyPair) -> [u8; 64] {
        signing_keys.sign(&self.payload().into_bytes())
    }

    /// To a reqwest-compatible header
    fn to_header(&self, error_code: RequestErrorCode) -> Result<HeaderMap, IronOxideErr> {
        let mut headers: HeaderMap = Default::default();
        self.payload()
            .parse()
            .map_err(|_| IronOxideErr::RequestError {
                message: format!(
                    "Failed to encode '{}' into a X-IronCore-User-Context header",
                    &self.payload()
                ),
                code: error_code,
                http_status: None,
            })
            .map(|url| {
                headers.append("X-IronCore-User-Context", url);
                headers
            })
    }
}

/// Representation of X-IronCore-Request-Sig header
#[derive(Clone, Debug)]
pub struct HeaderIronCoreRequestSig<'a> {
    ironcore_user_context: HeaderIronCoreUserContext,
    method: Method,
    url: SignatureUrlString,
    body: Option<&'a [u8]>, //serialization of this body has to be identical to that in IronCoreRequest
    signing_keys: &'a DeviceSigningKeyPair,
}

impl<'a> HeaderIronCoreRequestSig<'a> {
    /// Payload of the header
    fn payload(&self) -> Vec<u8> {
        let HeaderIronCoreRequestSig {
            body,
            ironcore_user_context,
            method,
            url,
            ..
        } = self;

        let bytes_no_body = format!(
            "{}{}{}",
            &ironcore_user_context.payload(),
            &method,
            url.signature_string(),
        )
        .into_bytes();

        match body {
            &Some(body_bytes) => [&bytes_no_body, body_bytes].concat(),
            None => bytes_no_body,
        }
    }

    /// Signature over the header's payload
    fn signature(&self) -> [u8; 64] {
        self.signing_keys.sign(&self.payload())
    }
    fn to_header(&self) -> HeaderMap {
        let mut headers: HeaderMap = Default::default();
        headers.append(
            "X-IronCore-Request-Sig",
            BASE64_STANDARD
                .encode(self.signature())
                .parse()
                .expect("signature as base64 can always be encoded as ASCII"),
        );
        headers
    }
}

///A struct which holds the basic info that will be needed for making requests to an ironcore service. Currently just the base_url.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct IronCoreRequest {
    base_url: &'static str,
    #[serde(skip_serializing, skip_deserializing, default = "default_client")]
    client: &'static reqwest::Client,
}

fn default_client() -> &'static reqwest::Client {
    OUR_REQUEST.client
}

impl Default for IronCoreRequest {
    fn default() -> Self {
        *OUR_REQUEST
    }
}
impl Hash for IronCoreRequest {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.base_url.hash(state);
    }
}
impl PartialEq for IronCoreRequest {
    fn eq(&self, other: &Self) -> bool {
        self.base_url == other.base_url
    }
}
impl Eq for IronCoreRequest {}

impl IronCoreRequest {
    pub const fn new(base_url: &'static str, client: &'static reqwest::Client) -> IronCoreRequest {
        IronCoreRequest { base_url, client }
    }

    pub fn base_url(&self) -> &str {
        self.base_url
    }

    ///POST body to the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub async fn post_jwt_auth<A: Serialize, B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &A,
        error_code: RequestErrorCode,
        auth: &Authorization<'_>,
    ) -> Result<B, IronOxideErr> {
        self.request::<A, _, String, _>(
            relative_url,
            Method::POST,
            Some(body),
            None,
            error_code,
            auth.to_auth_header(),
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
        .await
    }

    ///POST body to the resource at relative_url using IronCore authorization.
    ///If the request fails a RequestError will be raised.
    pub async fn post<A: Serialize, B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &A,
        error_code: RequestErrorCode,
        auth_b: crate::internal::auth_v2::AuthV2Builder<'_>,
    ) -> Result<B, IronOxideErr> {
        self.request_ironcore_auth::<A, _, _>(
            relative_url,
            Method::POST,
            Some(body),
            None,
            error_code,
            auth_b,
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
        .await
    }
    pub async fn post_raw<B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &[u8],
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder<'_>,
    ) -> Result<B, IronOxideErr> {
        let (mut req, body_bytes) = Result::<_, IronOxideErr>::Ok({
            // build up a request...
            let mut req = Request::new(
                Method::POST,
                url::Url::parse(&format!("{}{}", self.base_url(), relative_url))
                    .map_err(|e| IronOxideErr::from((e, error_code)))?,
            );
            *req.body_mut() = Some(body.to_vec().into());
            (req, body.to_vec())
        })?;
        // use the completed request to finish authorization v2 headers
        let auth = SignatureUrlString::new(req.url().as_str())
            .map(|sig_url| auth_b.finish_with(sig_url, req.method().clone(), Some(&body_bytes)))
            .map_err(|e| IronOxideErr::from((e, error_code)))?;

        // we only support Authorization::Version2 with this call
        if let Authorization::Version2 {
            user_context,
            request_sig,
        } = &auth
        {
            let user_context_header = user_context.to_header(error_code)?;
            replace_headers(req.headers_mut(), user_context_header);
            replace_headers(req.headers_mut(), DEFAULT_HEADERS.clone());
            replace_headers(req.headers_mut(), auth.to_auth_header());
            replace_headers(req.headers_mut(), request_sig.to_header());

            self.send_req(req, error_code, move |server_resp| {
                IronCoreRequest::deserialize_body(server_resp, error_code)
            })
            .await
        } else {
            panic!("authorized requests must use version 2 of API authentication")
        }
    }
    ///PUT body to the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub async fn put<A: Serialize, B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &A,
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder<'_>,
    ) -> Result<B, IronOxideErr> {
        self.request_ironcore_auth::<A, _, _>(
            relative_url,
            Method::PUT,
            Some(body),
            None,
            error_code,
            auth_b,
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
        .await
    }

    ///GET the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub async fn get<A: DeserializeOwned>(
        &self,
        relative_url: &str,
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder<'_>,
    ) -> Result<A, IronOxideErr> {
        //A little lie here, String isn't actually the body type as it's unused
        self.request_ironcore_auth::<String, _, _>(
            relative_url,
            Method::GET,
            None,
            None,
            error_code,
            auth_b,
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
        .await
    }

    ///GET the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub async fn get_with_query_params<A: DeserializeOwned>(
        &self,
        relative_url: &str,
        query_params: &[(String, PercentEncodedString)],
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder<'_>,
    ) -> Result<A, IronOxideErr> {
        self.request_ironcore_auth::<String, _, _>(
            relative_url,
            Method::GET,
            None,
            Some(query_params),
            error_code,
            auth_b,
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
        .await
    }

    ///This should be used for a GET where the result can be empty. If the result is empty the returned value will be None.
    pub async fn get_with_empty_result_jwt_auth<A: DeserializeOwned>(
        &self,
        relative_url: &str,
        error_code: RequestErrorCode,
        auth: &Authorization<'_>,
    ) -> Result<Option<A>, IronOxideErr> {
        //A little lie here, String isn't actually the body type as it's unused
        self.request::<String, _, String, _>(
            relative_url,
            Method::GET,
            None,
            None,
            error_code,
            auth.to_auth_header(),
            move |server_resp| {
                if !server_resp.is_empty() {
                    IronCoreRequest::deserialize_body(server_resp, error_code).map(Some)
                } else {
                    Ok(None)
                }
            },
        )
        .await
    }

    /// DELETE body to the resource at relative_url using auth for authorization.
    /// If the request fails a RequestError will be raised.
    pub async fn delete<A: Serialize, B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &A,
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder<'_>,
    ) -> Result<B, IronOxideErr> {
        self.request_ironcore_auth::<A, _, _>(
            relative_url,
            Method::DELETE,
            Some(body),
            None,
            error_code,
            auth_b,
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
        .await
    }

    ///Make a request to the url using the specified method. DEFAULT_HEADERS will be used as well as whatever headers are passed
    /// in. The response will be sent to `resp_handler` so the caller can make the received bytes however they want.
    pub async fn request<A, B, Q, F>(
        &self,
        relative_url: &str,
        method: Method,
        maybe_body: Option<&A>,
        maybe_query_params: Option<&Q>,
        error_code: RequestErrorCode,
        headers: HeaderMap,
        resp_handler: F,
    ) -> Result<B, IronOxideErr>
    where
        A: Serialize,
        B: DeserializeOwned,
        Q: Serialize + ?Sized,
        F: FnOnce(&Bytes) -> Result<B, IronOxideErr>,
    {
        let client = self.client.clone();
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
        IronCoreRequest::send_req_with_builder(req, error_code, resp_handler).await
    }

    ///Make a request to the url using the specified method. DEFAULT_HEADERS will be used as well as whatever headers are passed
    /// in. The response will be sent to `resp_handler` so the caller can make the received bytes however they want.
    pub async fn request_ironcore_auth<A, B, F>(
        &self,
        relative_url: &str,
        method: Method,
        maybe_body: Option<&A>,
        maybe_query_params: Option<&[(String, PercentEncodedString)]>,
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder<'_>,
        resp_handler: F,
    ) -> Result<B, IronOxideErr>
    where
        A: Serialize,
        B: DeserializeOwned,
        F: FnOnce(&Bytes) -> Result<B, IronOxideErr>,
    {
        let (mut req, body_bytes) = Result::<_, IronOxideErr>::Ok({
            // build up a request...
            let mut req = Request::new(
                method,
                url::Url::parse(&format!("{}{}", self.base_url(), relative_url))
                    .map_err(|e| IronOxideErr::from((e, error_code)))?,
            );

            // add query params
            if let Some(query) = maybe_query_params {
                Self::req_add_query(req.borrow_mut(), query);
            }

            // add the body
            let body_bytes: Vec<u8> = if let Some(json_se) = maybe_body {
                let body = serde_json::to_vec(&json_se)
                    .map_err(|e| IronOxideErr::from((e, error_code)))?;
                req.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                *req.body_mut() = Some(body.clone().into());
                body
            } else {
                vec![]
            };

            (req, body_bytes)
        })?;

        // use the completed request to finish authorization v2 headers
        let auth = SignatureUrlString::new(req.url().as_str())
            .map(|sig_url| auth_b.finish_with(sig_url, req.method().clone(), Some(&body_bytes)))
            .map_err(|e| IronOxideErr::from((e, error_code)))?;

        // we only support Authorization::Version2 with this call
        if let Authorization::Version2 {
            user_context,
            request_sig,
        } = &auth
        {
            let user_context_header = user_context.to_header(error_code)?;
            replace_headers(req.headers_mut(), user_context_header);
            replace_headers(req.headers_mut(), DEFAULT_HEADERS.clone());
            replace_headers(req.headers_mut(), auth.to_auth_header());
            replace_headers(req.headers_mut(), request_sig.to_header());

            self.send_req(req, error_code, resp_handler).await
        } else {
            panic!("authorized requests must use version 2 of API authentication")
        }
    }

    fn req_add_query(req: &mut Request, query_params: &[(String, PercentEncodedString)]) {
        // side-effect to the stars!
        if !query_params.is_empty() {
            // can't use serde_urlencoded here as we need a custom percent encoding
            let query_string: String = query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v.0))
                .collect::<Vec<_>>()
                .join("&");

            req.url_mut().set_query(Some(&query_string));
        }
    }

    async fn send_req<B, F>(
        &self,
        req: Request,
        error_code: RequestErrorCode,
        resp_handler: F,
    ) -> Result<B, IronOxideErr>
    where
        B: DeserializeOwned,
        F: FnOnce(&Bytes) -> Result<B, IronOxideErr>,
    {
        let client = self.client.clone();
        let server_res = client.execute(req).await;
        let res = server_res.map_err(|e| (e, error_code))?;
        //Parse the body content into bytes
        let status = res.status();
        //Now make the error type into the IronOxideErr and run the resp_handler which was passed to us.
        let server_resp = res.bytes().await.map_err(|err| {
            //Map the generic error from reqwest to our error type.
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
    }
    async fn send_req_with_builder<B, F>(
        req: RequestBuilder,
        error_code: RequestErrorCode,
        resp_handler: F,
    ) -> Result<B, IronOxideErr>
    where
        B: DeserializeOwned,
        F: FnOnce(&Bytes) -> Result<B, IronOxideErr>,
    {
        let res_result = req.send().await;
        let res = res_result.map_err(|e| (e, error_code))?;
        //Parse the body content into bytes
        let status = res.status();
        //Now make the error type into the IronOxideErr and run the resp_handler which was passed to us.
        let server_resp = res.bytes().await.map_err(|err| {
            //Map the generic error from reqwest to our error type.

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
    }

    pub async fn delete_with_no_body<B: DeserializeOwned>(
        &self,
        relative_url: &str,
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder<'_>,
    ) -> Result<B, IronOxideErr> {
        self.delete(
            relative_url,
            &PhantomData::<u8>, // BS type, maybe there's a better way?
            error_code,
            auth_b,
        )
        .await
    }

    ///Deserialize the body of the response into a Result.
    fn deserialize_body<A: DeserializeOwned>(
        body: &[u8],
        error_code: RequestErrorCode,
    ) -> Result<A, IronOxideErr> {
        let deserialized = serde_json::from_slice(body);
        deserialized.map_err(|serde_err| {
            IronCoreRequest::create_request_err(
                format!(
                    "Could not deserialize JSON response of: {:?} => serde error was: {}",
                    &std::str::from_utf8(body),
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
            //If the status code is an error we can try and rip off the ServerErrors which the webservice
            //returns, otherwise process it the way the user wants.
            IronCoreRequest::deserialize_body::<Vec<ServerError>>(body, error_code).map_or_else(
                |e| e,
                |error_response| IronOxideErr::RequestServerErrors {
                    errors: error_response,
                    code: error_code,
                    http_status: Some(status_code.as_u16()),
                },
            )
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
// brought this private function in from reqwest
fn replace_headers(dst: &mut HeaderMap, src: HeaderMap) {
    // IntoIter of HeaderMap yields (Option<HeaderName>, HeaderValue).
    // The first time a name is yielded, it will be Some(name), and if
    // there are more values with the same name, the next yield will be
    // None.
    let mut prev_name = None;
    for (key, value) in src {
        match key {
            Some(key) => {
                dst.insert(key.clone(), value);
                prev_name = Some(key);
            }
            None => match prev_name {
                Some(ref key) => {
                    dst.append(key.clone(), value);
                }
                None => unreachable!("HeaderMap::into_iter yielded None first"),
            },
        }
    }
}

impl From<(serde_json::Error, RequestErrorCode)> for IronOxideErr {
    fn from((e, code): (serde_json::Error, RequestErrorCode)) -> Self {
        IronOxideErr::RequestError {
            message: e.to_string(),
            code,
            http_status: None,
        }
    }
}

impl From<(reqwest::Error, RequestErrorCode)> for IronOxideErr {
    fn from((e, code): (reqwest::Error, RequestErrorCode)) -> Self {
        IronOxideErr::RequestError {
            message: e.to_string(),
            code,
            http_status: None,
        }
    }
}

impl From<(url::ParseError, RequestErrorCode)> for IronOxideErr {
    fn from((e, code): (url::ParseError, RequestErrorCode)) -> Self {
        IronOxideErr::RequestError {
            message: e.to_string(),
            code,
            http_status: None,
        }
    }
}

/// Common types for use across different internal apis
pub mod json {
    use crate::internal::{self, IronOxideErr};
    use base64::prelude::BASE64_STANDARD;
    use base64_serde::base64_serde_type;
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;

    base64_serde_type!(pub Base64Standard, BASE64_STANDARD);

    #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
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

    #[derive(Debug, PartialEq, Eq, Serialize)]
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
                ephemeral_public_key: internal::PublicKey::from(*tkey.0.ephemeral_public_key())
                    .into(),
                to_public_key: internal::PublicKey::from(*tkey.0.to_public_key()).into(),
                encrypted_temp_key: tkey.0.encrypted_temp_key().to_bytes(),
                hashed_temp_key: tkey.0.hashed_temp_key().to_bytes(),
                signature: tkey.0.signature().bytes().to_vec(),
                public_signing_key: tkey.0.public_signing_key().bytes().to_vec(),
            }
        }
    }

    #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
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

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AugmentationFactor(#[serde(with = "Base64Standard")] pub Vec<u8>);

    impl From<internal::AugmentationFactor> for AugmentationFactor {
        fn from(af: internal::AugmentationFactor) -> Self {
            AugmentationFactor(af.as_bytes().to_vec())
        }
    }

    #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TransformedEncryptedValue {
        #[serde(flatten)]
        encrypted_message: EncryptedOnceValue,
        transform_blocks: Vec<TransformBlock>,
    }

    #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
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
                    "Expected an EncryptedOnceValue but got a TransformedValue".to_string(),
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
    use crate::internal::tests::{contains, length};
    use galvanic_assert::{
        matchers::{variant::*, *},
        *,
    };

    use recrypt::api::{Ed25519Signature, PublicSigningKey};

    lazy_static! {
        static ref SHARED_CLIENT: reqwest::Client = reqwest::Client::new();
        static ref TEST_REQUEST: IronCoreRequest = IronCoreRequest {
            base_url: "https://example.com",
            client: &SHARED_CLIENT
        };
    }

    #[test]
    fn deserialize_errors() {
        let raw_string = r#"[{"message":"foo","code":2},{"message":"bar","code":3}]"#;
        let result: Vec<ServerError> = serde_json::from_slice(raw_string.as_bytes()).unwrap();
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
            error_as_bytes,
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
        let url_encoded = url_encode(not_url_safe_id);
        assert_eq!(
            *url_encoded,
            "\'%3D%23.other%7C%2F%24non%40%3Bsafe\'-%3A%3Bid_"
        )
    }

    #[test]
    fn ironcore_user_context_signing_and_headers_are_correct() {
        let ts = OffsetDateTime::from_unix_timestamp_nanos(123_456_000_000).unwrap();
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
        let user_context = HeaderIronCoreUserContext {
            timestamp: ts,
            segment_id,
            user_id,
            public_signing_key: key_pair.public_key(),
        };
        let payload_bytes = user_context.payload().into_bytes();

        let expected = "123456,1,user-10,xsqf+oiBpQPDr69jb+TvKxMSdnYATr7igNNR/uA1wtw=";

        // assert that the payload is constructed in the right order
        assert_eq!(
            expected.to_string(),
            String::from_utf8(payload_bytes.clone()).unwrap()
        );

        // assert that the associated header has the correct form
        let mut header = HeaderMap::default();
        header.append("X-IronCore-User-Context", expected.parse().unwrap());

        assert_eq!(
            user_context
                .to_header(RequestErrorCode::UserKeyList)
                .unwrap(),
            header
        );

        // assert that the signature() implementation can be verified with the included public signing key
        let signature = user_context.signature(&key_pair);
        let pub_signing_key: PublicSigningKey =
            PublicSigningKey::new(user_context.public_signing_key);
        assert!(pub_signing_key.verify(&payload_bytes, &Ed25519Signature::new(signature)));
    }

    #[derive(Serialize)]
    struct FakeRequest {
        k1: Vec<u8>,
        k2: u64,
        k3: String,
        k4: i64,
    }

    #[test]
    fn ironcore_auth_v2_produces_expected_values() {
        let ts = OffsetDateTime::from_unix_timestamp_nanos(123_456_000_000).unwrap();
        let signing_key_bytes: [u8; 64] = [
            38, 218, 141, 117, 248, 58, 31, 187, 17, 183, 163, 49, 109, 66, 9, 132, 131, 77, 196,
            31, 117, 15, 61, 29, 171, 119, 177, 31, 219, 164, 218, 221, 198, 202, 159, 250, 136,
            129, 165, 3, 195, 175, 175, 99, 111, 228, 239, 43, 19, 18, 118, 118, 0, 78, 190, 226,
            128, 211, 81, 254, 224, 53, 194, 220,
        ];
        let signing_keys = DeviceSigningKeyPair(
            recrypt::api::SigningKeypair::from_bytes(&signing_key_bytes).unwrap(),
        );
        let segment_id = 1;
        let user_id = UserId("user-10".to_string());
        let user_context = HeaderIronCoreUserContext {
            timestamp: ts,
            segment_id,
            user_id: user_id.clone(),
            public_signing_key: signing_keys.public_key(),
        };

        let build_url = |relative_url| format!("{}{}", OUR_REQUEST.base_url(), relative_url);
        let signing_url_string = SignatureUrlString::new(&build_url("users?id=user-10")).unwrap();

        // note that this and the expected value must correspond
        let fake_req = FakeRequest {
            k1: vec![42u8; 10],
            k2: 64u64,
            k3: "Fake text for a fake request".to_string(),
            k4: -482_949_i64,
        };

        let expected = "123456,1,user-10,xsqf+oiBpQPDr69jb+TvKxMSdnYATr7igNNR/uA1wtw=GET/api/1/users?id=user-10{\"k1\":[42,42,42,42,42,42,42,42,42,42],\"k2\":64,\"k3\":\"Fake text for a fake request\",\"k4\":-482949}";
        let expected_no_body = "123456,1,user-10,xsqf+oiBpQPDr69jb+TvKxMSdnYATr7igNNR/uA1wtw=GET/api/1/users?id=user-10";

        //
        // first test the signature over a JSON encoded request
        //
        let fake_req_json = serde_json::to_string(&fake_req).unwrap();
        let fake_req_json_bytes = fake_req_json.into_bytes();
        let request_sig = HeaderIronCoreRequestSig {
            ironcore_user_context: user_context.clone(),
            method: Method::GET,
            url: signing_url_string.clone(),
            body: Some(&fake_req_json_bytes),
            signing_keys: &signing_keys,
        };

        assert_eq!(&request_sig.payload(), &expected.to_string().into_bytes());

        // assert that the corresponding header also has the correct form
        let mut header = HeaderMap::default();
        header.append("X-IronCore-Request-Sig", "EdXNi3mkmHfEcFxhKfl3dri/Z1E0uGq6H+wbitD3N/Ooi9cq9tpmlkjoV4dnEFSKs/xxkOwlLOTwtVsM1f2lAw==".parse().unwrap());
        assert_eq!(&request_sig.to_header(), &header);

        //
        // show that no body also works
        //
        let request_sig = HeaderIronCoreRequestSig {
            ironcore_user_context: user_context,
            method: Method::GET,
            url: signing_url_string.clone(),
            body: None,
            signing_keys: &signing_keys,
        };

        assert_eq!(
            &request_sig.payload(),
            &expected_no_body.to_string().into_bytes()
        );

        // signature matches known value
        let expected_request_sig = "7zvbj5mGKir4LxrQCcHCNc6md/487MMiBokumIIq4wEk+kJEFIKP1iBRK2cX8cs9h4XrdvXju3kEh0xdJBTlBw==";
        assert_eq!(
            BASE64_STANDARD.encode(request_sig.signature()),
            expected_request_sig
        );

        // X-IronCore-Request-Sig header is well formed
        let mut header = HeaderMap::default();
        header.append(
            "X-IronCore-Request-Sig",
            expected_request_sig.parse().unwrap(),
        );
        assert_eq!(&request_sig.to_header(), &header);

        // verify that the signature produced matches can be verified
        assert!(signing_keys.0.public_key().verify(
            &request_sig.payload(),
            &Ed25519Signature::new_from_slice(
                &BASE64_STANDARD.decode(expected_request_sig).unwrap()
            )
            .unwrap()
        ));

        // verify that the authorization header is expected
        let auth = Authorization::create_signatures_v2(
            ts,
            segment_id,
            &user_id,
            Method::POST,
            signing_url_string,
            None,
            &signing_keys,
        );

        let mut auth_header_expected = HeaderMap::default();
        auth_header_expected.append("authorization", "IronCore 2.CzATu+yKHO9edYZ6L27EXE4jKlk9p9hBhQsTJjj5ENFk2VhMfLp1ADKfaDQ/Q6u/Q7yHawq9L5Y1BFivdUYSCQ==".parse().unwrap());
        assert_eq!(auth.to_auth_header(), auth_header_expected);
    }

    #[test]
    fn signature_url_new_works() {
        let user_list_url = |not_encoded_user| {
            format!(
                "{}{}",
                "https://api.ironcorelabs.com/api/1/users?id=",
                url_encode(not_encoded_user)
            )
        };
        let maybe_path = SignatureUrlString::new(&user_list_url("user-10"));
        assert_that!(&maybe_path, is_variant!(Result::Ok));
        assert_eq!(
            maybe_path.unwrap().signature_string(),
            "/api/1/users?id=user-10"
        );
        // test a user id that uses more allowed characters
        let maybe_path = SignatureUrlString::new(&user_list_url("abcABC012_.$#|@/:;=+'-"));

        assert_that!(&maybe_path, is_variant!(Result::Ok));
        assert_eq!(
            maybe_path.unwrap().signature_string(),
            "/api/1/users?id=abcABC012_.%24%23%7C%40%2F%3A%3B%3D%2B\'-"
        );

        let maybe_path =
            SignatureUrlString::new("https://api.ironcorelabs.com/api/1/documents/some-doc-id");

        assert_that!(&maybe_path, is_variant!(Result::Ok));
        assert_eq!(
            maybe_path.unwrap().signature_string(),
            "/api/1/documents/some-doc-id"
        );
    }

    #[test]
    fn signature_url_new_rejects_malformed_urls() {
        let maybe_path = SignatureUrlString::new("not a url");
        assert_that!(&maybe_path, is_variant!(Result::Err));

        let maybe_path = SignatureUrlString::new("://api?");
        assert_that!(&maybe_path, is_variant!(Result::Err));

        let maybe_path = SignatureUrlString::new("documents/some-doc-id");
        assert_that!(&maybe_path, is_variant!(Result::Err));
    }

    #[test]
    fn query_params_encoded_correctly() {
        let mut req = Request::new(
            Method::GET,
            url::Url::parse(&format!("{}/{}", TEST_REQUEST.base_url(), "users")).unwrap(),
        );
        let q = "!\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
        IronCoreRequest::req_add_query(&mut req, &[("id".to_string(), url_encode(q))]);
        //NOTE: This is not the same as SignatureUrlString's encoding, but is being documented here so we know if
        //it changes. `'` is being encoded in this case, but should not be according to the spec we have for v2 signatures.
        assert_eq!(req.url().query(), Some("id=!%22%23%24%25%26%27()*%2B%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~"))
    }

    #[test]
    fn empty_query_params_encoded_correctly() {
        let mut req = Request::new(
            Method::GET,
            url::Url::parse(&format!("{}/{}", TEST_REQUEST.base_url(), "policies")).unwrap(),
        );
        IronCoreRequest::req_add_query(&mut req, &[]);
        assert_eq!(req.url().query(), None);
        assert_eq!(req.url().as_str(), "https://example.com/policies")
    }

    #[test]
    fn as_unix_timestamp_millis_works() {
        // 1999999ns on the end of this. Also 1ms
        let ts = OffsetDateTime::from_unix_timestamp_nanos(1_638_576_000_001_999_999).unwrap();

        let ts_nanos = ts.unix_timestamp_nanos();
        let ts_millis = as_unix_timestamp_millis(ts);
        assert_eq!(1_638_576_000_001, ts_millis);

        assert_eq!(ts_nanos / 1000000, ts_millis);
    }
}
