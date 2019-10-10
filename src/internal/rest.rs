//! Helpers for talking to the ironcore service.

use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use futures::{stream::Stream, Future};
use reqwest::{
    header::HeaderMap,
    r#async::{Chunk, Client as RClient, Request as ARequest},
    Method, Request, StatusCode, Url, UrlError,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::internal::auth_v2::AuthV2Builder;
use crate::internal::rest::json::Base64Standard;
use crate::internal::{
    user_api::UserId, DeviceSigningKeyPair, IronOxideErr, Jwt, RequestAuth, RequestErrorCode,
    OUR_REQUEST,
};
use crate::IronOxide;
use futures::IntoFuture;
use itertools::Itertools;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::r#async::RequestBuilder;
use std::convert::TryFrom;
use std::ops::Deref;

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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServerError {
    message: String,
    code: u32,
}

///URL encode the provided string so it can be used within a URL
pub fn url_encode(token: &str) -> String {
    percent_encoding::utf8_percent_encode(token, percent_encoding::USERINFO_ENCODE_SET)
        .to_string()
        .replace(",", "%2C") //TODO workaround for what web-service currently expects, but not sure it's right
}

///Enum representing all the ways that authorization can be done for the IronCoreRequest.
pub enum Authorization<'a> {
    JwtAuth(&'a Jwt),
    Version1 {
        version: u8,
        message: String,
        signature: [u8; 64],
    },
    Version2 {
        user_context: HeaderIronCoreUserContext,
        request_sig: HeaderIronCoreRequestSig<'a>,
    },
}

impl<'a> Authorization<'a> {
    pub fn to_auth_header(&self) -> HeaderMap {
        let auth_value = match self {
            Authorization::JwtAuth(jwt) => format!("jwt {}", jwt.0).parse().unwrap(),
            Authorization::Version1 {
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
            Authorization::Version2 {
                user_context,
                request_sig,
            } => format!(
                "IronCore {}.{}",
                2,
                base64::encode(&user_context.signature(request_sig.signing_keys).to_vec())
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
        Authorization::Version1 {
            version: 1,
            message: payload,
            signature,
        }
    }

    pub fn create_signatures_v2(
        time: DateTime<Utc>,
        segment_id: usize,
        user_id: &UserId,
        method: Method,
        signature_url: SignatureUrlPath,
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

#[derive(Debug, Clone)]
pub struct SignatureUrlPath(String);

impl SignatureUrlPath {
    pub fn new(encoded_full_url: &str) -> Result<SignatureUrlPath, reqwest::UrlError> {
        let parsed_url = Url::parse(encoded_full_url)?;
        let query_str_format = |q: &str| format!("?{}", q);

        Ok(SignatureUrlPath(format!(
            "{}{}",
            parsed_url.path(),
            parsed_url.query().map_or("".into(), query_str_format)
        )))
    }

    //TODO test
    pub fn from_parts(
        base_url: &str,
        percent_encoded_relative_url: &str,
    ) -> Result<SignatureUrlPath, reqwest::UrlError> {
        Self::new(format!("{}{}", base_url, percent_encoded_relative_url).as_str())
    }

    fn path(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Debug)]
pub struct HeaderIronCoreUserContext {
    timestamp: DateTime<Utc>,
    segment_id: usize,
    user_id: UserId,
    public_signing_key: [u8; 32],
}

impl HeaderIronCoreUserContext {
    pub fn payload(&self) -> String {
        format!(
            "{},{},{},{}",
            self.timestamp.timestamp_millis(),
            self.segment_id,
            self.user_id.id(),
            base64::encode(&self.public_signing_key)
        )
    }

    pub fn payload_bytes(&self) -> Vec<u8> {
        //TODO remove
        self.payload().into_bytes()
    }

    pub fn signature(&self, signing_keys: &DeviceSigningKeyPair) -> [u8; 64] {
        signing_keys.sign(&self.payload_bytes())
    }

    fn to_header(&self) -> HeaderMap {
        let mut headers: HeaderMap = Default::default();
        headers.append("X-IronCore-User-Context", self.payload().parse().unwrap());
        headers
    }
}

#[derive(Clone, Debug)]
pub struct HeaderIronCoreRequestSig<'a> {
    ironcore_user_context: HeaderIronCoreUserContext,
    method: Method,
    url: SignatureUrlPath,  //TODO better type?
    body: Option<&'a [u8]>, //TODO serialization of this body has to be identical to that in IronCoreRequest
    signing_keys: &'a DeviceSigningKeyPair,
}

impl<'a> HeaderIronCoreRequestSig<'a> {
    pub fn payload(&self) -> Vec<u8> {
        let HeaderIronCoreRequestSig {
            body,
            ironcore_user_context,
            method,
            url,
            ..
        } = self;

        // use closure here to delay computation until we know if we need to append the body or not
        let maybe_partial_bytes = || {
            let bytes = format!(
                "{}{}{}",
                &ironcore_user_context.payload(),
                &method,
                url.path(),
            );
            dbg!(&bytes);
            bytes.into_bytes()
        };

        body.map_or_else(maybe_partial_bytes, |body_bytes| {
            [&maybe_partial_bytes(), body_bytes].concat()
        })
    }

    pub fn signature(&self) -> [u8; 64] {
        self.signing_keys.sign(&self.payload())
    }
    fn to_header(&self) -> HeaderMap {
        let mut headers: HeaderMap = Default::default();
        headers.append(
            "X-IronCore-Request-Sig",
            base64::encode(&self.signature().to_vec()).parse().unwrap(),
        );
        headers
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
    pub fn post_jwt_auth<A: Serialize, B: DeserializeOwned>(
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
            auth.to_auth_header(),
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
    }

    ///POST body to the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub fn post2<A: Serialize, B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &A,
        error_code: RequestErrorCode,
        auth_b: crate::internal::auth_v2::AuthV2Builder,
    ) -> impl Future<Item = B, Error = IronOxideErr> {
        // TODO may be able to use RequestBuilder::build() to make a Request obj that I could get the body out of
        // TODO if this possible, I may not have to copy the body!

        let body_json_bytes = serde_json::to_vec(body.clone()).unwrap();
        let auth = auth_b.finish_with(
            SignatureUrlPath::from_parts(OUR_REQUEST.base_url(), relative_url).unwrap(),
            Method::POST,
            Some(&body_json_bytes),
        );

        self.request2::<A, _, String, _>(
            relative_url,
            Method::POST,
            Some(body),
            None,
            error_code,
            &auth,
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
    }
    pub fn post_raw<B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &[u8],
        error_code: RequestErrorCode,
        req_auth: &RequestAuth,
    ) -> impl Future<Item = B, Error = IronOxideErr> {
        let client = RClient::new();
        dbg!(&relative_url);
        let mut builder = client.request(
            Method::POST,
            format!("{}{}", self.base_url, relative_url).as_str(),
        );

        //We want to add the body as raw bytes
        builder = builder.body(body.to_vec());

        let sig_url = SignatureUrlPath::new(
            format!("{}{}", req_auth.request.base_url(), relative_url).as_str(),
        )
        .unwrap(); //TODO unwrap
        let auth = req_auth.create_signature_v2(Utc::now(), sig_url, Method::POST, Some(body));
        if let Authorization::Version2 {
            user_context,
            request_sig,
        } = &auth
        {
            let req = builder
                .headers(RAW_BYTES_HEADERS.clone())
                .headers(auth.to_auth_header())
                .headers(user_context.to_header())
                .headers(request_sig.to_header());
            IronCoreRequest::send_req(req, error_code.clone(), move |server_resp| {
                IronCoreRequest::deserialize_body(server_resp, error_code.clone())
            })
        } else {
            panic!("v1 or jwt Authorization not supported") // TODO
        }
    }

    ///PUT body to the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub fn put<A: Serialize, B: DeserializeOwned>(
        &self,
        relative_url: &str,
        body: &A,
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder,
    ) -> impl Future<Item = B, Error = IronOxideErr> {
        let body_json_bytes = serde_json::to_vec(body.clone()).unwrap();
        let auth = auth_b.finish_with(
            SignatureUrlPath::from_parts(OUR_REQUEST.base_url(), relative_url).unwrap(),
            Method::PUT,
            Some(&body_json_bytes),
        );

        self.request2::<A, _, String, _>(
            relative_url,
            Method::PUT,
            Some(body),
            None,
            error_code,
            &auth,
            move |server_resp| IronCoreRequest::deserialize_body(server_resp, error_code),
        )
    }

    ///GET the resource at relative_url using auth for authorization.
    ///If the request fails a RequestError will be raised.
    pub fn get<A: DeserializeOwned>(
        &self,
        relative_url: &str,
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder,
    ) -> impl Future<Item = A, Error = IronOxideErr> {
        dbg!(&relative_url);
        let auth = auth_b.finish_with(
            SignatureUrlPath::from_parts(OUR_REQUEST.base_url(), relative_url).unwrap(),
            Method::GET,
            None,
        );
        //A little lie here, String isn't actually the body type as it's unused
        self.request2::<String, _, String, _>(
            relative_url,
            Method::GET,
            None,
            None,
            error_code,
            &auth,
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
        auth_b: AuthV2Builder,
    ) -> impl Future<Item = A, Error = IronOxideErr> {
        //        let auth = auth_b.finish_with(
        //            SignatureUrlPath::from_parts(OUR_REQUEST.base_url(), relative_url).unwrap(),
        //            Method::GET,
        //            None,
        //        );

        //A little lie here, String isn't actually the body type as it's unused
        self.request3::<String, _, [(String, String)], _>(
            relative_url,
            Method::GET,
            None,
            Some(query_params),
            error_code,
            auth_b,
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
            auth.to_auth_header(),
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
            auth.to_auth_header(),
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
        //        dbg!(&headers);
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
        IronCoreRequest::send_req(req, error_code, resp_handler)
    }

    ///Make a request to the url using the specified method. DEFAULT_HEADERS will be used as well as whatever headers are passed
    /// in. The response will be sent to `resp_handler` so the caller can make the received bytes however they want.
    pub fn request3<A, B, Q, F>(
        &self,
        relative_url: &str,
        method: Method,
        maybe_body: Option<&A>,
        maybe_query_params: Option<&Q>,
        error_code: RequestErrorCode,
        auth_b: AuthV2Builder,
        resp_handler: F,
    ) -> impl Future<Item = B, Error = IronOxideErr>
    where
        A: Serialize,
        B: DeserializeOwned,
        Q: Serialize + ?Sized,
        F: FnOnce(&Chunk) -> Result<B, IronOxideErr>,
    {
        use futures::future::IntoFuture;
        use publicsuffix::IntoUrl;
        let client = RClient::new();
        //        let mut builder = client.request(
        //            method.clone(),
        //            format!("{}{}", self.base_url, relative_url).as_str(),
        //        );

        // BEGIN
        //        // add query params, if any
        //        builder = maybe_query_params
        //            .iter()
        //            .fold(builder, |build, q| build.query(q));
        //
        //        //We want to add the body as json if it was specified
        //        builder = maybe_body
        //            .iter()
        //            .fold(builder, |build, body| build.json(body));
        //
        //        //        let req_no_headers = builder.build();

        // END
        //

        // build up a request...
        let mut req = ARequest::new(
            method,
            format!("{}{}", self.base_url(), relative_url)
                .into_url()
                .unwrap(),
        );

        // add query params
        if let Some(query) = maybe_query_params {
            //side-effect to the stars!
            let url = req.url_mut();
            let mut pairs = url.query_pairs_mut();
            let serializer = serde_urlencoded::Serializer::new(&mut pairs);
            query.serialize(serializer);
            //            if let Err(err) = query.serialize(serializer) {
            //                error = Some(::error::from(err));
            //            }
        }

        // add the body
        if let Some(json_se) = maybe_body {
            match serde_json::to_vec(json_se) {
                Ok(body) => {
                    req.headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    *req.body_mut() = Some(body.into());
                }
                Err(err) => panic!(), //error = Some(::error::from(err)),
            }
        }

        fn replace_headers(dst: &mut HeaderMap, src: HeaderMap) {
            // IntoIter of HeaderMap yields (Option<HeaderName>, HeaderValue).
            // The first time a name is yielded, it will be Some(name), and if
            // there are more values with the same name, the next yield will be
            // None.
            //
            // TODO: a complex exercise would be to optimize this to only
            // require 1 hash/lookup of the key, but doing something fancy
            // with header::Entry...

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

        // use the completed request to finish authorization v2 headers
        let auth = auth_b.finish_with(
            SignatureUrlPath::new(req.url().as_str()).unwrap(),
            req.method().clone(),
            None, //TODO
        );

        // we only support Authorization::Version2 with this call
        if let Authorization::Version2 {
            user_context,
            request_sig,
        } = &auth
        {
            replace_headers(req.headers_mut(), DEFAULT_HEADERS.clone());
            replace_headers(req.headers_mut(), auth.to_auth_header());
            replace_headers(req.headers_mut(), user_context.to_header());
            replace_headers(req.headers_mut(), request_sig.to_header());
            //                        IronCoreRequest::send_req(, error_code, resp_handler)
            client
                .execute(req)
                //Parse the body content into bytes
                .and_then(|res| {
                    let status_code = res.status();
                    res.into_body()
                        .concat2()
                        .map(move |body| (status_code, body))
                })
                //Now make the error type into the IronOxideErr and run the resp_handler which was passed to us.
                .then(move |resp| {
                    //Map the generic error from reqwest to our error type.
                    let (status, server_resp) = resp.map_err(|err| {
                        IronCoreRequest::create_request_err(
                            err.to_string(),
                            error_code,
                            err.status(),
                        )
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
        } else {
            panic!()
        }
        //        req_no_headers.unwrap().body().map_or(None, )
        //        let body_bytes: Option<&[u8]> =
        //            maybe_body.and_then(|b| Some(serde_json::to_vec(b.clone()).unwrap().as_slice()));
        //        let auth = auth_b.finish_with(
        //            SignatureUrlPath::new(req_no_headers.unwrap().url().as_str()).unwrap(),
        //            method,
        //            body_bytes,
        //        );

        //        if let Authorization::Version2 {
        //            user_context,
        //            request_sig,
        //        } = auth
        //        {
        //            let req = builder
        //                .headers(DEFAULT_HEADERS.clone())
        //                .headers(auth.to_auth_header())
        //                .headers(user_context.to_header())
        //                .headers(request_sig.to_header());
        //            dbg!(&req);
        //            IronCoreRequest::send_req(req, error_code, resp_handler)
        //        } else {
        //            panic!("") //TODO error message
        //        }
    }

    ///Make a request to the url using the specified method. DEFAULT_HEADERS will be used as well as whatever headers are passed
    /// in. The response will be sent to `resp_handler` so the caller can make the received bytes however they want.
    pub fn request2<A, B, Q, F>(
        &self,
        relative_url: &str,
        method: Method,
        maybe_body: Option<&A>,
        maybe_query_params: Option<&Q>,
        error_code: RequestErrorCode,
        auth: &Authorization,
        resp_handler: F,
    ) -> impl Future<Item = B, Error = IronOxideErr>
    where
        A: Serialize,
        B: DeserializeOwned,
        Q: Serialize + ?Sized,
        F: FnOnce(&Chunk) -> Result<B, IronOxideErr>,
    {
        use futures::future::IntoFuture;

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
        if let Authorization::Version2 {
            user_context,
            request_sig,
        } = auth
        {
            let req = builder
                .headers(DEFAULT_HEADERS.clone())
                .headers(auth.to_auth_header())
                .headers(user_context.to_header())
                .headers(request_sig.to_header());
            dbg!(&req);
            IronCoreRequest::send_req(req, error_code, resp_handler)
        } else {
            panic!("") //TODO error message
        }
    }

    fn send_req<B, F>(
        req: RequestBuilder,
        error_code: RequestErrorCode,
        resp_handler: F,
    ) -> impl Future<Item = B, Error = IronOxideErr>
    where
        B: DeserializeOwned,
        F: FnOnce(&Chunk) -> Result<B, IronOxideErr>,
    {
        //        dbg!(&req);
        req.send()
            //Parse the body content into bytes
            .and_then(|res| {
                let status_code = res.status();
                res.into_body()
                    .concat2()
                    .map(move |body| (status_code, body))
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

//TODO
impl From<serde_json::Error> for IronOxideErr {
    fn from(_: serde_json::Error) -> Self {
        unimplemented!()
    }
}

//TODO
impl From<reqwest::UrlError> for IronOxideErr {
    fn from(_: reqwest::UrlError) -> Self {
        unimplemented!()
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
    use recrypt::api::{Ed25519Signature, PublicSigningKey};
    use recrypt::prelude::Ed25519;
    use std::borrow::Borrow;

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
        let headers = auth.to_auth_header();
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

    #[test]
    fn ironcore_user_context_signing_and_headers_are_correct() {
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
        let user_context = HeaderIronCoreUserContext {
            timestamp: ts,
            segment_id,
            user_id,
            public_signing_key: key_pair.public_key(),
        };
        let payload_bytes = user_context.payload_bytes();

        let expected = "123456,1,user-10,xsqf+oiBpQPDr69jb+TvKxMSdnYATr7igNNR/uA1wtw=";

        // assert that the payload is constructed in the right order
        assert_eq!(
            expected.to_string(),
            String::from_utf8(payload_bytes.clone()).unwrap()
        );

        // assert that the associated header has the correct form
        let mut header = HeaderMap::default();
        header.append("X-IronCore-User-Context", expected.parse().unwrap());

        assert_eq!(user_context.to_header(), header);

        // assert that the signature() implementation can be verified with the included public signing key
        let signature = user_context.signature(&key_pair);
        let pub_signing_key: PublicSigningKey =
            PublicSigningKey::new(user_context.public_signing_key);
        assert!(pub_signing_key.verify(&payload_bytes, &Ed25519Signature::new(signature)));

        //TODO add to_auth_header test
    }

    #[derive(Serialize)]
    struct FakeRequest {
        k1: Vec<u8>,
        k2: u64,
        k3: String,
        k4: i64,
    }

    #[test]
    fn ironcore_request_sig_signing() {
        let ts = Utc.timestamp_millis(123456);
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
            user_id,
            public_signing_key: signing_keys.public_key(),
        };

        // note that this and the expected value must correspond
        let fake_req = FakeRequest {
            k1: vec![42u8; 10],
            k2: 64u64,
            k3: "Fake text for a fake request".to_string(),
            k4: -482949i64,
        };

        let build_url = |relative_url| format!("{}{}", OUR_REQUEST.base_url(), relative_url);

        let expected = "123456,1,user-10,xsqf+oiBpQPDr69jb+TvKxMSdnYATr7igNNR/uA1wtw=GET/api/1/users?id=user-10{\"k1\":[42,42,42,42,42,42,42,42,42,42],\"k2\":64,\"k3\":\"Fake text for a fake request\",\"k4\":-482949}";
        let expected_no_body = "123456,1,user-10,xsqf+oiBpQPDr69jb+TvKxMSdnYATr7igNNR/uA1wtw=GET/api/1/users?id=user-10";

        //
        // first test the signature over a JSON encoded request
        //
        let fake_req_json = serde_json::to_string(&fake_req).unwrap();
        let fake_req_json_bytes = fake_req_json.clone().into_bytes();
        let request_sig = HeaderIronCoreRequestSig {
            ironcore_user_context: user_context.clone(),
            method: Method::GET,
            url: SignatureUrlPath::new(&build_url("users?id=user-10")).unwrap(),
            body: Some(&fake_req_json_bytes),
            signing_keys: &signing_keys,
        };

        let json_encoded_body = fake_req_json;

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
            url: SignatureUrlPath::new(&build_url("users?id=user-10")).unwrap(),
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
            base64::encode(&request_sig.signature().to_vec()),
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
            &Ed25519Signature::new_from_slice(&base64::decode(expected_request_sig).unwrap())
                .unwrap()
        ))
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
        let maybe_path = SignatureUrlPath::new(&user_list_url("user-10"));
        assert_that!(&maybe_path, is_variant!(Result::Ok));
        assert_eq!(maybe_path.unwrap().path(), "/api/1/users?id=user-10");

        // test a user id that uses more allowed characters
        let maybe_path = SignatureUrlPath::new(&user_list_url("abcABC012_.$#|@/:;=+'-"));

        assert_that!(&maybe_path, is_variant!(Result::Ok));
        assert_eq!(
            maybe_path.unwrap().path(),
            "/api/1/users?id=abcABC012_.$%23%7C%40%2F%3A%3B%3D+\'-"
        );

        let maybe_path =
            SignatureUrlPath::new("https://api.ironcorelabs.com/api/1/documents/some-doc-id");

        assert_that!(&maybe_path, is_variant!(Result::Ok));
        assert_eq!(maybe_path.unwrap().path(), "/api/1/documents/some-doc-id");
    }

    #[test]
    fn signature_url_new_rejects_malformed_urls() {
        let maybe_path = SignatureUrlPath::new("not a url");
        assert_that!(&maybe_path, is_variant!(Result::Err));

        let maybe_path = SignatureUrlPath::new("://api?");
        assert_that!(&maybe_path, is_variant!(Result::Err));

        let maybe_path = SignatureUrlPath::new("documents/some-doc-id");
        assert_that!(&maybe_path, is_variant!(Result::Err));
    }
}
