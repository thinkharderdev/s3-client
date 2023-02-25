use crate::client::STRICT_ENCODE_SET;
use crate::error::{Result, S3ClientError};
use chrono::offset::Utc;
use chrono::DateTime;
use futures::future::BoxFuture;
use hyper::body::HttpBody;
use hyper::http::HeaderValue;
use hyper::{Body, HeaderMap, Request, Uri};
use percent_encoding::utf8_percent_encode;
use std::collections::BTreeMap;
use std::sync::Arc;
use url::Url;

type StdError = Box<dyn std::error::Error + Send + Sync>;

/// SHA256 hash of empty string
static EMPTY_SHA256_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug)]
pub struct AwsCredential {
    pub key_id: String,
    pub secret_key: String,
    pub token: Option<String>,
}

impl AwsCredential {
    /// Signs a string
    ///
    /// <https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html>
    fn sign(&self, to_sign: &str, date: DateTime<Utc>, region: &str, service: &str) -> String {
        let date_string = date.format("%Y%m%d").to_string();
        let date_hmac = hmac_sha256(format!("AWS4{}", self.secret_key), date_string);
        let region_hmac = hmac_sha256(date_hmac, region);
        let service_hmac = hmac_sha256(region_hmac, service);
        let signing_hmac = hmac_sha256(service_hmac, b"aws4_request");
        hex_encode(hmac_sha256(signing_hmac, to_sign).as_ref())
    }
}

pub(crate) struct RequestSigner<'a> {
    pub date: DateTime<Utc>,
    pub credential: &'a AwsCredential,
    pub service: &'a str,
    pub region: &'a str,
}

const DATE_HEADER: &str = "x-amz-date";
const HASH_HEADER: &str = "x-amz-content-sha256";
const TOKEN_HEADER: &str = "x-amz-security-token";
const AUTH_HEADER: &str = "authorization";

const ALL_HEADERS: &[&str; 4] = &[DATE_HEADER, HASH_HEADER, TOKEN_HEADER, AUTH_HEADER];

impl<'a> RequestSigner<'a> {
    pub fn sign(&self, request: &mut Request<Body>) {
        let url = Url::parse(request.uri().to_string().as_str()).unwrap();

        if let Some(ref token) = self.credential.token {
            let token_val = HeaderValue::from_str(token).unwrap();
            request.headers_mut().insert(TOKEN_HEADER, token_val);
        }

        let date_str = self.date.format("%Y%m%dT%H%M%SZ").to_string();
        let date_val = HeaderValue::from_str(&date_str).unwrap();
        request.headers_mut().insert(DATE_HEADER, date_val);

        // let digest = if request.body().is_end_stream() {
        //     EMPTY_SHA256_HASH.to_string()
        // } else {
        //     hex_digest(request.body()..as_bytes().unwrap())
        // };

        let digest = EMPTY_SHA256_HASH.to_string();

        let header_digest = HeaderValue::from_str(&digest).unwrap();
        request.headers_mut().insert(HASH_HEADER, header_digest);

        let (signed_headers, canonical_headers) = canonicalize_headers(request.headers());
        let canonical_query = canonicalize_query(&url);

        // https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            request.method().as_str(),
            request.uri().path(), // S3 doesn't percent encode this like other services
            canonical_query,
            canonical_headers,
            signed_headers,
            digest
        );

        let hashed_canonical_request = hex_digest(canonical_request.as_bytes());
        let scope = format!(
            "{}/{}/{}/aws4_request",
            self.date.format("%Y%m%d"),
            self.region,
            self.service
        );

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            self.date.format("%Y%m%dT%H%M%SZ"),
            scope,
            hashed_canonical_request
        );

        // sign the string
        let signature = self
            .credential
            .sign(&string_to_sign, self.date, self.region, self.service);

        // build the actual auth header
        let authorisation = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.credential.key_id, scope, signed_headers, signature
        );

        let authorization_val = HeaderValue::from_str(&authorisation).unwrap();
        request.headers_mut().insert(AUTH_HEADER, authorization_val);
    }
}

pub trait CredentialExt {
    /// Sign a request <https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html>
    fn with_aws_sigv4(self, credential: &AwsCredential, region: &str, service: &str) -> Self;
}

/// Provides credentials for use when signing requests
pub trait CredentialProvider: std::fmt::Debug + Send + Sync {
    fn get_credential(&self) -> BoxFuture<'_, Result<Arc<AwsCredential>>>;
}

/// A static set of credentials
#[derive(Debug)]
pub struct StaticCredentialProvider {
    pub credential: Arc<AwsCredential>,
}

impl CredentialProvider for StaticCredentialProvider {
    fn get_credential(&self) -> BoxFuture<'_, Result<Arc<AwsCredential>>> {
        Box::pin(futures::future::ready(Ok(self.credential.clone())))
    }
}

fn hmac_sha256(secret: impl AsRef<[u8]>, bytes: impl AsRef<[u8]>) -> ring::hmac::Tag {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_ref());
    ring::hmac::sign(&key, bytes.as_ref())
}

/// Computes the SHA256 digest of `body` returned as a hex encoded string
fn hex_digest(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    hex_encode(digest.as_ref())
}

/// Returns `bytes` as a lower-case hex encoded string
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // String writing is infallible
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Canonicalizes query parameters into the AWS canonical form
///
/// <https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html>
fn canonicalize_query(url: &Url) -> String {
    use std::fmt::Write;

    let capacity = match url.query() {
        Some(q) if !q.is_empty() => q.len(),
        _ => return String::new(),
    };
    let mut encoded = String::with_capacity(capacity + 1);

    let mut headers = url.query_pairs().collect::<Vec<_>>();
    headers.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

    let mut first = true;
    for (k, v) in headers {
        if !first {
            encoded.push('&');
        }
        first = false;
        let _ = write!(
            encoded,
            "{}={}",
            utf8_percent_encode(k.as_ref(), &STRICT_ENCODE_SET),
            utf8_percent_encode(v.as_ref(), &STRICT_ENCODE_SET)
        );
    }
    encoded
}

/// Canonicalizes headers into the AWS Canonical Form.
///
/// <https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html>
fn canonicalize_headers(header_map: &HeaderMap) -> (String, String) {
    let mut headers = BTreeMap::<&str, Vec<&str>>::new();
    let mut value_count = 0;
    let mut value_bytes = 0;
    let mut key_bytes = 0;

    for (key, value) in header_map {
        let key = key.as_str();
        if ["authorization", "content-length", "user-agent"].contains(&key) {
            continue;
        }

        let value = std::str::from_utf8(value.as_bytes()).unwrap();
        key_bytes += key.len();
        value_bytes += value.len();
        value_count += 1;
        headers.entry(key).or_default().push(value);
    }

    let mut signed_headers = String::with_capacity(key_bytes + headers.len());
    let mut canonical_headers =
        String::with_capacity(key_bytes + value_bytes + headers.len() + value_count);

    for (header_idx, (name, values)) in headers.into_iter().enumerate() {
        if header_idx != 0 {
            signed_headers.push(';');
        }

        signed_headers.push_str(name);
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        for (value_idx, value) in values.into_iter().enumerate() {
            if value_idx != 0 {
                canonical_headers.push(',');
            }
            canonical_headers.push_str(value.trim());
        }
        canonical_headers.push('\n');
    }

    (signed_headers, canonical_headers)
}
