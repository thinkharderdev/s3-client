use crate::credentials::{CredentialProvider, RequestSigner};
use crate::error::{Result, S3ClientError};
use bytes::{Buf, Bytes};
use chrono::Utc;
use futures::TryStreamExt;
use hyper::client::connect::Connect;
use hyper::client::HttpConnector;
use hyper::header::{HeaderValue, RANGE};
use hyper::{Body, Client, Request, Uri};
use hyper_tls::HttpsConnector;
use percent_encoding::{utf8_percent_encode, PercentEncode};
use std::ops::Range;
use std::sync::Arc;

pub(crate) const STRICT_ENCODE_SET: percent_encoding::AsciiSet = percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// This struct is used to maintain the URI path encoding
const STRICT_PATH_ENCODE_SET: percent_encoding::AsciiSet = STRICT_ENCODE_SET.remove(b'/');

pub(crate) struct HttpConfig {}

impl Default for HttpConfig {
    fn default() -> Self {
        todo!()
    }
}

struct S3Config {
    region: String,
    endpoint: String,
    credentials: Arc<dyn CredentialProvider>,
}

impl Default for S3Config {
    fn default() -> Self {
        todo!()
    }
}

#[derive(Default)]
pub struct S3ClientBuilder {
    s3_config: S3Config,
    http_config: HttpConfig,
}

impl S3ClientBuilder {
    pub fn build_tokio(self) -> S3Client<HttpsConnector<HttpConnector>> {
        S3Client {
            config: self.s3_config,
            client: crate::tokio::hyper_client(self.http_config),
        }
    }
}

pub struct S3Client<S: Connect + Clone + Send + Sync + 'static> {
    config: S3Config,
    client: Client<S>,
}

impl<S: Connect + Clone + Send + Sync + 'static> S3Client<S> {
    pub fn builder() -> S3ClientBuilder {
        S3ClientBuilder::default()
    }

    pub async fn get(
        &self,
        bucket: &str,
        key: &str,
        range: Option<Range<usize>>,
    ) -> Result<impl Buf> {
        let credential = self.config.credentials.get_credential().await?;

        let path = format!("{}/{}", bucket, encode_path(key));

        let uri = Uri::builder()
            .scheme("https")
            .authority(self.config.endpoint.as_str())
            .path_and_query(path)
            .build()?;

        let mut request = Request::get(uri).body(Body::empty())?;

        let signer = RequestSigner {
            date: Utc::now(),
            credential: credential.as_ref(),
            service: "s3",
            region: &self.config.region,
        };

        signer.sign(&mut request);

        if let Some(range) = range {
            request
                .headers_mut()
                .insert(RANGE, format_http_range(range).parse().unwrap());
        }

        let response = self.client.request(request).await?;

        let buf = hyper::body::aggregate(response.into_body()).await?;

        Ok(buf)
    }
}

fn encode_path(key: &str) -> PercentEncode<'_> {
    utf8_percent_encode(key, &STRICT_PATH_ENCODE_SET)
}

pub fn format_http_range(range: Range<usize>) -> String {
    format!("bytes={}-{}", range.start, range.end.saturating_sub(1))
}
