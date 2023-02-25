pub type Result<T, E = S3ClientError> = std::result::Result<T, E>;

pub enum S3ClientError {
    HyperError(hyper::Error),
    HttpError(hyper::http::Error),
}

impl From<hyper::Error> for S3ClientError {
    fn from(value: hyper::Error) -> Self {
        Self::HyperError(value)
    }
}

impl From<hyper::http::Error> for S3ClientError {
    fn from(value: hyper::http::Error) -> Self {
        Self::HttpError(value)
    }
}
