use hyper::StatusCode;
use std::io;
use reqwest;

#[derive(Debug)]
pub enum DoHError {
    Incomplete,
    InvalidData,
    TooLarge,
    UpstreamIssue,
    UpstreamTimeout,
    StaleKey,
    Hyper(hyper::Error),
    Reqwest(reqwest::Error),
    Io(io::Error),
    ODoHConfigError(anyhow::Error),
    TooManyTcpSessions,
}

impl std::error::Error for DoHError {}

impl std::fmt::Display for DoHError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            DoHError::Incomplete => write!(fmt, "Incomplete"),
            DoHError::InvalidData => write!(fmt, "Invalid data"),
            DoHError::TooLarge => write!(fmt, "Too large"),
            DoHError::UpstreamIssue => write!(fmt, "Upstream error"),
            DoHError::UpstreamTimeout => write!(fmt, "Upstream timeout"),
            DoHError::StaleKey => write!(fmt, "Stale key material"),
            DoHError::Hyper(e) => write!(fmt, "HTTP error: {}", e),
            DoHError::Reqwest(e) => write!(fmt, "HTTP Proxy error: {}", e),
            DoHError::Io(e) => write!(fmt, "IO error: {}", e),
            DoHError::ODoHConfigError(e) => write!(fmt, "ODoH config error: {}", e),
            DoHError::TooManyTcpSessions => write!(fmt, "Too many TCP sessions"),
        }
    }
}

impl From<DoHError> for StatusCode {
    fn from(e: DoHError) -> StatusCode {
        match e {
            DoHError::Incomplete => StatusCode::UNPROCESSABLE_ENTITY,
            DoHError::InvalidData => StatusCode::BAD_REQUEST,
            DoHError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            DoHError::UpstreamIssue => StatusCode::BAD_GATEWAY,
            DoHError::UpstreamTimeout => StatusCode::BAD_GATEWAY,
            DoHError::StaleKey => StatusCode::UNAUTHORIZED,
            DoHError::Hyper(_) => StatusCode::SERVICE_UNAVAILABLE,
            DoHError::Reqwest(_) => StatusCode::SERVICE_UNAVAILABLE,
            DoHError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            DoHError::ODoHConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            DoHError::TooManyTcpSessions => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}
