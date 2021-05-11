use hyper::StatusCode;
use std::io;

#[allow(dead_code)]
#[derive(Debug)]
pub enum DoHError {
    Incomplete,
    InvalidData,
    TooLarge,
    UpstreamIssue,
    UpstreamTimeout,
    StaleKey,
    Hyper(hyper::Error),
    Io(io::Error),
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
            DoHError::Io(e) => write!(fmt, "IO error: {}", e),
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
            DoHError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
