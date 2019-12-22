pub use anyhow::{anyhow, bail, ensure, Error};

use hyper::StatusCode;
use std::io;

#[allow(dead_code)]
#[derive(Debug)]
pub enum DoHError {
    Incomplete,
    InvalidData,
    TooLarge,
    UpstreamIssue,
    Hyper(hyper::Error),
    Io(io::Error),
}

impl std::fmt::Display for DoHError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Debug::fmt(self, fmt)
    }
}

impl std::error::Error for DoHError {
    fn description(&self) -> &str {
        match *self {
            DoHError::Incomplete => "Incomplete",
            DoHError::InvalidData => "Invalid data",
            DoHError::TooLarge => "Too large",
            DoHError::UpstreamIssue => "Upstream error",
            DoHError::Hyper(_) => self.description(),
            DoHError::Io(_) => self.description(),
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
            DoHError::Hyper(_) => StatusCode::SERVICE_UNAVAILABLE,
            DoHError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
