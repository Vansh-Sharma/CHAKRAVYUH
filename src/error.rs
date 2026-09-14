// Error types for CHAKRAVYUH.
//
// Uses thiserror for ergonomic error definitions.

use thiserror::Error;

/// All errors that CHAKRAVYUH can return.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration load error: {0}")]
    ConfigLoad(String),

    #[error("Configuration parse error: {0}")]
    ConfigParse(String),

    #[error("Engine initialization error: {0}")]
    EngineInit(String),

    #[error("Rate limiter storage backend error: {0}")]
    RateLimiterStorage(String),

    #[error("Ring evaluation error: {0}")]
    Evaluation(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Self {
        Error::ConfigParse(e.to_string())
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Other(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
