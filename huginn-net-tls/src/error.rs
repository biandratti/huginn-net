use thiserror::Error;

/// TLS-specific error handling
#[derive(Error, Debug)]
pub enum HuginnNetTlsError {
    /// An error occurred while parsing TLS data.
    #[error("Parse error: {0}")]
    Parse(String),

    /// An unsupported protocol was encountered.
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    /// An unknown error occurred.
    #[error("Unknown error")]
    Unknown,
}
