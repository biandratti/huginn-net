use thiserror::Error;

/// TLS-specific error handling
#[derive(Error, Debug)]
pub enum TlsError {
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

/// Convenience Result type for TLS operations
pub type Result<T> = std::result::Result<T, TlsError>;
