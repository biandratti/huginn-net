use thiserror::Error;

#[derive(Error, Debug)]
pub enum HuginnNetTlsError {
    /// An error occurred while parsing TLS data.
    #[error("Parse error: {0}")]
    Parse(String),

    /// An unsupported protocol was encountered.
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    /// Misconfiguration error.
    #[error("Misconfiguration: {0}")]
    Misconfiguration(String),

    /// The TLS record is valid but does not contain a ClientHello message.
    #[error("TLS record is not a ClientHello")]
    NotClientHello,

    /// An unknown error occurred.
    #[error("Unknown error")]
    Unknown,
}
