use thiserror::Error;

#[derive(Error, Debug)]
pub enum HuginnNetHttpError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("Unacceptable configuration: {0}")]
    Misconfiguration(String),

    #[error("No SETTINGS frame found in captured frames")]
    NoSettingsFrame,

    #[error("Malformed pseudo-headers in HEADERS frame: {0}")]
    MalformedPseudoHeaders(String),

    /// TLS key log error (I/O or setup). The message carries file paths and reasons only,
    /// never key log line contents. Only produced with the `akamai-keylog` feature; the variant
    /// exists in every build, so exhaustive matches in dependents don't depend on feature
    /// unification.
    #[error("Keylog error: {0}")]
    Keylog(String),
}
