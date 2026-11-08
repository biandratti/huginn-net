//! Errors of the key log parser.

/// Why a key log line was rejected. Variants carry no line content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeylogLineError {
    /// The line is longer than 512 bytes.
    #[error("key log line too long")]
    TooLong,
    /// The line does not have exactly three space-separated fields.
    #[error("key log line has the wrong number of fields")]
    WrongFieldCount,
    /// The label is not a known key log label.
    #[error("unknown key log label")]
    UnknownLabel,
    /// The client random or secret is not valid hex.
    #[error("invalid hex in key log line")]
    BadHex,
    /// The client random is not 32 bytes.
    #[error("client random must be 32 bytes")]
    BadClientRandomLength,
    /// The secret length is not valid for its label.
    #[error("secret length not valid for its label")]
    BadSecretLength,
    /// The line is not valid UTF-8.
    #[error("key log line is not valid UTF-8")]
    NotUtf8,
}
