use thiserror::Error;

#[derive(Error, Debug)]
pub enum HuginnNetHttpError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("Unacceptable configuration: {0}")]
    Misconfiguration(String),
}
