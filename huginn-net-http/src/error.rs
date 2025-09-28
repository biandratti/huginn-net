use thiserror::Error;

#[derive(Error, Debug)]
pub enum HuginnNetError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),
}
