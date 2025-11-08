use thiserror::Error;

#[derive(Error, Debug)]
pub enum HuginnNetTcpError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("Invalid TCP flags: {0}")]
    InvalidTcpFlags(u8),

    #[error("Invalid package: {0}")]
    UnexpectedPackage(String),

    #[error("Misconfiguration: {0}")]
    Misconfiguration(String),
}
