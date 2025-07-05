use pnet::packet::ethernet::EtherType;
use thiserror::Error;

/// Error handling during network packet analysis and Database parsing.
#[derive(Error, Debug)]
pub enum HuginnNetError {
    /// An error occurred while parsing data.
    ///
    /// This variant is used when a parsing operation fails.
    /// The associated string provides additional context about the error.
    #[error("Parse error: {0}")]
    Parse(String),

    /// An unsupported protocol was encountered.
    ///
    /// This variant is used when a protocol is not supported by the application.
    /// The associated string specifies the unsupported protocol.
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    /// Invalid TCP flags were detected.
    ///
    /// This variant is used when TCP flags are invalid or unexpected.
    /// The associated value provides the invalid flags.
    #[error("Invalid TCP flags: {0}")]
    InvalidTcpFlags(u8),

    /// An invalid package was encountered.
    ///
    /// This variant is used when a package is deemed invalid.
    /// The associated string provides details about the invalid package.
    #[error("Invalid package: {0}")]
    UnexpectedPackage(String),

    /// An unsupported Ethernet type was encountered.
    ///
    /// This variant is used when an Ethernet type is not supported.
    /// The associated value specifies the unsupported Ethernet type.
    #[error("Unsupported ethernet type: {0}")]
    UnsupportedEthernetType(EtherType),

    /// An unknown error occurred.
    ///
    /// This variant is used as a catch-all for errors that do not fit other categories.
    #[error("Unknown error")]
    Unknown,
}
