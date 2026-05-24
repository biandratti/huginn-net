pub mod common;
#[cfg(feature = "mtu")]
pub mod mtu;
#[cfg(feature = "syn")]
pub mod syn;
#[cfg(feature = "syn-ack")]
pub mod syn_ack;
#[cfg(feature = "uptime")]
pub mod uptime;

#[cfg(feature = "json")]
pub(crate) fn serialize_display<T: std::fmt::Display, S: serde::Serializer>(
    val: &T,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&val.to_string())
}

pub use common::*;
#[cfg(feature = "mtu")]
pub use mtu::*;
#[cfg(feature = "syn")]
pub use syn::*;
#[cfg(feature = "syn-ack")]
pub use syn_ack::*;
#[cfg(feature = "uptime")]
pub use uptime::*;

/// Represents the output from TCP analysis.
///
/// This struct contains various optional outputs that can be derived
/// from analyzing TCP packets. Some fields are only present when the
/// corresponding Cargo feature is enabled.
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub struct TcpAnalysisResult {
    /// Information derived from SYN packets.
    ///
    /// Present only when the `syn` feature is enabled.
    #[cfg(feature = "syn")]
    pub syn: Option<SynTCPOutput>,

    /// Information derived from SYN-ACK packets.
    ///
    /// Present only when the `syn-ack` feature is enabled.
    #[cfg(feature = "syn-ack")]
    pub syn_ack: Option<SynAckTCPOutput>,

    /// Information about the Maximum Transmission Unit (MTU).
    ///
    /// Present only when the `mtu` feature is enabled.
    #[cfg(feature = "mtu")]
    pub mtu: Option<MTUOutput>,

    /// Information about the client system uptime.
    ///
    /// Present only when the `uptime` feature is enabled.
    #[cfg(feature = "uptime")]
    pub client_uptime: Option<UptimeOutput>,

    /// Information about the server system uptime.
    ///
    /// Present only when the `uptime` feature is enabled.
    #[cfg(feature = "uptime")]
    pub server_uptime: Option<UptimeOutput>,
}
